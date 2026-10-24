use std::sync::{Arc, Weak};

use bgp_packet::BgpAttr;
use hashbrown::HashTable;

/// The interning store hashes the whole `BgpAttr` (AS_PATH, communities,
/// …) on every received update — a profile of an 8×500k convergence put
/// the default SipHash at ~24% of daemon CPU. `BgpAttr` keys are
/// internal dedup keys, not attacker-chosen hash-table indices, so a
/// fast non-cryptographic hasher (ahash) is the right trade here.
type AttrHasher = ahash::RandomState;

/// The store never sweeps a table smaller than this.
const SWEEP_FLOOR: usize = 64;

/// One stored attribute set. The hash is kept with the entry so the
/// table can rehash an entry whose set is already gone.
#[derive(Debug)]
struct Entry {
    hash: u64,
    attr: Weak<BgpAttr>,
}

/// Interns path attribute sets so that every user of an equal set
/// shares one `Arc<BgpAttr>`, and two equal sets from the same store are
/// always `Arc::ptr_eq`.
///
/// The store holds only a `Weak` per set, so it never keeps a set alive
/// and never holds a second copy of it. The entry of a set nobody uses
/// any more is removed by [`sweep`](Self::sweep): the store sweeps by
/// itself when its table has doubled since the last sweep, and owners
/// call it after they drop many routes at once (a peer going down).
///
/// Each task that owns RIB rows has its own store (the shard, each pool
/// worker, each VRF, the main task, each per-peer egress task and each
/// update-group engine). An `Arc` is valid whichever store made it, but
/// pointer-equality checks only hold between `Arc`s of one store.
#[derive(Debug)]
pub struct BgpAttrStore {
    table: HashTable<Entry>,
    hasher: AttrHasher,
    /// Table size at which the next insert sweeps first.
    sweep_at: usize,
    /// The set returned last. The NLRIs of one UPDATE come in a row with
    /// the same set, so they find it here without hashing it again.
    last: Weak<BgpAttr>,
}

impl Default for BgpAttrStore {
    fn default() -> Self {
        Self::new()
    }
}

impl BgpAttrStore {
    pub fn new() -> Self {
        Self {
            table: HashTable::new(),
            hasher: AttrHasher::default(),
            sweep_at: SWEEP_FLOOR,
            last: Weak::new(),
        }
    }

    /// The shared `Arc` for `attr`, made from `attr` when the set is new.
    pub fn intern(&mut self, attr: BgpAttr) -> Arc<BgpAttr> {
        match self.find(&attr) {
            Ok(found) => found,
            Err(hash) => self.insert(hash, Arc::new(attr)),
        }
    }

    /// As [`intern`](Self::intern), but for a set that is already in an
    /// `Arc`: a new set keeps that `Arc`, so it is not copied.
    pub fn intern_arc(&mut self, attr: Arc<BgpAttr>) -> Arc<BgpAttr> {
        match self.find(&attr) {
            Ok(found) => found,
            Err(hash) => self.insert(hash, attr),
        }
    }

    /// The stored `Arc` equal to `attr`, or the hash to insert it with.
    fn find(&mut self, attr: &BgpAttr) -> Result<Arc<BgpAttr>, u64> {
        if let Some(last) = self.last.upgrade()
            && (std::ptr::eq(Arc::as_ptr(&last), attr) || *last == *attr)
        {
            return Ok(last);
        }
        let hash = self.hasher.hash_one(attr);
        let found = self
            .table
            .iter_hash(hash)
            .filter(|entry| entry.hash == hash)
            .find_map(|entry| entry.attr.upgrade().filter(|stored| **stored == *attr));
        match found {
            Some(found) => {
                self.last = Arc::downgrade(&found);
                Ok(found)
            }
            None => Err(hash),
        }
    }

    fn insert(&mut self, hash: u64, attr: Arc<BgpAttr>) -> Arc<BgpAttr> {
        if self.table.len() >= self.sweep_at {
            self.sweep();
        }
        let entry = Entry {
            hash,
            attr: Arc::downgrade(&attr),
        };
        self.table.insert_unique(hash, entry, |entry| entry.hash);
        self.last = Arc::downgrade(&attr);
        attr
    }

    /// Remove the entries of sets nobody uses any more.
    pub fn sweep(&mut self) {
        self.table.retain(|entry| entry.attr.strong_count() > 0);
        self.sweep_at = (2 * self.table.len()).max(SWEEP_FLOOR);
        if self.table.capacity() > 2 * self.sweep_at {
            self.table.shrink_to(self.sweep_at, |entry| entry.hash);
        }
    }

    /// Number of entries, including sets not used any more that the
    /// next sweep removes.
    pub fn len(&self) -> usize {
        self.table.len()
    }

    /// Number of sets in use.
    pub fn refcnt_all(&self) -> usize {
        self.table
            .iter()
            .filter(|entry| entry.attr.strong_count() > 0)
            .count()
    }

    /// The sets in use, each with its number of users.
    pub fn iter(&self) -> impl Iterator<Item = (Arc<BgpAttr>, usize)> + '_ {
        self.table.iter().filter_map(|entry| {
            let users = entry.attr.strong_count();
            entry.attr.upgrade().map(|attr| (attr, users))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bgp_packet::Med;

    fn attr(med: u32) -> BgpAttr {
        BgpAttr {
            med: Some(Med::new(med)),
            ..Default::default()
        }
    }

    #[test]
    fn equal_sets_share_one_arc() {
        let mut store = BgpAttrStore::new();
        let a = store.intern(attr(1));
        let b = store.intern(attr(1));
        let c = store.intern(attr(2));
        assert!(Arc::ptr_eq(&a, &b));
        assert!(!Arc::ptr_eq(&a, &c));
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn intern_arc_keeps_a_new_arc_and_reuses_a_known_one() {
        let mut store = BgpAttrStore::new();
        let first = Arc::new(attr(1));
        let kept = store.intern_arc(first.clone());
        assert!(Arc::ptr_eq(&kept, &first), "a new set keeps the given Arc");
        let again = store.intern_arc(Arc::new(attr(1)));
        assert!(
            Arc::ptr_eq(&again, &first),
            "an equal set gets the stored Arc"
        );
        assert!(Arc::ptr_eq(&store.intern(attr(1)), &first));
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn store_does_not_keep_a_copy_of_unused_sets() {
        let mut store = BgpAttrStore::new();
        let a = store.intern(attr(1));
        let b = store.intern(attr(2));
        drop(a);
        let live: Vec<BgpAttr> = store.iter().map(|(attr, _)| (*attr).clone()).collect();
        assert_eq!(live, vec![(*b).clone()]);
    }

    #[test]
    fn sweep_drops_sets_nobody_uses() {
        let mut store = BgpAttrStore::new();
        let a = store.intern(attr(1));
        let b = store.intern(attr(2));
        drop(a);
        store.sweep();
        assert_eq!(store.len(), 1);
        drop(b);
        store.sweep();
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn unused_sets_do_not_pile_up() {
        let mut store = BgpAttrStore::new();
        for med in 0..10_000 {
            drop(store.intern(attr(med)));
        }
        assert!(store.len() <= SWEEP_FLOOR, "len {}", store.len());
    }

    #[test]
    fn sweep_keeps_sets_in_use() {
        let mut store = BgpAttrStore::new();
        let kept: Vec<Arc<BgpAttr>> = (0..1_000).map(|med| store.intern(attr(med))).collect();
        for med in 1_000..10_000 {
            drop(store.intern(attr(med)));
        }
        assert!(store.len() <= 2 * kept.len() + SWEEP_FLOOR);
        for (med, arc) in kept.iter().enumerate() {
            assert!(Arc::ptr_eq(&store.intern(attr(med as u32)), arc));
        }
        assert_eq!(store.refcnt_all(), kept.len());
    }
}
