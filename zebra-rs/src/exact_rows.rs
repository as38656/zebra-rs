/// Exact-size changes for the row vectors of per-prefix tables.
///
/// `Vec::push` grows an empty vector to room for 4 rows. A table keeps one
/// such vector per prefix and nearly every prefix has a single row, so the
/// 3 spare rows (216 bytes each for a BGP route, 384 for a RIB entry) are
/// wasted on every prefix. These methods keep the capacity equal to the
/// length. A path added later reallocates once, which is cheap for the few
/// rows a prefix has.
pub trait ExactRows<T> {
    /// Append `row`, growing by exactly one row.
    fn push_exact(&mut self, row: T);

    /// Remove the row at `index` and give the unused room back.
    fn remove_exact(&mut self, index: usize) -> T;
}

impl<T> ExactRows<T> for Vec<T> {
    fn push_exact(&mut self, row: T) {
        self.reserve_exact(1);
        self.push(row);
    }

    fn remove_exact(&mut self, index: usize) -> T {
        let row = self.remove(index);
        self.shrink_to_fit();
        row
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rows_grow_and_shrink_one_at_a_time() {
        let mut rows: Vec<u64> = Vec::new();
        for (n, expected) in [(1, 1), (2, 2), (3, 3), (4, 4), (5, 5)] {
            rows.push_exact(n);
            assert_eq!(rows.capacity(), expected);
        }
        assert_eq!(rows.remove_exact(1), 2);
        assert_eq!(rows.capacity(), 4);
        assert_eq!(rows, vec![1, 3, 4, 5]);
    }
}
