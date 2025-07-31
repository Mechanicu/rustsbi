use super::PmpBitmap;
use core::sync::atomic::AtomicUsize;
use core::sync::atomic::Ordering;

impl PmpBitmap {
    pub const fn new(pmp_start: u8, pmp_end: u8, mask: usize) -> Self {
        Self {
            map: (AtomicUsize::new(mask)),
            start: (pmp_start),
            end: (pmp_end),
        }
    }
    fn check_idx(&self, idx: u8) {
        if idx < self.start || idx > self.end || idx & (idx - 1) != 0 {
            panic!(
                "Index {} out of bounds for Bitmap of {}~{}",
                idx, self.start, self.end
            );
        }
    }
    pub fn alloc(&self) -> Option<u8> {
        let mut cur_map = self.map.load(Ordering::SeqCst);
        loop {
            // Find idx of first zero bit in current PMP area bitmap and set used.
            // Beware of that every PMP slot record in PmpIdx will be set to used when init!!!.
            let first_zero = match (self.start..self.end).find(|&i| cur_map & (1 << i) == 0) {
                Some(bit) => bit,
                None => return None,
            };
            let new_map = cur_map | (1 << first_zero);

            // Try to update bitmap by CAS. If update successfully, then return idx.
            match self.map.compare_exchange_weak(
                cur_map,
                new_map,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => return Some(first_zero),
                Err(actual) => cur_map = actual,
            }
        }
    }
    pub fn free(&self, idx: u8, mask: usize) {
        self.check_idx(idx);
        let mask = (1 << idx) & mask;
        self.map.fetch_and(!mask, Ordering::SeqCst);
    }
}
