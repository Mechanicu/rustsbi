//! PMP management module of Penglai PMP.
//!
//! For now, the one using PMP most usually be secure monitor (SM) of TEE,
//! But in different SM, the way to manage PMP is different, so for now we
//! manage all PMP under Penglai PMP secure monitor when enable Penglai PMP
//! in current Rust Prototyper.

use core::sync::atomic::AtomicUsize;
use core::sync::atomic::Ordering::SeqCst;

pub const PENGLAI_PMP_START: i16 = 0;
pub const PENGLAI_PMP_END: i16 = 15;
pub const PENGLAI_PMP_COUNT: i16 = PENGLAI_PMP_END - PENGLAI_PMP_START;

#[repr(i16)]
pub enum PmpIdx {
    PmpInvalid = -1,
    PmpSM = 0,
    PmpTemp = 1,
    PmpDefault = PENGLAI_PMP_END,
}

struct PmpBitmap {
    map: AtomicUsize,
    start: i16,
    end: i16,
}

impl PmpBitmap {
    pub const fn new(pmp_start: i16, pmp_end: i16) -> Self {
        Self {
            map: (AtomicUsize::new(0)),
            start: (pmp_start),
            end: (pmp_end),
        }
    }
    fn check_idx(&self, idx: i16) {
        if idx < self.start || idx > self.end || idx & (idx - 1) != 0 {
            panic!(
                "Index {} out of bounds for Bitmap of {}~{}",
                idx, self.start, self.end
            );
        }
    }
    pub fn alloc(&self) -> i16 {
        let mut cur_map = self.map.load(SeqCst);
        loop {
            // Find idx of first zero bit in current PMP area bitmap and set used.
            let first_zero = match (self.start..self.end).find(|&i| cur_map & (1 << i) == 0) {
                Some(bit) => bit,
                None => return PmpIdx::PmpInvalid as i16,
            };
            let new_map = cur_map | (1 << first_zero);

            // Try to update bitmap by CAS. If update successfully, then return idx.
            match self
                .map
                .compare_exchange_weak(cur_map, new_map, SeqCst, SeqCst)
            {
                Ok(_) => return first_zero as i16,
                Err(actual) => cur_map = actual,
            }
        }
    }
    pub fn free(&self, idx: i16) {
        self.check_idx(idx);
        let mask = 1 << idx;
        self.map.fetch_and(!mask, SeqCst);
    }
}

static GLOBAL_PMP_BITMAP: PmpBitmap = PmpBitmap::new(PENGLAI_PMP_START, PENGLAI_PMP_END);

/// Set PMP slot N configuration on every hart.
pub fn set_slot(slot: usize) {}

/// Clear PMP slot N configuration on every hart.
pub fn clear_slop(slot: usize) {}

/// Set PMP slot configuration on current hart.
pub fn set_pmp(slot: usize) {}

/// Clean PMP slot configuration on current hart.
pub fn clear_pmp(slot: usize) {}

pub fn alloc_slot() -> i16 {
    GLOBAL_PMP_BITMAP.alloc()
}

pub fn free_slot(idx: i16) {
    GLOBAL_PMP_BITMAP.free(idx);
}

pub fn dump_pmps() {}
