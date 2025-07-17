//! Secure memory manager helper functions.
//!

use crate::cfg::PAGE_SIZE;
use super::SEC_PMP_REGIONS;
fn check_mem_align(addr: usize, len: usize) -> bool {
    if (len >= PAGE_SIZE) &&
     (len & (len - 1) == 0) &&
    (addr & (len - 1) == 0) {
        return true;
    }
    return false;
}

fn check_mem_overlap(addr: usize, len : usize) -> bool {
    // for (i, region) in SEC_PMP_REGIONS.
    return false;
}
