//! Secure memory manager helper functions.
//!
use super::{super::PENGLAI_PMP_COUNT, SecPMPRegion};

/// Check if new secure memory region is PAGE_SIZE align and not wrap around.
pub fn check_mem_align(addr: usize, len: usize, align: usize) -> bool {
    if addr & (align - 1) != 0 || len < align || len & (align - 1) != 0 || addr + len < addr {
        return false;
    }
    true
}

/// Check if new secure memory region overlap with exsisting region.
pub fn check_mem_overlap(
    regions: &[SecPMPRegion; PENGLAI_PMP_COUNT as usize],
    addr: usize,
    len: usize,
) -> bool {
    for region in regions.iter().take(regions.len() - 1) {
        if region.is_valid == true && region.mem_region.is_mem_overlap(addr, addr + len) == true {
            // New region overlap with exsisting region.
            return true;
        }
    }
    // New region not overlap with exsisting region and can be used.
    false
}

/// Get index of first unused region.
pub fn get_unused_region(
    regions: &mut [SecPMPRegion; PENGLAI_PMP_COUNT as usize],
) -> Option<&mut SecPMPRegion> {
    for region in regions.iter_mut() {
        if region.is_valid == false {
            return Some(region);
        }
    }
    return None;
}
