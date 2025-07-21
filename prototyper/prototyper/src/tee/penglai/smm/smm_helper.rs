//! Secure memory manager helper functions.
//!
use crate::cfg::PAGE_SIZE;
use super::{pmp::{N_AVAL_PMP_REGION}, SecPMPRegion, SecmemRegionAllocator};

#[inline]
pub fn for_each_region<F>(
    guard: &mut spin::MutexGuard<'_, [SecPMPRegion; N_AVAL_PMP_REGION]>,
    mut f: F,
) where
    F: FnMut(usize, &mut SecPMPRegion),
{
    for (i, region) in guard.iter_mut().enumerate() {
        f(i, region);
    }
}

#[inline]
pub fn try_each_region<F, R>(
    guard: &mut spin::MutexGuard<'_, [SecPMPRegion; N_AVAL_PMP_REGION]>,
    mut f: F,
) -> Option<R>
where
    F: FnMut(usize, &mut SecPMPRegion) -> Option<R>,
{
    for (i, region) in guard.iter_mut().enumerate() {
        if let Some(r) = f(i, region) {
            return Some(r);
        }
    }
    None
}

#[inline]
pub fn get_region<F, R>(
    guard: &mut spin::MutexGuard<'_, [SecPMPRegion; N_AVAL_PMP_REGION]>,
    idx: usize,
    f: F,
) -> Option<R>
where
    F: FnOnce(&mut SecPMPRegion) -> R,
{
    Some(f(&mut guard[idx]))
}

#[inline]
pub fn check_mem_align(addr: usize, len: usize) -> bool {
    if (len >= PAGE_SIZE) && (len & (len - 1) == 0) && (addr & (len - 1) == 0) {
        return true;
    }
    return false;
}

#[inline]
/// Check if new secure memory region overlap with any secure memory region already inited.
pub fn check_mem_overlap(
    guard: &mut spin::MutexGuard<'_, [SecPMPRegion; N_AVAL_PMP_REGION]>,
    addr: usize,
    len: usize,
) -> bool {
    try_each_region(guard, |_, region| {
        if region.is_valid && region.mem_region.is_mem_overlap(addr, addr + len) {
            Some(true)
        } else {
            None
        }
    })
    .unwrap_or(false)
}

#[inline]
/// Get first unused secure region.
pub fn get_unused_region<'a>(
    guard: &'a mut spin::MutexGuard<'_, [SecPMPRegion; N_AVAL_PMP_REGION]>,
) -> Option<&'a mut SecPMPRegion> {
    guard.iter_mut().find(|r| !r.is_valid)
}
