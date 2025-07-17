//! Secure memory management of Penglai PMP extension in RustSBI.
//!

use super::host::SMMRet;
use buddy_system_allocator::LockedHeap;
use core::alloc::Layout;
use core::mem::MaybeUninit;
use core::ptr::NonNull;
use spin::{Mutex, Once};

pub const SECMEM_MAX_ORDER: usize = 20;
pub const N_AVAL_PMP_REGION: usize = 8;

mod buddy;
mod smm_helper;

pub trait SecmemRegionAllocator {
    fn new(start: usize, end: usize) -> Self;
    fn init(&self);
    fn alloc(&self, layout: Layout) -> Result<NonNull<u8>, ()>;
    fn dealloc(&self, ptr: NonNull<u8>, layout: Layout);
    fn extend(&self, start: usize, len: usize);
    fn range_check(&self, start: usize, end: usize) -> bool;
    fn check_used(&self) -> usize;
    fn check_aval(&self) -> usize;
}

pub struct SecmemRegion {
    pub start: usize,
    pub len: usize,
    pub allocator: LockedHeap<SECMEM_MAX_ORDER>,
}

pub struct SecPMPRegion {
    pub pmp_idx: usize,
    pub is_valid: bool,
    pub mem_region: SecmemRegion,
}

static mut SEC_PMP_REGIONS: [MaybeUninit<Mutex<SecPMPRegion>>; N_AVAL_PMP_REGION] =
    unsafe { MaybeUninit::uninit().assume_init() };

/// PMP and secure memory bind array.
///
/// A PMP slot (slot here means PMP with index N on every hart) will and only bind with
/// on memory region with a allocator (allocator can only use buddy algorithm for now).
pub fn secmem_init(start: usize, len: usize) -> SMMRet {
    // Init every secure PMP region metadata
    unsafe {
        for i in 0..N_AVAL_PMP_REGION {
            SEC_PMP_REGIONS[i].write(Mutex::new(SecPMPRegion {
                pmp_idx: 0,
                is_valid: false,
                mem_region: SecmemRegion {
                    start: (0),
                    len: (0),
                    allocator: (LockedHeap::<SECMEM_MAX_ORDER>::empty()),
                },
            }));
            // For each member thar been initialied, drop assume-init status
        }
    }

    SMMRet::Success
}
pub fn secmem_extend() -> SMMRet {
    SMMRet::Success
}

pub fn secmem_reclaim() -> SMMRet {
    SMMRet::Success
}

pub fn secmem_alloc() -> SMMRet {
    SMMRet::Success
}

pub fn secmem_free() -> SMMRet {
    SMMRet::Success
}
