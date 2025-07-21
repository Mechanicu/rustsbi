//! Secure memory management of Penglai PMP extension in RustSBI.
//!
//! Penglai PMP use PMP slots in accordance with the following regulations:
//!
//! 1. PMP slot 0: reserved for temporarily granting the kernel access premissions of  
//! specified secure memory region.
//!
//! 2. PMP slot 1: used for protect secure monitor (usually whole firmware, here is prototyper)
//!
//! 3. PMP 2~(N-2): each PMP slot is used to protect a physical continous secure memory region.
//! Each secure memory region shouldn't overlap with each other.
//!
//! 4. PMP slot N-1 (last PMP slot): used fot grant the kernel access permissions of memory not
//! protected by secure monitor.

use super::host::SMMRet;
use crate::firmware::{SBI_END_ADDRESS, SBI_START_ADDRESS};
use buddy_system_allocator::LockedHeap;
use core::alloc::Layout;
use core::mem::MaybeUninit;
use core::ptr::NonNull;
use pmp::*;
use riscv::register::{Permission, Range};
use smm_helper::*;
use spin::{Lazy, Mutex};

pub const SECMEM_MAX_ORDER: usize = 20;

mod buddy;
mod pmp;
mod smm_helper;

pub trait SecmemRegionAllocator {
    fn new(start: usize, end: usize) -> Self;
    fn init(&self);
    fn alloc(&self, layout: Layout) -> Result<NonNull<u8>, ()>;
    fn dealloc(&self, ptr: NonNull<u8>, layout: Layout);
    fn extend(&self, start: usize, len: usize);
    fn is_mem_overlap(&self, start: usize, end: usize) -> bool;
    fn check_used(&self) -> usize;
    fn check_aval(&self) -> usize;
}

pub struct SecmemRegion {
    pub start: usize,
    pub len: usize,
    pub allocator: LockedHeap<SECMEM_MAX_ORDER>,
}

pub struct SecPMPRegion {
    pub slot: usize,
    pub permission: Permission,
    pub mode: Range,
    pub is_valid: bool,
    pub mem_region: SecmemRegion,
}

static SEC_REGIONS: Lazy<Mutex<[SecPMPRegion; N_AVAL_PMP_REGION]>> = Lazy::new(|| {
    // 初始化逻辑
    let mut init_arr: [SecPMPRegion; N_AVAL_PMP_REGION] =
        unsafe { MaybeUninit::uninit().assume_init() };
    for (i, slot) in init_arr.iter_mut().enumerate() {
        *slot = SecPMPRegion {
            slot: i,
            permission: Permission::NONE,
            mode: Range::OFF,
            is_valid: false,
            mem_region: SecmemRegion {
                start: 0,
                len: 0,
                allocator: LockedHeap::<SECMEM_MAX_ORDER>::empty(),
            },
        };
    }
    Mutex::new(init_arr)
});

/// PMP and secure memory bind array.
///
/// A PMP slot (slot here means PMP with index N on every hart) will and only bind with
/// on memory region with a allocator (allocator can only use buddy algorithm for now).
pub fn secmem_init(start: usize, len: usize) -> SMMRet {
    // Init every secure PMP region metadata

    // secure memory region must be aligned
    if false == smm_helper::check_mem_align(start, len) {
        return SMMRet::Error;
    }

    // Get lock from here.
    let mut guard = SEC_REGIONS.lock();
    // Init secure monitor PMP regions (only for memory overlap check, not used for
    // secure memory alloc), usually this will take at least one PMP slot to fully protect
    // whole Rust prototyper.
    get_region(&mut guard, PMP4PROTECT_SM, |r| {
        r.permission = Permission::NONE;
        r.mode = Range::NAPOT;
        r.is_valid = true;
        unsafe {
            r.mem_region.start = SBI_START_ADDRESS;
            r.mem_region.len = SBI_END_ADDRESS - SBI_START_ADDRESS;
        }
    });

    // Init first secure memory PMP regions. This memory region will protected by PMP slot
    // indexd by @pmp_idx and used for secure memory alloc.
    if let Some(unused_region) = get_unused_region(&mut guard) {
        unused_region.is_valid = true;
        unused_region.permission = Permission::NONE;
        unused_region.mode = Range::NAPOT;
        unused_region.mem_region.len = len;
        unused_region.mem_region.start = start;
        unsafe {
            unused_region
                .mem_region
                .allocator
                .lock()
                .init(unused_region.mem_region.start, unused_region.mem_region.len);
        }
    } else {
        // Cannot find any unused secure region.
        return SMMRet::Error;
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
