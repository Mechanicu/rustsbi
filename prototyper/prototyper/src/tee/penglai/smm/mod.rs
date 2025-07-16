//! Secure memory management of Penglai PMP extension in RustSBI.
//!

use buddy_system_allocator::LockedHeap;
use core::alloc::Layout;
use core::ptr::NonNull;
use rustsbi::SbiRet;

mod buddy;

pub const SECMEM_MAX_ORDER: usize = 20;

pub trait SecmemRegionAllocator {
    fn new(start: usize, end: usize) -> Self;
    fn init(&self);
    fn alloc(&self, layout: Layout) -> Result<NonNull<u8>, ()>;
    fn dealloc(&self, ptr: NonNull<u8>, layout: Layout);
    fn check_used(&self) -> usize;
    fn range_check(&self, start: usize, end: usize) -> bool;
}

pub struct SecmemRegion {
    pub start: usize,
    pub len: usize,
    pub allocator: LockedHeap<SECMEM_MAX_ORDER>,
    pub is_valid: bool,
}

// pub SecmemPMPRegion : [SecmemPMPRegion] = [];

pub fn secmem_manager_init(start_addr: usize, len: usize) -> SbiRet {}

pub fn secmem_extend() -> SbiRet {}

pub fn secmem_reclaim() -> SbiRet {}

pub fn secmem_alloc() -> SbiRet {}

pub fn secmem_free() -> SbiRet {}
