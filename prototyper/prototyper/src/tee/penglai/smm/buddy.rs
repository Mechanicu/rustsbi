//! buddy algorithm for secure memory management.
//!
use super::{SECMEM_MAX_ORDER, SecmemRegion, SecmemRegionAllocator};
use buddy_system_allocator::LockedHeap;
use core::ptr::NonNull;

impl SecmemRegionAllocator for SecmemRegion {
    fn new(start: usize, len: usize) -> Self {
        Self {
            start: (start),
            len: len,
            allocator: LockedHeap::<SECMEM_MAX_ORDER>::empty(),
            is_valid: true,
        }
    }
    #[inline]
    fn init(&self) {
        unsafe {
            self.allocator.lock().init(self.start, self.len);
        }
    }
    #[inline]
    fn alloc(&self, layout: core::alloc::Layout) -> Result<NonNull<u8>, ()> {
        self.allocator.lock().alloc(layout)
    }
    #[inline]
    fn dealloc(&self, ptr: NonNull<u8>, layout: core::alloc::Layout) {
        self.allocator.lock().dealloc(ptr, layout);
    }
    #[inline]
    fn check_used(&self) -> usize {
        self.allocator.lock().stats_alloc_actual()
    }
    #[inline]
    fn range_check(&self, start: usize, end: usize) -> bool {
        if self.start < end && (self.start + self.len > start) {
            return true;
        }
        return false;
    }
}
