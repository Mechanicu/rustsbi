//! buddy algorithm for secure memory management.
//!
use super::{SECMEM_MAX_ORDER, SecmemRegion};
use buddy_system_allocator::LockedHeap;
use core::ptr::NonNull;

impl SecmemRegion {
    pub const fn new(start: usize, len: usize) -> Self {
        Self {
            start: (start),
            len: len,
            allocator: LockedHeap::<SECMEM_MAX_ORDER>::new(),
        }
    }
    #[inline]
    pub fn init(&mut self, start: usize, len: usize) {
        self.start = start;
        self.len = len;
        unsafe {
            self.allocator.lock().init(start, len);
        }
    }
    #[inline]
    pub fn alloc(&self, layout: core::alloc::Layout) -> Result<NonNull<u8>, ()> {
        self.allocator.lock().alloc(layout)
    }
    #[inline]
    pub fn dealloc(&self, ptr: NonNull<u8>, layout: core::alloc::Layout) {
        self.allocator.lock().dealloc(ptr, layout);
    }
    #[inline]
    pub fn extend(&self, start: usize, len: usize) {
        unsafe {
            self.allocator.lock().add_to_heap(start, start + len);
        }
    }
    #[inline]
    pub fn is_mem_overlap(&self, start: usize, end: usize) -> bool {
        if self.start < end && (self.start + self.len > start) {
            return true;
        }
        return false;
    }
    #[inline]
    pub fn check_used(&self) -> usize {
        self.allocator.lock().stats_alloc_actual()
    }
    #[inline]
    pub fn check_aval(&self) -> usize {
        self.allocator.lock().stats_total_bytes() - self.allocator.lock().stats_alloc_actual()
    }
}
