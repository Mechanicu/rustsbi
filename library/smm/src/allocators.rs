use super::SecMemAllocator;
use buddy_system_allocator::Heap;
use core::alloc::Layout;
use core::ptr::NonNull;
use pmpm::MemSlice;

pub struct DefaultAllocator<const ORDER: usize> {}

pub struct PenglaiAllocator<const ORDER: usize> {
    buddy: Heap<ORDER>,
}
pub struct KeystoneAllocator<const ORDER: usize> {
    area: (MemSlice, bool),
}

/// Default allocator, for read only sec mem (like SM code/data).
impl<const ORDER: usize> SecMemAllocator<ORDER> for DefaultAllocator<ORDER> {
    fn new() -> Self {
        Self {}
    }
    fn alloc(&mut self, layout: Layout) -> Result<NonNull<u8>, ()> {
        Err(())
    }
    fn free(&mut self, ptr: NonNull<u8>, layout: Layout) {}
    fn init(&mut self, slice: MemSlice) {}
    fn avaliable(&self) -> usize {
        0
    }
    fn total(&self) -> usize {
        0
    }
}

/// Memory allocation style of Penglai. Penglai supports enclaves sharing a
/// secure memory region, which is allocated using the buddy algorithm.
impl<const ORDER: usize> SecMemAllocator<ORDER> for PenglaiAllocator<ORDER> {
    fn new() -> Self {
        Self {
            buddy: Heap::<ORDER>::new(),
        }
    }
    fn init(&mut self, slice: MemSlice) {
        unsafe {
            self.buddy.init(slice.start(), slice.size());
        }
    }
    fn alloc(&mut self, layout: Layout) -> Result<NonNull<u8>, ()> {
        self.buddy.alloc(layout)
    }
    fn free(&mut self, ptr: NonNull<u8>, layout: Layout) {
        self.buddy.dealloc(ptr, layout);
    }
    fn avaliable(&self) -> usize {
        self.buddy.stats_total_bytes() - self.buddy.stats_alloc_actual()
    }
    fn total(&self) -> usize {
        self.buddy.stats_total_bytes()
    }
}

/// Memory allocation style of Keystone. Enclaves in Keystone exclusively occupy
/// the entire region, thus the region is merely marked and no further allocation
/// is performed within it.
impl<const ORDER: usize> SecMemAllocator<ORDER> for KeystoneAllocator<ORDER> {
    fn new() -> Self {
        Self {
            area: (MemSlice::new(0, 0, 0), false),
        }
    }
    fn init(&mut self, slice: MemSlice) {
        self.area = (slice, true);
    }
    fn alloc(&mut self, layout: Layout) -> Result<NonNull<u8>, ()> {
        if (self.area.1 == false) || (self.area.0.size() < layout.size()) {
            return Err(());
        }

        self.area.1 = false;
        Ok(NonNull::new(self.area.0.start() as *mut u8).ok_or(())?)
    }
    fn free(&mut self, ptr: NonNull<u8>, layout: Layout) {
        if (self.area.1 == true) || (ptr.as_ptr() as usize != self.area.0.start()) {
            panic!("Deallocating foreign or incorrect pointer");
        }
        self.area.1 = true;
    }
    fn avaliable(&self) -> usize {
        if self.area.1 == true {
            self.area.0.size()
        } else {
            0
        }
    }
    fn total(&self) -> usize {
        self.area.0.size()
    }
}

