use super::SecMemAllocator;
use buddy_system_allocator::LockedHeap;
use core::alloc::Layout;
use core::ptr::NonNull;
use pmpm::MemSlice;
use spin::Mutex;

pub struct PenglaiAllocator<const ORDER: usize> {
    buddy: LockedHeap<ORDER>,
}
pub struct KeystoneAllocator<const ORDER: usize> {
    area: Mutex<(MemSlice, bool)>,
}

/// Memory allocation style of Penglai. Penglai supports enclaves sharing a 
/// secure memory region, which is allocated using the buddy algorithm.
impl<const ORDER: usize> SecMemAllocator<ORDER> for PenglaiAllocator<ORDER> {
    fn new() -> Self {
        Self {
            buddy: LockedHeap::<ORDER>::new(),
        }
    }
    fn init(&mut self, slice: MemSlice) {
        unsafe {
            self.buddy.lock().init(slice.start(), slice.size());
        }
    }
    fn alloc(&self, layout: Layout) -> Result<NonNull<u8>, ()> {
        self.buddy.lock().alloc(layout)
    }
    fn free(&self, ptr: NonNull<u8>, layout: Layout) {
        self.buddy.lock().dealloc(ptr, layout);
    }
}

/// Memory allocation style of Keystone. Enclaves in Keystone exclusively occupy
/// the entire region, thus the region is merely marked and no further allocation
/// is performed within it.
impl<const ORDER: usize> SecMemAllocator<ORDER> for KeystoneAllocator<ORDER> {
    fn new() -> Self {
        Self {
            area: Mutex::new((MemSlice::new(0, 0), false)),
        }
    }
    fn init(&mut self, slice: MemSlice) {
        *self.area.lock() = (slice, true);
    }
    #[allow(unused)]
    fn alloc(&self, layout: Layout) -> Result<NonNull<u8>, ()> {
        let mut guard = self.area.lock();
        if guard.1 == false {
            return Err(());
        }

        guard.1 = false;
        Ok(NonNull::new(guard.0.start() as *mut u8).ok_or(())?)
    }
    #[allow(unused)]
    fn free(&self, ptr: NonNull<u8>, layout: Layout) {
        let mut guard = self.area.lock();
        if guard.1 == true {
            panic!("Deallocating foreign or incorrect pointer");
        }
        guard.1 = true;
    }
}
