use super::SecMemAllocator;
use buddy_system_allocator::Heap;
use core::alloc::Layout;
use core::ptr::NonNull;

pub struct AppAlloc<const ORDER: usize> {
    buddy: Heap<ORDER>,
}
pub struct RTAlloc<const ORDER: usize> {
    addr: usize,
    len: usize,
    total: usize,
}

pub struct NoneAlloc<const ORDER: usize> {}

impl<const ORDER: usize> SecMemAllocator<ORDER> for NoneAlloc<ORDER> {
    fn new() -> Self {
        Self {}
    }
}

/// Memory allocation style of Penglai. Penglai supports enclaves sharing a
/// secure memory region, which is allocated using the buddy algorithm.
impl<const ORDER: usize> SecMemAllocator<ORDER> for AppAlloc<ORDER> {
    fn new() -> Self {
        Self {
            buddy: Heap::<ORDER>::new(),
        }
    }
    fn init(&mut self, addr: usize, len: usize) {
        unsafe {
            self.buddy.init(addr as usize, len as usize);
        }
    }
    fn alloc(&mut self, layout: Layout) -> Result<NonNull<u8>, ()> {
        self.buddy.alloc(layout)
    }
    fn free(&mut self, ptr: NonNull<u8>, layout: Layout) {
        self.buddy.dealloc(ptr, layout);
    }
    fn available(&self) -> usize {
        self.buddy.stats_total_bytes() - self.buddy.stats_alloc_actual()
    }
    fn total(&self) -> usize {
        self.buddy.stats_total_bytes()
    }
}

/// Memory allocation style of Keystone. Enclaves in Keystone exclusively occupy
/// the entire region, thus the region is merely marked and no further allocation
/// is performed within it.
impl<const ORDER: usize> SecMemAllocator<ORDER> for RTAlloc<ORDER> {
    fn new() -> Self {
        Self {
            addr: 0,
            len: 0,
            total: 0,
        }
    }
    fn init(&mut self, addr: usize, len: usize) {
        self.addr = addr;
        self.len = len;
        self.total = len;
    }
    fn alloc(&mut self, layout: Layout) -> Result<NonNull<u8>, ()> {
        if (self.len as usize) < layout.size() {
            return Err(());
        }
        self.len = 0;
        Ok(NonNull::new(self.addr as *mut u8).ok_or(())?)
    }
    fn free(&mut self, ptr: NonNull<u8>, layout: Layout) {
        if ptr.as_ptr() as usize != self.addr {
            panic!("[RTAlloc] Deallocating foreign or incorrect pointer");
        }
        self.len = layout.size() as usize;
    }
    fn available(&self) -> usize {
        self.len as usize
    }
    fn total(&self) -> usize {
        self.total as usize
    }
}
