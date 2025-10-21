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
}

/// Memory allocation style of Keystone. Enclaves in Keystone exclusively occupy
/// the entire region, thus the region is merely marked and no further allocation
/// is performed within it.
impl<const ORDER: usize> SecMemAllocator<ORDER> for KeystoneAllocator<ORDER> {
    fn new() -> Self {
        Self {
            area: (MemSlice::new(0, 0), false),
        }
    }
    fn init(&mut self, slice: MemSlice) {
        self.area = (slice, true);
    }
    #[allow(unused)]
    fn alloc(&mut self, layout: Layout) -> Result<NonNull<u8>, ()> {
        if (self.area.1 == false) || (self.area.0.size() < layout.size()) {
            return Err(());
        }

        self.area.1 = false;
        Ok(NonNull::new(self.area.0.start() as *mut u8).ok_or(())?)
    }
    #[allow(unused)]
    fn free(&mut self, ptr: NonNull<u8>, layout: Layout) {
        if (self.area.1 == true) || (ptr.as_ptr() as usize != self.area.0.start()) {
            panic!("Deallocating foreign or incorrect pointer");
        }
        self.area.1 = true;
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    const HEAP_SIZE: usize = 1 << 12 << 4;

    /// Test utility: Creates a MemSlice by leaking a Boxed array, simulating a static memory area.
    fn create_mem_slice_test_safe() -> MemSlice {
        // Create a boxed array and leak it to get a stable, static address.
        let boxed_memory: Box<[u8; HEAP_SIZE]> = Box::new([0; HEAP_SIZE]);
        let leaked_slice: &'static mut [u8] = Box::leak(boxed_memory);
        let start_addr = leaked_slice.as_mut_ptr() as usize;
        MemSlice::new(HEAP_SIZE, start_addr)
    }

    /// Test utility: Creates a Layout object.
    fn create_layout(size: usize, align: usize) -> Layout {
        Layout::from_size_align(size, align).expect("Failed to create Layout")
    }

    /// Utility: Writes a pattern to the allocated block and verifies the read-back.
    ///
    /// # Safety
    /// Caller must ensure `ptr` is a valid, writable pointer of at least `size` bytes.
    unsafe fn check_memory_read_write(ptr: NonNull<u8>, size: usize, pattern: u8) {
        let raw_ptr = ptr.as_ptr();

        // 1. Write: Fill the entire block with the pattern (memset operation)
        std::ptr::write_bytes(raw_ptr, pattern, size);

        // 2. Read: Verify the write
        // Convert the raw pointer into a temporary, mutable byte slice (&mut [u8])
        let slice = core::slice::from_raw_parts(raw_ptr, size);

        // Verify every byte in the slice matches the pattern
        for (i, &byte) in slice.iter().enumerate() {
            assert_eq!(byte, pattern, "Memory pattern mismatch at offset {}", i);
        }
    }
    #[test]
    fn penglai_stress_test_increasing_size() {
        // Constants
        const PAGE_SIZE: usize = 4096;
        const MAX_ORDER: usize = 32;

        let mut allocator = PenglaiAllocator::<MAX_ORDER>::new();
        allocator.init(create_mem_slice_test_safe());

        // Vector to store allocated blocks for cleanup: (Pointer, Layout)
        let mut allocated_blocks: Vec<(NonNull<u8>, Layout)> = Vec::new();

        // Starting size and loop variables
        let mut current_size = PAGE_SIZE;
        let mut success_count = 0;

        println!("--- Starting Penglai Allocator Stress Test (Increasing Size) ---");

        loop {
            // Create Layout: size increases by PAGE_SIZE, alignment is PAGE_SIZE
            let layout = match Layout::from_size_align(current_size, PAGE_SIZE) {
                Ok(l) => l,
                Err(_) => {
                    println!("Error: Layout creation failed for size: {}", current_size);
                    break;
                }
            };

            // Attempt allocation
            match allocator.alloc(layout) {
                Ok(ptr) => {
                    success_count += 1;

                    // 1. Print address and size
                    println!(
                        "[SUCCESS #{}] ADDR: {:#x}, SIZE: {} bytes",
                        success_count,
                        ptr.as_ptr() as usize,
                        layout.size()
                    );

                    // 2. Perform memset and verification (using a pattern based on the count)
                    // The pattern will change for each block.
                    let pattern = (success_count & 0xFF) as u8;
                    // SAFETY: ptr is valid and owned by us.
                    unsafe {
                        check_memory_read_write(ptr, layout.size(), pattern);
                    }

                    // Store for later freeing
                    allocated_blocks.push((ptr, layout));

                    // Increase size for the next iteration (Page by Page)
                    current_size += PAGE_SIZE;
                }
                Err(_) => {
                    // 3. Allocation failed (OOM condition met)
                    println!("\n--- Allocation Failed (Out of Memory) ---");
                    println!("Failed to allocate a block of size: {} bytes", current_size);
                    println!("Total successful allocations: {}", success_count);
                    break;
                }
            }
        }
        println!(
            "\n--- Starting Deallocation (Total: {} blocks) ---",
            allocated_blocks.len()
        );

        // 4. Cleanup: Free all blocks
        let initial_count = allocated_blocks.len();
        for (i, (ptr, layout)) in allocated_blocks.into_iter().rev().enumerate() {
            // Log freeing operation
            println!(
                "[FREE #{}/{}] ADDR: {:#x}, SIZE: {} bytes",
                initial_count - i,
                initial_count,
                ptr.as_ptr() as usize,
                layout.size()
            );

            // SAFETY: The pointer and layout match what was allocated.
            allocator.free(ptr, layout);
        }

        // Final check: Allocate a small known size block to ensure the heap is functional after cleanup
        let final_layout = create_layout(PAGE_SIZE, PAGE_SIZE);
        let final_ptr = allocator
            .alloc(final_layout)
            .expect("Allocator failed post-cleanup check!");

        println!("\n--- Post-Cleanup Check Success ---");
        println!(
            "Successfully re-allocated a page at {:#x}",
            final_ptr.as_ptr() as usize
        );

        allocator.free(final_ptr, final_layout);
    }

    const KEYSTONE_ORDER: usize = 32;

    #[test]
    fn keystone_init_and_exclusive_alloc() {
        let mut allocator = KeystoneAllocator::<KEYSTONE_ORDER>::new();
        let slice = create_mem_slice_test_safe();
        let expected_start = slice.start();
        allocator.init(slice);

        let layout_any = create_layout(1, 1);
        let ptr1 = allocator
            .alloc(layout_any)
            .expect("Keystone first alloc failed");
        // 1. Print address and size
        println!(
            "[SUCCESS] ADDR: {:#x}, SIZE: {} bytes",
            ptr1.as_ptr() as usize,
            layout_any.size()
        );
        assert_eq!(
            ptr1.as_ptr() as usize,
            expected_start,
            "Keystone alloc returned incorrect start address"
        );

        let result_realloc = allocator.alloc(layout_any);
        assert!(result_realloc.is_err(), "Keystone re-alloc check failed");

        allocator.free(ptr1, layout_any);

        let ptr2 = allocator
            .alloc(layout_any)
            .expect("Keystone re-alloc after free failed");
        assert_eq!(
            ptr2.as_ptr() as usize,
            expected_start,
            "Keystone re-alloc returned incorrect start address"
        );

        allocator.free(ptr2, layout_any);
    }
}
