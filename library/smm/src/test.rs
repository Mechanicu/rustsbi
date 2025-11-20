use super::*;

#[cfg(test)]
mod test_allocator {
    use super::*;
    use alloc::boxed::Box;
    use alloc::vec::Vec;
    const HEAP_SIZE: usize = 1 << 12 << 4;

    /// Test utility: Creates a MemSlice by leaking a Boxed array, simulating a static memory area.
    fn create_mem_slice_test_safe() -> MemSlice {
        // Create a boxed array and leak it to get a stable, static address.
        let boxed_memory: Box<[u8; HEAP_SIZE]> = Box::new([0; HEAP_SIZE]);
        let leaked_slice: &'static mut [u8] = Box::leak(boxed_memory);
        let start_addr = leaked_slice.as_mut_ptr() as usize;
        MemSlice::new(HEAP_SIZE, start_addr, 0)
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
        unsafe { core::ptr::write_bytes(raw_ptr, pattern, size) };

        // 2. Read: Verify the write
        // Convert the raw pointer into a temporary, mutable byte slice (&mut [u8])
        let slice = unsafe { core::slice::from_raw_parts(raw_ptr, size) };

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

#[cfg(test)]
mod test_region {
    use super::*;

    // Define constants to match the generic constraints
    const TEST_ORDER: usize = 32; // Common buddy system order
    const TEST_ALIGN: usize = 4096; // Common page size for alignment (ALIGN)
    const HEAP_SIZE: usize = (1 << 20) + TEST_ALIGN * 3; // 1 MB of test memory

    // --- TEST UTILITIES ---
    /// Creates a MemSlice by leaking a Boxed array to get a stable, static address.
    fn create_mem_slice_test_safe() -> MemSlice {
        let boxed_memory: Box<[u8; HEAP_SIZE]> = Box::new([0; HEAP_SIZE]);
        let leaked_slice: &'static mut [u8] = Box::leak(boxed_memory);
        let start_addr = leaked_slice.as_mut_ptr() as usize;
        MemSlice::new(HEAP_SIZE, start_addr, 0)
    }

    // --- TEST SUITE FOR PenglaiAllocator (Buddy System) ---

    type PenglaiRegion = SecMemRegion<TEST_ORDER, 64, PenglaiAllocator<TEST_ORDER>>;

    #[test]
    fn penglai_region_test() {
        let param = SecMemParams {
            pinfo: PMPInfo::new(),
            slice: (create_mem_slice_test_safe()),
            mtype: (SecMemType::App),
        };
        let mut penglai = PenglaiRegion::new(&param);
        println!(
            "PENGLAI: total:{:0x}, aval:{:0x}, addr:{:0x}",
            penglai.allocator.total(),
            penglai.allocator.avaliable(),
            param.slice.start()
        );
        assert_eq!(penglai.allocator.total(), param.slice.size());
        assert_eq!(penglai.allocator.avaliable(), param.slice.size());

        let mut current_size = TEST_ALIGN;
        while current_size <= HEAP_SIZE {
            match penglai.alloc(current_size) {
                Ok(slice) => {
                    unsafe {
                        (slice.start() as *mut u8).write_bytes(0xff, current_size);
                    }
                    println!(
                        "PENGLAI: alloc:{:0x}, aval:{:0x}",
                        slice.size(),
                        penglai.allocator.avaliable()
                    );
                    penglai.free(slice);
                    current_size += TEST_ALIGN;
                }
                Err(_) => {
                    println!("Failed, OOM, current size:{}", current_size);
                    break;
                }
            }
        }
    }

    fn create_mock_param(mtype: SecMemType, index: usize) -> SecMemParams {
        SecMemParams {
            mtype,
            slice: MemSlice::new(0x2000, 0x1000_0000 + index * 0x1000, 0),
            pinfo: PMPInfo::new(),
        }
    }
    const TEST_ROUNDS: usize = 2;
    #[repr(align(4096))]
    pub struct PageAlignedArray<const N: usize> {
        data: [u8; N],
    }

    impl<const N: usize> PageAlignedArray<N> {
        pub const fn new() -> Self {
            PageAlignedArray { data: [0; N] }
        }
    }
    const PENGLAI_REGION_SIZE: usize = 1 << 20 << 5;
    const KEYSTONE_REGION_SIZE: usize = 1 << 20 << 4;
    static mut PENGLAI_REGION: PageAlignedArray<PENGLAI_REGION_SIZE> = PageAlignedArray::new();
    static mut KEYSTONE_REGION: PageAlignedArray<KEYSTONE_REGION_SIZE> = PageAlignedArray::new();
    #[test]
    #[allow(static_mut_refs)]
    pub fn stress_test_sec_mem_manager() {
        for round in 0..TEST_ROUNDS {
            let sm_param = create_mock_param(SecMemType::Monitor, 0);
            let app_valid_param = SecMemParams {
                pinfo: PMPInfo::new(),
                slice: MemSlice::new(
                    PENGLAI_REGION_SIZE,
                    unsafe { PENGLAI_REGION.data.as_ptr() as usize },
                    0,
                ),
                mtype: SecMemType::App,
            };
            let rt_valid_param = SecMemParams {
                pinfo: PMPInfo::new(),
                slice: MemSlice::new(
                    KEYSTONE_REGION_SIZE,
                    unsafe { KEYSTONE_REGION.data.as_ptr() as usize },
                    0,
                ),
                mtype: SecMemType::Runtime,
            };
            let rt_invalid_param = SecMemParams {
                pinfo: PMPInfo::new(),
                slice: MemSlice::new(
                    KEYSTONE_REGION_SIZE + KEYSTONE_REGION_SIZE / 2,
                    unsafe { KEYSTONE_REGION.data.as_ptr() as usize + KEYSTONE_REGION_SIZE / 2 },
                    0,
                ),
                mtype: SecMemType::Runtime,
            };
            let app_invalid_param = SecMemParams {
                pinfo: PMPInfo::new(),
                slice: MemSlice::new(
                    PENGLAI_REGION_SIZE / 2,
                    unsafe { PENGLAI_REGION.data.as_ptr() as usize },
                    0,
                ),
                mtype: SecMemType::Runtime,
            };
            // init and extend regions
            let mut manager = SecMemManager::<TEST_ORDER, TEST_ALIGN>::new(&sm_param);
            let mut initial_params = (1..=10)
                .map(|i| create_mock_param(SecMemType::None, i))
                .collect::<Vec<_>>();
            initial_params.push(app_valid_param);
            initial_params.push(rt_valid_param);
            initial_params.push(app_invalid_param);
            initial_params.push(rt_invalid_param);
            for param in initial_params.iter() {
                manager.extend(param);
            }

            // delete and retrive slices test
            let released_slices = manager.delete();
            assert!(
                (manager.app_regions.len() == 0)
                    || (manager.rt_regions.len() == 0)
                    || (manager.nonsec_regions.len() == 0),
                "regions was not cleared by delete.",
            );
            for slice in released_slices.iter() {
                println!(
                    "Retrive slice: addr:{:0x}, size:{:0x}",
                    slice.start(),
                    slice.size()
                );
            }
            assert!(
                released_slices.len() > 0,
                "Round {} delete returned no slices.",
                round
            );
        }
    }
}
