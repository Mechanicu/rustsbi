//! Penglai/Keystone style secure memory management module.
// #![no_std]
#[allow(unused)]
extern crate alloc;
use crate::allocators::{DefaultAllocator, KeystoneAllocator, PenglaiAllocator};
use alloc::vec::Vec;
use core::alloc::Layout;
use core::mem::take;
use core::ptr::NonNull;
use log::error;
use pmpm::MAX_PMP_ENTRY_COUNT;
use pmpm::MemSlice;
use riscv::register::{Permission, Range};

pub mod allocators;

#[derive(PartialEq, Clone, Copy)]
pub enum SecMemType {
    Monitor,
    App,
    Runtime,
    None,
}

#[derive(Clone, Copy)]
pub struct PMPInfo {
    slot: u8,
    hperm: Permission,
    eperm: Permission,
    mode: Range,
}

#[derive(Clone, Copy)]
struct SecMemRegion<const ORDER: usize, const ALIGN: usize, A: SecMemAllocator<ORDER>> {
    mtype: SecMemType,
    slice: MemSlice,
    pinfo: PMPInfo,
    allocator: A,
}

#[derive(Clone, Copy)]
pub struct SecMemParams {
    pinfo: PMPInfo,
    slice: MemSlice,
    mtype: SecMemType,
}

impl PMPInfo {
    pub const fn new() -> Self {
        Self {
            slot: 0,
            hperm: Permission::NONE,
            mode: Range::OFF,
            eperm: Permission::NONE,
        }
    }
}

impl<const ORDER: usize, const ALIGN: usize, A> SecMemRegion<ORDER, ALIGN, A>
where
    A: SecMemAllocator<ORDER>,
{
    pub fn new(param: &SecMemParams) -> Self {
        let mut new_region = Self {
            slice: param.slice,
            mtype: param.mtype,
            pinfo: param.pinfo,
            allocator: A::new(),
        };
        // Init allocator.
        new_region.allocator.init(new_region.slice);
        new_region
    }
    // alloc mem from allocators
    #[inline]
    pub fn alloc(&mut self, size: usize) -> Result<MemSlice, ()> {
        let real_size: usize = match self.mtype {
            SecMemType::Runtime => self.slice.size(),
            SecMemType::App => size.next_power_of_two(),
            _ => 0,
        };
        match self
            .allocator
            .alloc(Layout::from_size_align(real_size, ALIGN).unwrap())
        {
            Ok(ptr) => Ok(MemSlice::new(real_size, ptr.as_ptr() as usize, 0)),
            Err(_) => Err(()),
        }
    }
    // free mem back to allocator
    #[inline]
    pub fn free(&mut self, slice: MemSlice) {
        self.allocator.free(
            NonNull::<u8>::new(slice.start() as *mut u8).unwrap(),
            Layout::from_size_align(slice.size(), ALIGN).unwrap(),
        );
    }
    // If target region is overlap with current mem region.
    #[inline]
    pub fn is_mem_overlap(&self, slice: MemSlice) -> bool {
        if slice.start() <= self.slice.end() && (self.slice.start() <= slice.end()) {
            return true;
        }
        return false;
    }
    // If current mem region contains target region.
    #[inline]
    pub fn is_mem_contained(&self, slice: MemSlice) -> bool {
        if slice.start() <= self.slice.end() && (self.slice.start() <= slice.start()) {
            return true;
        }
        return false;
    }
}

pub trait SecMemAllocator<const ORDER: usize> {
    /// Create new allocator
    fn new() -> Self;
    /// Init allocator with specific memory region.
    fn init(&mut self, slice: MemSlice);
    /// Alloc mem from allocator.
    fn alloc(&mut self, layout: Layout) -> Result<NonNull<u8>, ()>;
    // Free mem to allocator.
    fn free(&mut self, ptr: NonNull<u8>, layout: Layout);
    // Avaliable mem can be alloced.
    fn avaliable(&self) -> usize;
    // Total mem.
    fn total(&self) -> usize;
}

pub struct SecMemManager<const ORDER: usize, const ALIGN: usize> {
    // These region are non secure and no need to check overlap.
    // PMP N-1 : default grant kernel access with all mem.
    // PMP 0   : Only used in Penglai, for temporarily grant kernel access with specific sec mem.
    nonsec_regions: Vec<SecMemRegion<ORDER, ALIGN, DefaultAllocator<ORDER>>>,
    // These region are secure and need to check overlap.
    // SM region, protect SM code/data.
    sm_region: SecMemRegion<ORDER, ALIGN, DefaultAllocator<ORDER>>,
    // Penglai regions.
    app_regions: Vec<SecMemRegion<ORDER, ALIGN, PenglaiAllocator<ORDER>>>,
    // Keystone regions.
    rt_regions: Vec<SecMemRegion<ORDER, ALIGN, KeystoneAllocator<ORDER>>>,
}

impl<const ORDER: usize, const ALIGN: usize> SecMemManager<ORDER, ALIGN> {
    // Init manager, only create SM region.
    pub fn new(sm_param: &SecMemParams) -> Self {
        SecMemManager {
            nonsec_regions: Vec::new(),
            sm_region: SecMemRegion::new(sm_param),
            app_regions: Vec::new(),
            rt_regions: Vec::new(),
        }
    }
    // Delete manager, free all resource.
    pub fn delete(&mut self) -> Vec<MemSlice> {
        let app_regions = take(&mut self.app_regions);
        let rt_regions = take(&mut self.rt_regions);
        let mut regions: Vec<MemSlice> =
            app_regions.into_iter().map(|region| region.slice).collect();
        regions.extend(
            rt_regions
                .into_iter()
                .map(|region| region.slice)
                .collect::<Vec<MemSlice>>(),
        );
        regions
    }
    // Create new region with mem.
    pub fn extend(&mut self, params: &SecMemParams) -> bool {
        if !check_mem_align(params.slice, ALIGN)
            || !check_pmp_cfg(&params.pinfo)
            // new region shouldn't overlap with any exist region
            || self.check_mem_overlap(params.slice)
        {
            println!(
                "New region failed: addr {:0x}, len {:0x}",
                params.slice.start(),
                params.slice.size()
            );
            return false;
        }
        println!(
            "New region: addr {:0x}, len {:0x}",
            params.slice.start(),
            params.slice.size()
        );
        match params.mtype {
            SecMemType::App => self.app_regions.push(SecMemRegion::new(params)),
            SecMemType::Runtime => self.rt_regions.push(SecMemRegion::new(params)),
            SecMemType::None => self.nonsec_regions.push(SecMemRegion::new(params)),
            SecMemType::Monitor => error!("[SMM] There should only one SM region in global."),
        }
        true
    }

    // Reclaim mem from unused region.
    pub fn reclaim() {}

    // Alloc enough mem from manager.
    pub fn alloc(&mut self, size: usize, mtype: SecMemType) -> MemSlice {
        MemSlice::new(0, 0, 0)
    }

    // Free mem to manager.
    pub fn free(&mut self, slice: MemSlice) {}

    fn check_mem_overlap(&self, slice: MemSlice) -> bool {
        // Check if new region overlap with any sec mem.
        if self
            .app_regions
            .iter()
            .any(|region| region.is_mem_overlap(slice))
            || self
                .rt_regions
                .iter()
                .any(|region| region.is_mem_overlap(slice))
            || self.sm_region.is_mem_overlap(slice)
        {
            return true;
        }
        false
    }
}

/// Helper functions.
/// Check PMP cfg validation
fn check_pmp_cfg(pinfo: &PMPInfo) -> bool {
    if pinfo.slot >= MAX_PMP_ENTRY_COUNT {
        error!("Check params failed, slot:{}", pinfo.slot,);
        return false;
    }
    true
}
/// Check mem validation.  
fn check_mem_align(slice: MemSlice, align: usize) -> bool {
    let size = slice.size();
    let start = slice.start();

    // Size must be non-zero and a multiple of ALIGN.
    if (size == 0) || (!size.is_multiple_of(align)) || (!start.is_multiple_of(align)) {
        error!(
            "Alignment Check Failed: Size 0x{:x} is not non-zero or not a multiple of ALIGN 0x{:x}.",
            size, align
        );
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
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
