//! Penglai/Keystone style secure memory management module.
#![no_std]
#[allow(unused)]
extern crate alloc;
use crate::allocators::NoneAlloc;
use alloc::vec::Vec;
use core::alloc::Layout;
use core::ptr::NonNull;
use log::error;
use pmpm::MAX_PMP_ENTRY_COUNT;
use riscv::register::{Permission, Range};

pub mod allocators;
mod test;

#[derive(Clone, Copy)]
pub struct PMPInfo {
    slot: u8,
    mode: Range,
    perm: Permission,
}

#[derive(Clone, Copy, PartialEq)]
pub enum SecMemAllocatorWrapper<const ORDER: usize, AR, AA>
where
    AR: SecMemAllocator<ORDER>,
    AA: SecMemAllocator<ORDER>,
{
    None,
    General,
    Runtime(AR),
    Application(AA),
}

#[derive(Clone, Copy, PartialEq)]
pub enum SecMemType {
    None,
    General,
    Runtime,
    Application,
}

#[derive(Clone, Copy)]
struct SecMemRegion<const ALIGN: usize, const ORDER: usize, AR, AA>
where
    AR: SecMemAllocator<ORDER>,
    AA: SecMemAllocator<ORDER>,
{
    addr: usize,
    len: usize,
    id: usize,
    pinfo: PMPInfo,
    is_used: bool,
    pub allocator: SecMemAllocatorWrapper<ORDER, AR, AA>,
}

#[derive(Clone, Copy)]
pub struct SecMemParams {
    pinfo: PMPInfo,
    addr: usize,
    len: usize,
}

impl PMPInfo {
    pub const fn new() -> Self {
        Self {
            slot: 0,
            mode: Range::OFF,
            perm: Permission::NONE,
        }
    }
}

pub trait SecMemAllocator<const ORDER: usize> {
    /// Create new allocator
    fn new() -> Self;
    /// Init allocator with specific memory region.
    fn init(&mut self, addr: usize, len: usize) {
        let _ = (addr, len);
    }
    /// Alloc mem from allocator.
    fn alloc(&mut self, layout: Layout) -> Result<NonNull<u8>, ()> {
        let _ = layout;
        Err(())
    }
    /// Free mem to allocator.
    fn free(&mut self, ptr: NonNull<u8>, layout: Layout) {
        let _ = (ptr, layout);
    }
    /// Avaliable mem can be alloced.
    fn available(&self) -> usize {
        0
    }
    /// Total mem.
    fn total(&self) -> usize {
        0
    }
}

impl<const ALIGN: usize, const ORDER: usize, AR, AA> SecMemRegion<ALIGN, ORDER, AR, AA>
where
    AR: SecMemAllocator<ORDER>,
    AA: SecMemAllocator<ORDER>,
{
    /// Create new region
    pub fn new(param: &SecMemParams, id: usize) -> Self {
        Self {
            addr: param.addr,
            len: param.len,
            pinfo: param.pinfo,
            id,
            is_used: false,
            allocator: SecMemAllocatorWrapper::None,
        }
    }

    /// If target region is overlap with current mem region.
    #[inline]
    pub fn is_mem_overlap(&self, addr: usize, len: usize) -> bool {
        let self_end = self.addr + self.len;
        if let Some(target_end) = addr.checked_add(len) {
            return addr < self_end && self.addr < target_end;
        }
        true
    }

    /// If current mem region contains target region.
    #[inline]
    pub fn is_mem_contained(&self, addr: usize, len: usize) -> bool {
        let self_end = self.addr + self.len;
        if let Some(target_end) = addr.checked_add(len) {
            return addr >= self.addr && target_end <= self_end;
        }
        false
    }
}

pub trait SecMemManager<const ALIGN: usize, const ORDER: usize, AR, AA>
where
    AR: SecMemAllocator<ORDER>,
    AA: SecMemAllocator<ORDER>,
{
    /// Create and init new manager
    fn init(sm_param: &SecMemParams) -> Self;
    /// Delete manager, free all resource.
    fn deinit(self, cur_regions: &mut [(usize, usize); MAX_PMP_ENTRY_COUNT as usize]) -> u32;
    /// Create new region with mem.
    fn extend(&mut self, params: &SecMemParams) -> bool;
    /// Reclaim an unused allocable region from manager
    fn reclaim(&mut self) -> Option<(usize, usize)>;
    /// Alloc enclave mem from request region of type
    fn alloc_em(&mut self, len: usize, em_type: SecMemType) -> Option<(usize, usize, usize)>;
    /// Free enclave mem back to origin region
    fn free_em(&mut self, addr: usize, len: usize, region_id: usize) -> Option<bool>;
    /// Isolate region from untrust components
    fn protect_region(&self, pmp_idx: u32) -> bool;
    /// De-isolate region from untrust components
    fn unprotect_region(&self, pmp_idx: u32) -> bool;
}

pub struct MultiSecMemManager<const ALIGN: usize, const ORDER: usize, AR, AA>
where
    AR: SecMemAllocator<ORDER>,
    AA: SecMemAllocator<ORDER>,
{
    // A simple incrementing ID
    cur_idx: usize,
    /// These region are reserved and not used to alloc enclave mem.
    ///
    /// PMP N-1 : Default grant kernel access with all mem.
    /// PMP 1   : Only used in Penglai, for temporarily grant kernel access with specific sec mem.
    /// PMP 0   : Protect SM code/data.
    reserved_regions: Vec<SecMemRegion<ALIGN, ORDER, NoneAlloc<ORDER>, NoneAlloc<ORDER>>>,
    /// These region are used to manage allocable secure mem.
    ///
    /// Use PMP 2~(N-2)
    alloc_regions: Vec<SecMemRegion<ALIGN, ORDER, AR, AA>>,
}

impl<const ALIGN: usize, const ORDER: usize, AR, AA> SecMemManager<ALIGN, ORDER, AR, AA>
    for MultiSecMemManager<ALIGN, ORDER, AR, AA>
where
    AR: SecMemAllocator<ORDER>,
    AA: SecMemAllocator<ORDER>,
{
    fn init(sm_param: &SecMemParams) -> Self {
        let mut reserved_regions = Vec::<
            SecMemRegion<ALIGN, ORDER, NoneAlloc<ORDER>, NoneAlloc<ORDER>>,
        >::with_capacity(3usize);
        let alloc_regions = Vec::<SecMemRegion<ALIGN, ORDER, AR, AA>>::with_capacity(
            (MAX_PMP_ENTRY_COUNT - 3) as usize,
        );
        if check_mem_align(sm_param.addr, sm_param.len, ALIGN) {
            reserved_regions.push(SecMemRegion::<
                ALIGN,
                ORDER,
                NoneAlloc<ORDER>,
                NoneAlloc<ORDER>,
            >::new(sm_param, 0));
            Self {
                cur_idx: 0,
                reserved_regions: reserved_regions,
                alloc_regions: alloc_regions,
            }
        } else {
            panic!("[SMM] Cannot protect SM due to memory check fail");
        }
    }

    fn deinit(mut self, cur_regions: &mut [(usize, usize); MAX_PMP_ENTRY_COUNT as usize]) -> u32 {
        let count = self.alloc_regions.len();
        for (idx, region) in self.alloc_regions.drain(..).enumerate() {
            unsafe {
                core::ptr::write_bytes(region.addr as *mut u8, 0, region.len);
            }
            cur_regions[idx] = (region.addr, region.len)
        }
        count as u32
    }

    fn extend(&mut self, params: &SecMemParams) -> bool {
        let overlap_region = self
            .alloc_regions
            .iter()
            .find(|region| region.is_mem_overlap(params.addr, params.len));
        if check_pmp_cfg(&params.pinfo)
            && (self.alloc_regions.capacity() > self.alloc_regions.len())
        {
            self.cur_idx += 1;
            self.alloc_regions
                .push(SecMemRegion::<ALIGN, ORDER, AR, AA>::new(
                    params,
                    self.cur_idx,
                ));
            return true;
        }
        false
    }

    fn reclaim(&mut self) -> Option<(usize, usize)> {
        let index = self
            .alloc_regions
            .iter()
            .position(|region| region.is_used == false)?;
        let region = self.alloc_regions.swap_remove(index);
        unsafe {
            core::ptr::write_bytes(region.addr as *mut u8, 0, region.len);
        }
        Some((region.addr, region.len))
    }

    fn alloc_em(&mut self, len: usize, em_type: SecMemType) -> Option<(usize, usize, usize)> {
        // Init alloc layout, size must be multiple of align
        let alloc_layout = Layout::from_size_align(len, ALIGN).ok()?.pad_to_align();

        for region in self.alloc_regions.iter_mut() {
            if region.len < len {
                continue;
            }

            // If region is General, then change it to request type
            // BEWARE that alloc should success in most of time, so change of type won't reverse even when alloc failed,
            // if region reach limits, it depends on TEE Manager to reclaim unused regions manully.
            if matches!(region.allocator, SecMemAllocatorWrapper::General) {
                if matches!(em_type, SecMemType::Runtime) {
                    let mut alloc = AR::new();
                    alloc.init(region.addr, region.len);
                    region.allocator = SecMemAllocatorWrapper::Runtime(alloc);
                } else if matches!(em_type, SecMemType::Application) {
                    let mut alloc = AA::new();
                    alloc.init(region.addr, region.len);
                    region.allocator = SecMemAllocatorWrapper::Application(alloc);
                }
            }

            // If region type is equal to request type, try alloc enclave mem
            if let Ok(ptr) = match &mut region.allocator {
                SecMemAllocatorWrapper::Runtime(alloc)
                    if matches!(em_type, SecMemType::Runtime)
                    // Pre-allocation capacity check
                        && (alloc.available() >= alloc_layout.size()) =>
                {
                    alloc.alloc(alloc_layout)
                }
                SecMemAllocatorWrapper::Application(alloc)
                    if matches!(em_type, SecMemType::Application)
                    // Pre-allocation capacity check
                        && (alloc.available() >= alloc_layout.size()) =>
                {
                    alloc.alloc(alloc_layout)
                }
                _ => Err(()),
            } {
                // If alloc successfully, get addr and idx of region
                region.is_used = true;
                return Some((ptr.as_ptr() as usize, alloc_layout.size(), region.id));
            }
        }
        None
    }

    fn free_em(&mut self, addr: usize, len: usize, region_id: usize) -> Option<bool> {
        let free_layout = Layout::from_size_align(len, ALIGN).ok()?.pad_to_align();
        let free_ptr = NonNull::new(addr as *mut u8)?;

        if let Some(free_region) = self
            .alloc_regions
            .iter_mut()
            .find(|region| region.is_mem_contained(addr, len))
        {
            if region_id != free_region.id {
                panic!(
                    "[SMM] Memory region matches but the specific region ID does not.free addr:{}, 
                    free size:{}, region addr:{}, region size:{}, expect region:{}, findeds region:{}",
                    addr, len, free_region.addr, free_region.len, region_id, free_region.id
                )
            }
            return match &mut free_region.allocator {
                SecMemAllocatorWrapper::Application(alloc) => {
                    alloc.free(free_ptr, free_layout);
                    if alloc.available() == alloc.total() {
                        free_region.is_used = false;
                        free_region.allocator = SecMemAllocatorWrapper::General;
                    }
                    Some(true)
                }
                SecMemAllocatorWrapper::Runtime(alloc) => {
                    alloc.free(free_ptr, free_layout);
                    if alloc.available() == alloc.total() {
                        free_region.is_used = false;
                        free_region.allocator = SecMemAllocatorWrapper::General;
                    }
                    Some(true)
                }
                _ => None,
            };
        }
        None
    }

    fn protect_region(&self, pmp_idx: u32) -> bool {
        false
    }

    fn unprotect_region(&self, pmp_idx: u32) -> bool {
        false
    }
}

impl<const ALIGN: usize, const ORDER: usize, AR, AA> MultiSecMemManager<ALIGN, ORDER, AR, AA>
where
    AR: SecMemAllocator<ORDER>,
    AA: SecMemAllocator<ORDER>,
{
    /// Temporary grant untrusted components access to secure memory area
    fn grant_access(addr: usize, len: usize) -> bool {
        true
    }
    /// Retrive untrusted components access to secure memory area
    fn retrive_access(addr: usize, len: usize) -> bool {
        true
    }
}

/// Helper functions.
/// Check PMP cfg validation
fn check_pmp_cfg(pinfo: &PMPInfo) -> bool {
    if pinfo.slot as u32 >= MAX_PMP_ENTRY_COUNT {
        error!("Check params failed, slot:{}", pinfo.slot,);
        return false;
    }
    true
}
/// Check mem validation.  
pub fn check_mem_align(addr: usize, len: usize, align: usize) -> bool {
    // Size must be non-zero and a multiple of ALIGN.
    if (len == 0) || (!len.is_multiple_of(align)) || (!addr.is_multiple_of(align)) {
        error!(
            "Alignment Check Failed: len 0x{:x} is not non-zero or not a multiple of ALIGN 0x{:x}.",
            len, align
        );
        return false;
    }
    true
}
