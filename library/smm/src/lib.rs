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
mod test;

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
            SecMemType::App => size.next_multiple_of(ALIGN),
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
        match params.mtype {
            SecMemType::None => self.nonsec_regions.push(SecMemRegion::new(params)),
            SecMemType::Monitor => {
                error!("[SMM] There should only one SM region in global.");
                return false;
            }
            SecMemType::App => {
                if self.check_mem_overlap(params.slice) {
                    return false;
                } else {
                    self.app_regions.push(SecMemRegion::new(params))
                }
            }
            SecMemType::Runtime => {
                if self.check_mem_overlap(params.slice) {
                    return false;
                } else {
                    self.rt_regions.push(SecMemRegion::new(params))
                }
            }
        }
        true
    }

    // Reclaim mem from unused region.
    pub fn reclaim() {}

    // Alloc enough mem from manager.
    pub fn alloc(&mut self, size: usize, mtype: SecMemType) -> Option<MemSlice> {
        match mtype {
            SecMemType::App => {
                self.app_regions
                    .iter_mut()
                    .find_map(|region| match region.alloc(size) {
                        Ok(slice) => Some(slice),
                        Err(_) => None,
                    })
            }
            SecMemType::Runtime => {
                self.rt_regions
                    .iter_mut()
                    .find_map(|region| match region.alloc(size) {
                        Ok(slice) => Some(slice),
                        Err(_) => None,
                    })
            }
            _ => {
                error!("[SMM] Shouldn't alloc memory from this type");
                return None;
            }
        }
    }

    // Free mem to manager.
    pub fn free(&mut self, slice: MemSlice, mtype: SecMemType) {
        
    }

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
