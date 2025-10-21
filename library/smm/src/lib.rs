//! Penglai/Keystone style secure memory management module.

extern crate alloc;
use crate::allocators::{DefaultAllocator, KeystoneAllocator, PenglaiAllocator};
use alloc::vec::Vec;
use core::alloc::Layout;
use core::ptr::NonNull;
use log::{error, info};
use pmpm::MAX_PMP_ENTRY_COUNT;
use pmpm::MemSlice;
use riscv::register::{Permission, Range};
pub mod allocators;
pub mod manager;
#[derive(PartialEq, Clone, Copy)]
enum SecMemType {
    General,
    App,
    Runtime,
    None,
}

#[derive(Clone, Copy)]
pub struct PMPInfo {
    slot: u8,
    hperm: Permission,
    hmode: Range,
    eperm: Permission,
    emode: Range,
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
    alloc_type : 
}

pub enum SecMemRegionUnion<const ORDER: usize, const ALIGN: usize> {
    Default(SecMemRegion<ORDER, ALIGN, DefaultAllocator<ORDER>>),
    Penglai(SecMemRegion<ORDER, ALIGN, PenglaiAllocator<ORDER>>),
    Keystone(SecMemRegion<ORDER, ALIGN, KeystoneAllocator<ORDER>>),
}

impl PMPInfo {
    pub const fn new() -> Self {
        Self {
            slot: u8::max_value(),
            hperm: Permission::NONE,
            hmode: Range::OFF,
            eperm: Permission::NONE,
            emode: Range::OFF,
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
            mtype: SecMemType::General,
            pinfo: param.pinfo,
            allocator: A::new(),
        };
        // Init allocator.
        new_region.allocator.init(new_region.slice);
        new_region
    }
    #[inline]
    pub fn alloc(&mut self, size: usize) -> Result<(NonNull<u8>, usize), ()> {
        let mut real_size = (size + ALIGN) & (!(ALIGN - 1));
        if self.mtype == SecMemType::Runtime {
            real_size = self.slice.size();
        }
        match self
            .allocator
            .alloc(unsafe { Layout::from_size_align_unchecked(real_size, ALIGN) })
        {
            Ok(ptr) => Ok((ptr, real_size)),
            Err(_) => Err(()),
        }
    }
    // If target region is overlap with current mem region.
    pub fn is_mem_overlap(&self, slice: MemSlice) -> bool {
        if slice.start() <= self.slice.end() && (self.slice.start() <= slice.end()) {
            return true;
        }
        return false;
    }
    // If current mem region contains target region.
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
}

pub struct SecMemManager<const ORDER: usize, const ALIGN: usize> {
    regions: Vec<SecMemRegionUnion<ORDER, ALIGN>>,
}

impl<const ORDER: usize, const ALIGN: usize> SecMemManager<ORDER, ALIGN> {
    // Init manager, create regions manage structure.
    fn init(&mut self, params: &Vec<SecMemParams>) {
        self.regions.clear();
        for param in params.iter() {
            if check_params(&param) {
                let new_region = SecMemRegion::<ORDER, ALIGN, DefaultAllocator<ORDER>>::new(&param);
                info!(
                    "[PENGLAI] new region, slot:{}, addr:0x{:0x}, size:0x{:0x}",
                    new_region.pinfo.slot,
                    new_region.slice.start(),
                    new_region.slice.size()
                );
                self.regions.push(SecMemRegionUnion::Default(new_region));
            }
        }
    }
    // Create new region with mem.
    fn extend(params: &SecMemParams) {}
    // Reclaim mem from unused region.
    fn reclaim() {}
    // Alloc enough mem from manager.
    fn alloc(size: usize) -> MemSlice {}
    // Free mem to manager.
    fn free(ptr: NonNull<u8>) {}
    // Deinit manager, free all resource.
    fn deinit(&self) -> Vec<MemSlice> {
        self.regions
            .iter()
            .filter_map(|region_union| match region_union {
                SecMemRegionUnion::Penglai(region) => Some(region.slice),
                SecMemRegionUnion::Keystone(region) => Some(region.slice),
                _ => None,
            })
            .collect()
    }
}

/// Helper functions.
#[inline]
fn check_params(param: &SecMemParams) -> bool {
    if param.pinfo.slot >= MAX_PMP_ENTRY_COUNT {
        error!(
            "Check params failed, slot:{}, addr:0x{:0x}, size:0x{:0x}",
            param.pinfo.slot,
            param.slice.start(),
            param.slice.size()
        );
        return false;
    }
    true
}
