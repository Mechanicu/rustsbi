//! Penglai/Keystone style secure memory management module.

use core::alloc::Layout;
use core::ptr::NonNull;
use pmpm::MemSlice;
use riscv::register::{Permission, Range};

mod allocators;

#[derive(Debug, Clone, Copy)]
enum SecMemType {
    General,
    App,
    Runtime,
    None,
}

pub trait SecMemAllocator<const ORDER: usize> {
    fn new() -> Self;
    fn init(&mut self, slice: MemSlice);
    fn alloc(&self, layout: Layout) -> Result<NonNull<u8>, ()>;
    fn free(&self, ptr: NonNull<u8>, layout: Layout);
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
    align: usize,
    pinfo: PMPInfo,
    alloc: A,
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
    pub fn new(slice: MemSlice) -> Self {
        Self {
            slice,
            align: ALIGN,
            mtype: SecMemType::General,
            pinfo: PMPInfo::new(),
            alloc: A::new(),
        }
    }
    // Init PMP info and allocator.
    pub fn init(&mut self, pinfo: &PMPInfo) {
        self.pinfo = *pinfo;
        self.alloc.init(self.slice);
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
#[cfg(test)]
mod tests {
    use super::*;


}
