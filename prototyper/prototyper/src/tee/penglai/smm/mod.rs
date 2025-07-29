//! Secure memory management of Penglai PMP extension in RustSBI.
//!
//! Penglai PMP use PMP slots in accordance with the following regulations:
//!
//! 1. PMP slot 0: reserved for temporarily granting the kernel access premissions of  
//! specified secure memory region.
//!
//! 2. PMP slot 1: used for protect secure monitor (usually whole firmware, here is prototyper)
//!
//! 3. PMP 2~(N-2): each PMP slot is used to protect a physical continous secure memory region.
//! Each secure memory region shouldn't overlap with each other.
//!
//! 4. PMP slot N-1 (last PMP slot): used fot grant the kernel access permissions of memory not
//! protected by secure monitor.

use super::host::SMMRet;
use crate::cfg::PAGE_SIZE;
use crate::firmware::{SBI_END_ADDRESS, SBI_START_ADDRESS};
use buddy_system_allocator::LockedHeap;
use core::mem::MaybeUninit;
use pmp::*;
use riscv::register::{Permission, Range};
use smm_helper::*;
use spin::Mutex;

pub const SECMEM_MAX_ORDER: usize = 20;

mod buddy;
mod pmp;
mod smm_helper;

#[repr(i16)]
pub enum SecRegionIdx {
    SecRegionInvalid = -1,
    SecRegionSM = 0,
    SecRegionDefault = PENGLAI_PMP_END,
}

pub struct SecmemRegion {
    pub start: usize,
    pub len: usize,
    pub allocator: LockedHeap<SECMEM_MAX_ORDER>,
}

pub struct SecPMPRegion {
    pub slot: usize,
    pub hperm: Permission,
    pub hmode: Range,
    pub eperm: Permission,
    pub emode: Range,
    pub is_valid: bool,
    pub mem_region: SecmemRegion,
}

impl SecPMPRegion {
    pub const fn new() -> Self {
        Self {
            slot: 0,
            hperm: Permission::NONE,
            hmode: Range::OFF,
            eperm: Permission::NONE,
            emode: Range::OFF,
            is_valid: false,
            mem_region: SecmemRegion::new(0, 0),
        }
    }
}

struct SecRegion {
    region: [SecPMPRegion; (PENGLAI_PMP_COUNT) as usize],
    size: u32,
}

impl SecRegion {
    pub const fn new() -> Self {
        Self {
            region: {
                // 初始化逻辑
                let mut init_arr: [SecPMPRegion; PENGLAI_PMP_COUNT as usize] =
                    unsafe { MaybeUninit::uninit().assume_init() };
                let ptr = init_arr.as_mut_ptr();
                unsafe {
                    let mut i = 0;
                    while i < PENGLAI_PMP_COUNT as usize {
                        ptr.add(i).write(SecPMPRegion::new());
                        i += 1;
                    }
                }
                init_arr
            },
            size: (0),
        }
    }
    pub fn region(&self) -> &[SecPMPRegion; (PENGLAI_PMP_COUNT) as usize] {
        &self.region
    }
    pub fn region_mut(&mut self) -> &mut [SecPMPRegion; (PENGLAI_PMP_COUNT) as usize] {
        &mut self.region
    }
}

static SEC_REGIONS: Mutex<SecRegion> = Mutex::new(SecRegion::new());

/// PMP and secure memory bind array.
///
/// A PMP slot (slot here means PMP with index N on every hart) will and only bind with
/// on memory region with a allocator (allocator can only use buddy algorithm for now).
pub fn secmem_init(start: usize, len: usize) -> SMMRet {
    // Init every secure PMP region metadata

    // Secure memory region must be aligned to PAGE_SIZE.
    if false == check_mem_align(start, len, PAGE_SIZE) {
        return SMMRet::Error;
    }

    // Get lock from here.
    let mut guard = SEC_REGIONS.lock();
    let regions = guard.region_mut();

    // New region must not overlap with exsisting regions.
    if true == check_mem_overlap(regions, start, len) {
        return SMMRet::Error;
    }

    // Init secure monitor PMP regions (only for memory overlap check, not used for
    // secure memory alloc), usually this will take at least one PMP slot to fully protect
    // whole Rust prototyper.
    let sm_region = &mut regions[PmpIdx::PmpSM as usize];
    sm_region.is_valid = true;
    unsafe {
        sm_region.mem_region.start = SBI_START_ADDRESS;
        sm_region.mem_region.len = SBI_END_ADDRESS - SBI_START_ADDRESS;
    }

    // Init first secure memory PMP regions. This memory region will protected by PMP slot
    // indexd by @pmp_idx and used for secure memory alloc.
    if let Some(unused_region) = get_unused_region(regions) {
        unused_region.is_valid = true;
        unused_region.hperm = Permission::NONE;
        unused_region.hmode = Range::NAPOT;
        unused_region.eperm = Permission::RWX;
        unused_region.emode = Range::NAPOT;
        unused_region.mem_region.len = len;
        unused_region.mem_region.start = start;
        unused_region.mem_region.init(start, len);
    } else {
        // Cannot find any unused secure region.
        return SMMRet::Error;
    }

    SMMRet::Success
}
pub fn secmem_extend() -> SMMRet {
    SMMRet::Success
}

pub fn secmem_reclaim() -> SMMRet {
    SMMRet::Success
}

pub fn secmem_alloc() -> SMMRet {
    SMMRet::Success
}

pub fn secmem_free() -> SMMRet {
    SMMRet::Success
}
