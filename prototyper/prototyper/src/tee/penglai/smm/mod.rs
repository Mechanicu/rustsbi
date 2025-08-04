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
use super::PenglaiPmpIdx;
use super::{PENGLAI_PMP_BITMAP, PENGLAI_PMP_COUNT, PENGLAI_RESERVED_MASK};
use crate::cfg::PAGE_SIZE;
use crate::firmware::{SBI_END_ADDRESS, SBI_START_ADDRESS};
use crate::tee::pmpm::{tee_get_pmp, tee_pmp_clean_sync, tee_pmp_sync};
use buddy_system_allocator::LockedHeap;
use core::alloc::Layout;
use core::mem::MaybeUninit;
use core::ptr::NonNull;
use riscv::register::{Permission, Range};
use rustsbi::SbiRet;
use spin::Mutex;

pub const SECMEM_MAX_ORDER: usize = 20;
pub const MAX_REGION_COUNT: u8 = PENGLAI_PMP_COUNT;
pub const PENGLAI_SMEM_ALIGN: usize = PAGE_SIZE;

mod buddy;

pub struct SecmemRegion {
    pub start: usize,
    pub len: usize,
    pub allocator: LockedHeap<SECMEM_MAX_ORDER>,
}

pub struct SecPMPRegion {
    pub hperm: Permission,
    pub hmode: Range,
    pub eperm: Permission,
    pub emode: Range,
    pub is_valid: bool,
    pub mem_region: SecmemRegion,
    pub slot: u8,
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

/// Penglai secure region.
///
/// A PMP slot (slot here means PMP with index N on every hart) will and only protect
/// one memory region managed by a allocator (allocator can only use buddy algorithm for now).
struct SecRegion {
    region: [SecPMPRegion; (MAX_REGION_COUNT) as usize],
}

impl SecRegion {
    pub const fn new() -> Self {
        Self {
            region: {
                // 初始化逻辑
                let mut init_arr =
                    MaybeUninit::<[SecPMPRegion; MAX_REGION_COUNT as usize]>::uninit();
                let ptr = init_arr.as_mut_ptr();
                let mut i = 0;
                while i < MAX_REGION_COUNT as usize {
                    unsafe {
                        let region_ptr = ptr.cast::<SecPMPRegion>().add(i);
                        region_ptr.write(SecPMPRegion::new());
                        i += 1;
                    }
                }
                unsafe { init_arr.assume_init() }
            },
        }
    }
    pub fn region(&self) -> &[SecPMPRegion; (MAX_REGION_COUNT) as usize] {
        &self.region
    }
    pub fn region_mut(&mut self) -> &mut [SecPMPRegion; (MAX_REGION_COUNT) as usize] {
        &mut self.region
    }
}

static SEC_REGIONS: Mutex<SecRegion> = Mutex::new(SecRegion::new());

/// Check if new secure memory region is PENGLAI_SMEM_ALIGN align and not wrap around.
pub fn check_mem_align(addr: usize, len: usize, align: usize) -> bool {
    if addr & (align - 1) != 0 || len < align || len & (align - 1) != 0 || addr + len < addr {
        return false;
    }
    true
}

/// Check if enclave memory overlap with exsisting region.
pub fn check_mem_overlap(
    regions: &[SecPMPRegion; PENGLAI_PMP_COUNT as usize],
    addr: usize,
    len: usize,
) -> Option<usize> {
    for (idx, region) in regions.iter().enumerate() {
        if region.is_valid == true && region.mem_region.is_mem_overlap(addr, addr + len) == true {
            // New region overlap with exsisting region.
            return Some(idx);
        }
    }
    // New region not overlap with exsisting region and can be used.
    None
}

/// Check if any exsisting region contains current enclave memory .
pub fn check_mem_contained(
    regions: &[SecPMPRegion; PENGLAI_PMP_COUNT as usize],
    addr: usize,
    len: usize,
) -> Option<usize> {
    for (idx, region) in regions.iter().enumerate() {
        if region.is_valid == true && region.mem_region.is_mem_contained(addr, addr + len) == true {
            // New region overlap with exsisting region.
            return Some(idx);
        }
    }
    None
}

/// Get index of first unused region.
pub fn get_unused_region(
    regions: &mut [SecPMPRegion; PENGLAI_PMP_COUNT as usize],
) -> Option<&mut SecPMPRegion> {
    for region in regions.iter_mut() {
        if region.is_valid == false {
            return Some(region);
        }
    }
    return None;
}

#[inline]
fn set_pmp_host_sync(region: &SecPMPRegion) -> SbiRet {
    tee_pmp_sync(
        region.slot,
        region.mem_region.start,
        region.mem_region.len,
        region.hmode,
        region.hperm,
    )
}

#[inline]
fn set_pmp_sync_enclave(region: &SecPMPRegion) -> SbiRet {
    tee_pmp_sync(
        region.slot,
        region.mem_region.start,
        region.mem_region.len,
        region.emode,
        region.eperm,
    )
}

/// Check if memory is protected by SMM.
#[inline]
pub fn is_data_protected(addr: usize, len: usize) -> Option<usize> {
    let guard = SEC_REGIONS.lock();
    let regions = guard.region();
    check_mem_overlap(regions, addr, len)
}

#[inline]
/// Use @PmpTemp PMP slot to grant kernel with temporary access to enclave memory.
pub fn grant_kernel_access(addr: usize, len: usize) -> SbiRet {
    let mut guard = SEC_REGIONS.lock();
    let temp_region = &mut guard.region_mut()[PenglaiPmpIdx::PmpTemp as usize];
    temp_region.mem_region.start = addr;
    temp_region.mem_region.len = len;
    set_pmp_host_sync(&temp_region)
}

#[inline]
/// The reverse operation of @grant_kernel_access
pub fn retrive_kernel_access(addr: usize, len: usize) -> SbiRet {
    let ((cur_addr, cur_len), pmp_config) = tee_get_pmp(PenglaiPmpIdx::PmpTemp as u8);
    // The memory must be enclave memory.
    if (pmp_config.range == Range::NAPOT) && (cur_addr == addr) && (cur_len == len) {
        return tee_pmp_clean_sync(PenglaiPmpIdx::PmpTemp as u8);
    }
    SbiRet::invalid_address()
}

/// Penglai secure region and PMP slot init.
pub fn secmem_init(addr: usize, len: usize) -> SbiRet {
    // Get lock from here.
    info!("Secmem init start");
    let mut guard = SEC_REGIONS.lock();
    let regions = guard.region_mut();

    // Init secure monitor region (only for memory overlap check, not used for
    // secure memory alloc), usually this will take at least one PMP slot to fully protect
    // whole Rust prototyper.
    let sm_region = &mut regions[PenglaiPmpIdx::PmpSM as usize];
    sm_region.is_valid = true;
    unsafe {
        sm_region.mem_region.start = SBI_START_ADDRESS;
        sm_region.mem_region.len = SBI_END_ADDRESS - SBI_START_ADDRESS;
        sm_region.emode = Range::NAPOT;
        sm_region.hmode = Range::NAPOT;
    }
    // Set PMP slot for SM region.
    if set_pmp_host_sync(&sm_region) == SbiRet::invalid_param() {
        return SbiRet::failed();
    }
    info!("Secmem init, SM region init success");

    // Init default region, used for granting host with full memory access
    // when memory not protected by PMP.
    let default_region = &mut regions[PenglaiPmpIdx::PmpDefault as usize];
    // To avoid memory overlap check, default region set as unused.
    default_region.is_valid = false;
    default_region.mem_region.start = 0;
    default_region.mem_region.len = usize::MAX;
    default_region.emode = Range::NAPOT;
    default_region.hmode = Range::NAPOT;
    default_region.hperm = Permission::RWX;
    // Set PMP slot for default region.
    if set_pmp_host_sync(default_region) == SbiRet::invalid_param() {
        return SbiRet::failed();
    }
    info!("Secmem init, Default region init success");

    // Init temporary region, used for temporarily granting host with access of secure memory.
    let temp_region = &mut regions[PenglaiPmpIdx::PmpTemp as usize];
    temp_region.is_valid = true;
    temp_region.hmode = Range::NAPOT;
    temp_region.hperm = Permission::RWX;
    info!("Secmem init, Temporary region init success");

    drop(guard);
    // Reserved regions init successfully, init first region for enclave.
    secmem_extend(addr, len)
}

/// Penglai extend secure memory.
///
/// This function accept a physical memory area and use memory to init new secure region.
pub fn secmem_extend(addr: usize, len: usize) -> SbiRet {
    info!("Extend secmem, check align,{} {}", addr, len);
    // Addr and size should align to PENGLAI_SMEM_ALIGN.
    if false == check_mem_align(addr, len, PENGLAI_SMEM_ALIGN) {
        return SbiRet::invalid_param();
    }
    let mut guard = SEC_REGIONS.lock();
    let regions = guard.region_mut();

    // New region must not overlap with exsisting regions.
    if check_mem_overlap(regions, addr, len) == None {
        return SbiRet::invalid_param();
    }
    // Alloc a free PMP slot for new region.
    let new_slot = match PENGLAI_PMP_BITMAP.alloc() {
        Some(slot) => slot,
        None => {
            error!("Extend secmem, alloc PMP slot failed!");
            return SbiRet::failed();
        }
    };
    info!("Extend secmem, new slot {}", new_slot);
    // Init secure memory region that used for secure memory alloc.
    let new_region = match get_unused_region(regions) {
        Some(region) => {
            region.slot = new_slot;
            region.is_valid = true;
            region.hperm = Permission::NONE;
            region.hmode = Range::NAPOT;
            region.eperm = Permission::RWX;
            region.emode = Range::NAPOT;
            region.mem_region.len = len;
            region.mem_region.start = addr;
            region.mem_region.init(addr, len);
            region
        }
        None => {
            error!("Extend secmem, alloc region failed!");
            PENGLAI_PMP_BITMAP.free(new_slot, !PENGLAI_RESERVED_MASK);
            return SbiRet::failed();
        }
    };
    info!(
        "Extend secmem, new region {} {} {}, align:{}",
        new_region.slot, new_region.mem_region.start, new_region.mem_region.len, PENGLAI_SMEM_ALIGN
    );

    // Set PMP slot to protected new secure region.
    set_pmp_host_sync(new_region)
}

pub fn secmem_reclaim() -> SbiRet {
    SbiRet::success(0)
}

/// Penglai alloc enclave memory from secure region.
pub fn secmem_alloc(reqsize: usize) -> Option<(usize, usize)> {
    let guard = SEC_REGIONS.lock();
    let regions = guard.region();
    let emem_layout: Layout = Layout::from_size_align(reqsize, PENGLAI_SMEM_ALIGN).unwrap();
    // Check every secure region (except reserved regions) and try to alloc needed enclave mem.
    for (idx, region) in regions.iter().enumerate() {
        if (PENGLAI_RESERVED_MASK & (1 << idx) == 0) && region.is_valid == true {
            if let Ok(ptr) = region.mem_region.alloc(emem_layout) {
                let uptr = ptr.as_ptr() as usize;
                info!(
                    "Alloc enclave mem success,{} {} {} {}",
                    idx,
                    uptr,
                    emem_layout.size(),
                    emem_layout.align()
                );
                return Some((uptr, emem_layout.size()));
            }
        }
    }
    None
}

/// Penglai free enclave memory back to secure region.
///
/// This function may not exposed to user, it's hard to make sure U/S mode
/// allocate and free enclave memory in same secure region.
pub fn secmem_free(addr: usize, len: usize) -> SbiRet {
    // Addr and size should align to PENGLAI_SMEM_ALIGN.
    if false == check_mem_align(addr, len, PENGLAI_SMEM_ALIGN) {
        return SbiRet::invalid_param();
    }
    let guard = SEC_REGIONS.lock();
    let regions = guard.region();

    let emem_layout: Layout = Layout::from_size_align(len, PENGLAI_SMEM_ALIGN).unwrap();
    // Check if any region (except reserved regions) contains enclave mem and try to free mem.
    if let Some(idx) = check_mem_contained(regions, addr, len)
        && (PENGLAI_RESERVED_MASK & (1 << idx) == 0)
    {
        regions[idx].mem_region.dealloc(
            unsafe { NonNull::new_unchecked(addr as *mut u8) },
            emem_layout,
        );
        info!("Free enclave memory success,{} {} {}", idx, addr, len);
        return SbiRet::success(0);
    }
    SbiRet::invalid_param()
}
