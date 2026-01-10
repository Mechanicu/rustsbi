use core::usize;

use super::*;
use crate::protector::TestSecMemProtector;

type UniSecMemProtector = TestSecMemProtector;

/// These PMP slots are reserved and not used to alloc enclave mem.
///
/// PMP N-1 : Default grant kernel access with all mem.
/// PMP 1   : Only used in Penglai, for temporarily grant kernel access with specific sec mem.
/// PMP 0   : Protect SM code/data.
const UNI_SECMEM_SM_SLOT: u32 = 1 << 0;
const UNI_SECMEM_TEMP_SLOT: u32 = 1 << 1;
const UNI_SECMEM_DEFAULT_SLOT: u32 = 1 << (MAX_PMP_ENTRY_COUNT - 1);
const UNI_SECMEM_PMP_ALLOCMASK: u64 = ((1 << MAX_PMP_ENTRY_COUNT) - 1)
    & !((UNI_SECMEM_SM_SLOT | UNI_SECMEM_TEMP_SLOT | UNI_SECMEM_TEMP_SLOT) as u64);
const UNI_SECMEM_PMP_MANAGEMASK: u64 = UNI_SECMEM_PMP_ALLOCMASK
    & ((UNI_SECMEM_SM_SLOT | UNI_SECMEM_DEFAULT_SLOT | UNI_SECMEM_TEMP_SLOT) as u64);

pub struct UniSecMemManager<const ORDER: usize, AR, AA>
where
    AR: SecMemAllocator<ORDER>,
    AA: SecMemAllocator<ORDER>,
{
    /// A simple incrementing ID for region
    cur_idx: usize,
    ///
    protector: UniSecMemProtector,

    /// These PMP slots are reserved and not used to alloc enclave mem.
    reserved_regions: Vec<SecMemRegion<ORDER, NoneAlloc<ORDER>, NoneAlloc<ORDER>>>,
    /// These region are used to manage allocable secure mem.
    ///
    /// Use PMP 2~(N-2)
    alloc_regions: Vec<SecMemRegion<ORDER, AR, AA>>,
}

impl<const ORDER: usize, AR, AA> SecMemManager<ORDER, AR, AA> for UniSecMemManager<ORDER, AR, AA>
where
    AR: SecMemAllocator<ORDER>,
    AA: SecMemAllocator<ORDER>,
{
    fn new() -> Self {
        Self {
            cur_idx: 0,
            protector: UniSecMemProtector::new(UNI_SECMEM_PMP_ALLOCMASK, UNI_SECMEM_PMP_MANAGEMASK),
            reserved_regions:
                Vec::<SecMemRegion<ORDER, NoneAlloc<ORDER>, NoneAlloc<ORDER>>>::with_capacity(
                    1usize,
                ),
            alloc_regions: Vec::<SecMemRegion<ORDER, AR, AA>>::with_capacity(
                (MAX_PMP_ENTRY_COUNT - 3) as usize,
            ),
        }
    }
    fn init(&mut self, sm_addr: usize, sm_len: usize) -> bool {
        // Reset temporary and default PMP slot
        if !self.protector.disable(UNI_SECMEM_TEMP_SLOT)
            || !self
                .protector
                .grant_access_all(0, usize::MAX, UNI_SECMEM_DEFAULT_SLOT)
        {
            error!("[SMM] Reset Temporary/Default PMP slot failed");
            return false;
        }

        // Init and protect SM region
        if self.protector.is_protectable(sm_addr, sm_len)
            && self
                .protector
                .retrive_access_all(sm_addr, sm_len, UNI_SECMEM_SM_SLOT)
        {
            self.reserved_regions.push(
                SecMemRegion::<ORDER, NoneAlloc<ORDER>, NoneAlloc<ORDER>>::new(
                    sm_addr,
                    sm_len,
                    self.cur_idx,
                    UNI_SECMEM_SM_SLOT,
                ),
            );
        } else {
            error!("[SMM] Cannot protect SM region due to memory check or protect fail");
            return false;
        }
        self.cur_idx += 1;
        true
    }

    fn deinit(mut self, cur_regions: &mut [(usize, usize); MAX_PMP_ENTRY_COUNT as usize]) -> u32 {
        let mut count = 0;
        for region in self.alloc_regions.drain(..) {
            // Though SMM assume all enclaves should exited successfully before deinit, which means
            // there isn't any protected data in secure memory. But TEE driver may also be attacked,
            // so SMM still clean all data in secure memory when deinit to avoid any protected data leap.
            unsafe {
                core::ptr::write_bytes(region.addr as *mut u8, 0, region.len);
                sfence_vma_all();
            }
            // Disable hardware used to protect region.
            cur_regions[count] = (region.addr, region.len);
            count += 1;
            if !self.protector.disable(region.slot) {
                error!(
                    "[SMM] Deinit Region-{} with slot-{} fail",
                    region.id, region.slot
                );
            }
        }
        count as u32
    }

    fn extend(&mut self, addr: usize, len: usize) -> bool {
        // Check if new memory area can be protect by hardware
        if !self.protector.is_protectable(addr, len)
            || (self.alloc_regions.len() >= self.alloc_regions.capacity())
            // New region's mem area shouldn't overlap with any exist region
            || self
                .alloc_regions
                .iter()
                .any(|r| r.is_mem_overlap(addr, len))
        {
            return false;
        }

        // Try alloc a hardware to protect new region
        if let Some(hwid) = self.protector.alloc() {
            if !self.protector.retrive_access_all(addr, len, hwid) {
                self.protector.free(hwid);
                return false;
            }
            self.cur_idx += 1;
            self.alloc_regions.push(SecMemRegion::<ORDER, AR, AA>::new(
                addr,
                len,
                self.cur_idx,
                hwid,
            ));
        }
        true
    }

    fn reclaim(&mut self) -> Option<(usize, usize)> {
        let index = self
            .alloc_regions
            .iter()
            .position(|region| region.is_used == false)?;
        let region = self.alloc_regions.swap_remove(index);
        // Sanitization is done when free enclave memory. And in-use region won't be reclaim, so
        // no need clean secure memory.
        // unprotect region and try free PMP slot
        if self.protector.disable(region.slot) && self.protector.free(region.slot) {
            return Some((region.addr, region.len));
        }
        None
    }

    fn alloc_em(&mut self, len: usize, em_type: SecMemType) -> Option<(usize, usize, usize)> {
        // Init alloc layout, size must be power of 2
        let expect_len = len.next_power_of_two();
        let alloc_layout = Layout::from_size_align(expect_len, expect_len).ok()?;

        for region in self.alloc_regions.iter_mut() {
            if region.len < len {
                continue;
            }

            // If region is General, then change it to request type
            // BEWARE that alloc should success in most of time, so change of type won't reverse even when alloc failed,
            // if region reach limits, it depends on TEE driver to reclaim unused regions manully.
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

    fn free_em(&mut self, addr: usize, len: usize) -> Option<usize> {
        let expect_len = len.next_power_of_two();
        let free_layout = Layout::from_size_align(expect_len, expect_len).ok()?;
        let free_ptr = NonNull::new(addr as *mut u8)?;

        if let Some(free_region) = self
            .alloc_regions
            .iter_mut()
            .find(|region| region.is_mem_contained(addr, len))
        {
            // Clean enclave memory to avoid data leap between enclaves and when host request reclaim
            unsafe {
                core::ptr::write_bytes(addr as *mut u8, 0, len);
                sfence_vma_all();
            }
            return match &mut free_region.allocator {
                SecMemAllocatorWrapper::Application(alloc) => {
                    alloc.free(free_ptr, free_layout);
                    // if all memory of region is free, reset region status.
                    if alloc.available() == alloc.total() {
                        free_region.is_used = false;
                        free_region.allocator = SecMemAllocatorWrapper::General;
                    }
                    Some(free_region.id)
                }
                SecMemAllocatorWrapper::Runtime(alloc) => {
                    alloc.free(free_ptr, free_layout);
                    // if all memory of region is free, reset region status.
                    if alloc.available() == alloc.total() {
                        free_region.is_used = false;
                        free_region.allocator = SecMemAllocatorWrapper::General;
                    }
                    Some(free_region.id)
                }
                _ => None,
            };
        }
        None
    }

    /// Grant enclave access to certain region on current hart
    fn grant_access(&self, addr: usize, len: usize, region_id: usize) -> bool {
        // find region match enclave memory and region id, grant access to region on current hart
        if let Some(enclave_region) = self
            .alloc_regions
            .iter()
            .find(|region| region.id == region_id && region.is_mem_contained(addr, len))
        {
            return self.protector.grant_access(
                enclave_region.addr,
                enclave_region.len,
                enclave_region.slot,
            );
        }
        false
    }
    /// Retrive enclave access to certain region on current hart
    fn retrive_access(&self, addr: usize, len: usize, region_id: usize) -> bool {
        if let Some(enclave_region) = self
            .alloc_regions
            .iter()
            .find(|region| region.id == region_id && region.is_mem_contained(addr, len))
        {
            return self.protector.retrive_access(
                enclave_region.addr,
                enclave_region.len,
                enclave_region.slot,
            );
        }
        false
    }
}
