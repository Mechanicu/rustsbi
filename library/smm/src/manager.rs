use super::*;

/// Temporary grant untrusted components access to secure memory area
pub fn grant_host_access(addr: usize, len: usize) -> bool {
    true
}
/// Retrive untrusted components access to secure memory area
pub fn retrive_host_access(addr: usize, len: usize) -> bool {
    true
}
/// Protect memory area by PMP slot
pub fn protect_area(addr: usize, len: usize, slot: u32) -> bool {
    true
}
/// Unprotect memory area by PMP slot
pub fn unprotect_area(addr: usize, len: usize, slot: u32) -> Option<(usize, usize)> {
    Some((0, 0))
}
const MULTI_SECMEM_SM_SLOT: u32 = 0;
const MULTI_SECMEM_TEMP_SLOT: u32 = 1;
const MULTI_SECMEM_DEFAULT_SLOT: u32 = MAX_PMP_ENTRY_COUNT - 1;
const MULTI_SECMEM_PMPMASK: u64 = ((1 << MAX_PMP_ENTRY_COUNT) - 1)
    & !((MULTI_SECMEM_SM_SLOT | MULTI_SECMEM_TEMP_SLOT | MULTI_SECMEM_TEMP_SLOT) as u64);
pub struct MultiSecMemManager<const ORDER: usize, AR, AA>
where
    AR: SecMemAllocator<ORDER>,
    AA: SecMemAllocator<ORDER>,
{
    /// A simple incrementing ID for region
    cur_idx: usize,
    ///
    pmp_allocator: PMPSlotAllocator,
    /// These region are reserved and not used to alloc enclave mem.
    ///
    /// PMP N-1 : Default grant kernel access with all mem.
    /// PMP 1   : Only used in Penglai, for temporarily grant kernel access with specific sec mem.
    /// PMP 0   : Protect SM code/data.
    reserved_regions: Vec<SecMemRegion<ORDER, NoneAlloc<ORDER>, NoneAlloc<ORDER>>>,
    /// These region are used to manage allocable secure mem.
    ///
    /// Use PMP 2~(N-2)
    alloc_regions: Vec<SecMemRegion<ORDER, AR, AA>>,
}

impl<const ORDER: usize, AR, AA> SecMemManager<ORDER, AR, AA> for MultiSecMemManager<ORDER, AR, AA>
where
    AR: SecMemAllocator<ORDER>,
    AA: SecMemAllocator<ORDER>,
{
    fn new() -> Self {
        Self {
            cur_idx: 0,
            pmp_allocator: PMPSlotAllocator::new(MULTI_SECMEM_PMPMASK),
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
        let _ = unprotect_area(0, usize::MAX, MULTI_SECMEM_DEFAULT_SLOT);
        let _ = unprotect_area(0, 0, MULTI_SECMEM_TEMP_SLOT);

        // Init SM region and PMP slot
        if check_pmp_area_available(sm_addr, sm_len, Range::NAPOT)
        // && self.protect_mem_area(addr, len, MULTI_SECMEM_DEFAULT_SLOT)
        {
            self.reserved_regions.push(
                SecMemRegion::<ORDER, NoneAlloc<ORDER>, NoneAlloc<ORDER>>::new(
                    sm_addr,
                    sm_len,
                    self.cur_idx,
                    MULTI_SECMEM_SM_SLOT,
                ),
            );
        } else {
            error!("[SMM] Cannot protect SM due to memory check fail");
            return false;
        }
        self.cur_idx += 1;
        true
    }

    fn deinit(mut self, cur_regions: &mut [(usize, usize); MAX_PMP_ENTRY_COUNT as usize]) -> u32 {
        let count = self.alloc_regions.len();
        for (idx, region) in self.alloc_regions.drain(..).enumerate() {
            unsafe {
                core::ptr::write_bytes(region.addr as *mut u8, 0, region.len);
                sfence_vma_all();
            }
            if let Some((protect_addr, protect_len)) =
                unprotect_area(0, 0, MULTI_SECMEM_TEMP_SLOT)
            {}
            cur_regions[idx] = (region.addr, region.len)
        }
        count as u32
    }

    fn extend(&mut self, addr: usize, len: usize) -> bool {
        if !check_pmp_area_available(addr, len, Range::NAPOT)
            || (self.alloc_regions.len() >= self.alloc_regions.capacity())
        {
            return false;
        }
        // New region's mem area shouldn't overlap with any exist region
        if self
            .alloc_regions
            .iter()
            .any(|r| r.is_mem_overlap(addr, len))
        {
            return false;
        }
        // Try alloc a PMP slot to protect new region
        let new_pmp_slot = match self.pmp_allocator.alloc() {
            Ok(idx) => idx,
            Err(_) => return false,
        };
        if !protect_area(addr, len, new_pmp_slot) {
            let _ = self.pmp_allocator.free(new_pmp_slot);
            return false;
        }

        self.cur_idx += 1;
        self.alloc_regions.push(SecMemRegion::<ORDER, AR, AA>::new(
            addr,
            len,
            self.cur_idx,
            new_pmp_slot,
        ));
        true
    }

    fn reclaim(&mut self) -> Option<(usize, usize)> {
        let index = self
            .alloc_regions
            .iter()
            .position(|region| region.is_used == false)?;
        let region = self.alloc_regions.swap_remove(index);
        // Sanitization is done when free enclave memory
        // unprotect region and try free PMP slot
        if let Some((protect_addr, protect_len)) =
            unprotect_area(region.addr, region.len, region.slot)
        {
            // PMP protect area should same with region mem area
            if protect_addr == region.addr && protect_len == region.len {
                let _ = self.pmp_allocator.free(region.slot);
                return Some((protect_addr, protect_len));
            }
            panic!("[SMM] Reclaimed region's mem area incompatible with PMP protect area");
        }
        None
    }

    fn alloc_em(&mut self, len: usize, em_type: SecMemType) -> Option<(usize, usize, usize)> {
        // Init alloc layout, size must be multiple of align
        let expect_len = len.next_power_of_two();
        let alloc_layout = Layout::from_size_align(expect_len, expect_len)
            .ok()?
            .pad_to_align();

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
        let expect_len = len.next_power_of_two();
        let free_layout = Layout::from_size_align(expect_len, expect_len)
            .ok()?
            .pad_to_align();
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
            // Clean enclave memory to avoid data leap between enclaves
            unsafe {
                core::ptr::write_bytes(addr as *mut u8, 0, len);
                sfence_vma_all();
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

    /// Grant enclave access to certain region
    fn grant_enclave_access(&self, region_id: usize) -> bool {
        true
    }
    /// Retrive enclave access to certain region
    fn retrive_enclave_access(&self, region_id: usize) -> bool {
        true
    }
}
