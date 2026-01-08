use super::SecMemProtector;
use core::usize;
use pmpm::{PmpConfig, bitmap::PMPSlotAllocator, set_pmp_entry};
use riscv::register::{Permission, Range};

pub struct TestSecMemProtector {
    hw_manager: PMPSlotAllocator,
}

impl TestSecMemProtector {
    fn new(alloc_mask: u64, manage_mask: u64) -> Self {
        Self {
            hw_manager: (PMPSlotAllocator::new(alloc_mask, manage_mask)),
        }
    }
}

impl SecMemProtector for TestSecMemProtector {
    fn alloc(&mut self) -> Option<u32> {
        match self.hw_manager.alloc() {
            Ok(slot) => Some(slot),
            Err(_) => None,
        }
    }
    fn free(&mut self, hwid: u32) -> bool {
        match self.hw_manager.free(hwid) {
            Ok(_) => true,
            Err(_) => false,
        }
    }
    fn disable(&self, hwid: u32) -> bool {
        true
    }
    fn enable(&self, hwid: u32) -> bool {
        true
    }
    fn grant_access(&self, addr: usize, len: usize, hwid: u32) -> bool {
        true
    }
    fn grant_access_all(&self, addr: usize, len: usize, hwid: u32) -> bool {
        true
    }
    fn retrive_access(&self, addr: usize, len: usize, hwid: u32) -> bool {
        true
    }
    fn retrive_access_all(&self, addr: usize, len: usize, hwid: u32) -> bool {
        true
    }
}

pub type SecMemProtectorByPMP = PMPSlotAllocator;

impl SecMemProtector for SecMemProtectorByPMP {
    fn alloc(&mut self) -> Option<u32> {
        match self.alloc() {
            Ok(slot) => Some(slot),
            Err(_) => None,
        }
    }
    fn free(&mut self, hwid: u32) -> bool {
        match self.free(hwid) {
            Ok(_) => true,
            Err(_) => false,
        }
    }
    fn disable(&self, hwid: u32) -> bool {
        self.is_managed(hwid)
            && set_pmp_entry(
                hwid,
                0,
                0,
                &PmpConfig::new(Range::OFF, Permission::NONE, false),
            )
    }
    fn enable(&self, hwid: u32) -> bool {
        self.is_managed(hwid)
            && set_pmp_entry(
                hwid,
                0,
                0,
                &PmpConfig::new(Range::NAPOT, Permission::RWX, false),
            )
    }
    fn grant_access(&self, addr: usize, len: usize, hwid: u32) -> bool {
        self.is_managed(hwid)
            && set_pmp_entry(
                hwid,
                addr,
                len,
                &PmpConfig::new(Range::NAPOT, Permission::RWX, false),
            )
    }
    fn retrive_access(&self, addr: usize, len: usize, hwid: u32) -> bool {
        self.is_managed(hwid)
            && set_pmp_entry(
                hwid,
                addr,
                len,
                &PmpConfig::new(Range::NAPOT, Permission::NONE, false),
            )
    }
    // TODO: Must impl by IPIs
    fn grant_access_all(&self, addr: usize, len: usize, hwid: u32) -> bool {
        true
    }
    fn retrive_access_all(&self, addr: usize, len: usize, hwid: u32) -> bool {
        true
    }
}
