//! PMP management module of Penglai PMP.
//!
//! For now, the one using PMP most usually be secure monitor (SM) of TEE,
//! But in different SM, the way to manage PMP is different, so for now we
//! manage all PMP under Penglai PMP secure monitor when enable Penglai PMP
//! in current Rust Prototyper.
use core::sync::atomic::AtomicUsize;
use riscv::register::{
    Permission, Range, pmpaddr0, pmpaddr1, pmpaddr2, pmpaddr3, pmpaddr4, pmpaddr5, pmpaddr6,
    pmpaddr7, pmpaddr8, pmpaddr9, pmpaddr10, pmpaddr11, pmpaddr12, pmpaddr13, pmpaddr14, pmpaddr15,
    pmpcfg0, pmpcfg2,
};

pub mod bitmap;
pub mod pmpsync;

pub const PMP_COUNT: u8 = 16;

pub struct PmpConfig {
    pmp_addr: usize,
    pmp_mode: Range,
    pmp_perm: Permission,
    pmp_idx: u8,
}

impl Copy for PmpConfig {}
impl Clone for PmpConfig {
    fn clone(&self) -> Self {
        Self {
            pmp_addr: (self.pmp_addr),
            pmp_mode: (self.pmp_mode),
            pmp_perm: (self.pmp_perm),
            pmp_idx: (self.pmp_idx),
        }
    }
}

pub struct PmpBitmap {
    map: AtomicUsize,
    start: u8,
    end: u8,
}

fn config_addr(addr: usize, len: usize, mode: Range) -> usize {
    match mode {
        Range::NAPOT => {
            return if addr == 0 && len == usize::MAX {
                usize::MAX
            } else {
                (addr | (len >> 1) - 1) >> 2
            };
        }
        Range::NA4 => return addr >> 2,
        Range::TOR => return addr,
        // Default set as OFF
        _ => return 0,
    }
}

#[inline]
/// Set PMP entry @idx on current hart.
pub fn set_pmp(idx: u8, addr: usize, len: usize, mode: Range, perm: Permission) {
    set_pmp_reg(idx, config_addr(addr, len, mode), mode, perm);
}

#[inline]
/// Clean PMP entry @idx on current hart.
pub fn clear_pmp(idx: u8) {
    set_pmp_reg(idx, 0, Range::OFF, Permission::NONE);
}

pub fn dump_pmps() {}

fn set_pmp_reg(idx: u8, addr: usize, range: Range, perm: Permission) {
    unsafe {
        match idx {
            0 => {
                pmpaddr0::write(addr);
                pmpcfg0::set_pmp(0, range, perm, false); // cfg0, 位0
            }
            1 => {
                pmpaddr1::write(addr);
                pmpcfg0::set_pmp(1, range, perm, false); // cfg0, 位1
            }
            2 => {
                pmpaddr2::write(addr);
                pmpcfg0::set_pmp(2, range, perm, false); // cfg0, 位2
            }
            3 => {
                pmpaddr3::write(addr);
                pmpcfg0::set_pmp(3, range, perm, false); // cfg0, 位3
            }
            4 => {
                pmpaddr4::write(addr);
                pmpcfg0::set_pmp(4, range, perm, false); // cfg0, 位4
            }
            5 => {
                pmpaddr5::write(addr);
                pmpcfg0::set_pmp(5, range, perm, false); // cfg0, 位5
            }
            6 => {
                pmpaddr6::write(addr);
                pmpcfg0::set_pmp(6, range, perm, false); // cfg0, 位6
            }
            7 => {
                pmpaddr7::write(addr);
                pmpcfg0::set_pmp(7, range, perm, false); // cfg0, 位7
            }
            8 => {
                pmpaddr8::write(addr);
                pmpcfg2::set_pmp(0, range, perm, false); // cfg2, 位0
            }
            9 => {
                pmpaddr9::write(addr);
                pmpcfg2::set_pmp(1, range, perm, false); // cfg2, 位1
            }
            10 => {
                pmpaddr10::write(addr);
                pmpcfg2::set_pmp(2, range, perm, false); // cfg2, 位2
            }
            11 => {
                pmpaddr11::write(addr);
                pmpcfg2::set_pmp(3, range, perm, false); // cfg2, 位3
            }
            12 => {
                pmpaddr12::write(addr);
                pmpcfg2::set_pmp(4, range, perm, false); // cfg2, 位4
            }
            13 => {
                pmpaddr13::write(addr);
                pmpcfg2::set_pmp(5, range, perm, false); // cfg2, 位5
            }
            14 => {
                pmpaddr14::write(addr);
                pmpcfg2::set_pmp(6, range, perm, false); // cfg2, 位6
            }
            _ => {
                pmpaddr15::write(addr);
                pmpcfg2::set_pmp(7, range, perm, false); // cfg2, 位7
            }
        }
    }
}
