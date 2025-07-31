//! PMP management module of Penglai PMP.
//!
//! For now, the one using PMP most usually be secure monitor (SM) of TEE,
//! But in different SM, the way to manage PMP is different, so for now we
//! manage all PMP under Penglai PMP secure monitor when enable Penglai PMP
//! in current Rust Prototyper.
use crate::platform::PLATFORM;
use core::sync::atomic::AtomicUsize;
use riscv::register::{
    Permission, Pmp, Range, pmpaddr0, pmpaddr1, pmpaddr2, pmpaddr3, pmpaddr4, pmpaddr5, pmpaddr6,
    pmpaddr7, pmpaddr8, pmpaddr9, pmpaddr10, pmpaddr11, pmpaddr12, pmpaddr13, pmpaddr14, pmpaddr15,
    pmpcfg0, pmpcfg2,
};
use rustsbi::SbiRet;

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

fn encode_pmp_addr(addr: usize, len: usize, mode: Range) -> usize {
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

fn decode_pmp_addr(pmp_addr: usize, mode: Range) -> (usize, usize) {
    let mut addr = pmp_addr;
    match mode {
        Range::NAPOT => {
            let order = addr.trailing_ones();
            addr &= !((1 << (order + 1)) - 1);
            (addr >> 1, 1 << (order + 3))
        }
        Range::NA4 => (pmp_addr, 4),
        Range::TOR => (pmp_addr, 0),
        _ => (0, 0),
    }
}

#[inline]
/// Set PMP entry @idx on every hart.
pub fn tee_pmp_sync(idx: u8, addr: usize, len: usize, mode: Range, perm: Permission) -> SbiRet {
    // Set other harts first.
    let pmp_addr = encode_pmp_addr(addr, len, mode);
    let sbi_ret = unsafe { PLATFORM.sbi.ipi.as_ref() }
        .unwrap()
        .send_ipi_by_pmp(PmpConfig {
            pmp_addr: (pmp_addr),
            pmp_mode: (mode),
            pmp_perm: (perm),
            pmp_idx: (idx),
        });
    // If configure other harts successfully, then configure local PMP.
    set_pmp_reg(idx, pmp_addr, mode, perm);
    sbi_ret
}

#[inline]
/// Clean PMP entry @idx on every hart.
pub fn tee_pmp_clean_sync(idx: u8) -> SbiRet {
    // Set other harts first.
    tee_pmp_sync(idx, 0, 0, Range::OFF, Permission::NONE)
}

#[inline]
pub fn tee_get_pmp(idx: u8) -> ((usize, usize), Pmp) {
    let (pmp_addr, pmp_config) = get_pmp_reg(idx);
    (decode_pmp_addr(pmp_addr, pmp_config.range), pmp_config)
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

fn get_pmp_reg(idx: u8) -> (usize, Pmp) {
    match idx {
        0 => (pmpaddr0::read(), pmpcfg0::read().into_config(0)),
        1 => (pmpaddr1::read(), pmpcfg0::read().into_config(1)),
        2 => (pmpaddr2::read(), pmpcfg0::read().into_config(2)),
        3 => (pmpaddr3::read(), pmpcfg0::read().into_config(3)),
        4 => (pmpaddr4::read(), pmpcfg0::read().into_config(4)),
        5 => (pmpaddr5::read(), pmpcfg0::read().into_config(5)),
        6 => (pmpaddr6::read(), pmpcfg0::read().into_config(6)),
        7 => (pmpaddr7::read(), pmpcfg0::read().into_config(7)),
        8 => (pmpaddr8::read(), pmpcfg2::read().into_config(0)),
        9 => (pmpaddr9::read(), pmpcfg2::read().into_config(1)),
        10 => (pmpaddr10::read(), pmpcfg2::read().into_config(2)),
        11 => (pmpaddr11::read(), pmpcfg2::read().into_config(3)),
        12 => (pmpaddr12::read(), pmpcfg2::read().into_config(4)),
        13 => (pmpaddr13::read(), pmpcfg2::read().into_config(5)),
        14 => (pmpaddr14::read(), pmpcfg2::read().into_config(6)),
        _ => (pmpaddr15::read(), pmpcfg2::read().into_config(7)),
    }
}
