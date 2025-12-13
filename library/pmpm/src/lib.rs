//! PMP slot management.
//!
//! A PMP slot refers to the collection of PMP entries that correspond to the same index
//! across all harts, used to provide a unified memory isolation view for all harts in Penglai/Keystone.
//! The module consists of two parts: bitmap-based PMP slot management and software interrupt-based
//! PMP synchronization implementation.
#![no_std]
#[allow(unused)]
pub const MAX_PMP_ENTRY_COUNT: u32 = 64;
pub const PMP_SHIFT: u32 = 2;

use core::usize;

use riscv::register::{
    Permission, Pmp, Range, pmpaddr0, pmpaddr1, pmpaddr2, pmpaddr3, pmpaddr4, pmpaddr5, pmpaddr6,
    pmpaddr7, pmpaddr8, pmpaddr9, pmpaddr10, pmpaddr11, pmpaddr12, pmpaddr13, pmpaddr14, pmpaddr15,
    pmpcfg0, pmpcfg2,
};
pub mod bitmap;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PmpSlice {
    pa_lo: usize,
    pa_hi: usize,
    log2len: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct PmpConfig {
    range: Range,
    perm: Permission,
}

impl PmpConfig {
    pub fn new(range: Range, perm: Permission) -> Self {
        Self { range, perm }
    }
}

impl PmpSlice {
    pub fn new(log2len: u32, pa_lo: usize, pa_hi: usize) -> Self {
        PmpSlice {
            log2len,
            pa_lo,
            pa_hi,
        }
    }
    #[inline]
    pub fn log2len(&self) -> u32 {
        self.log2len
    }
    pub fn lo(&self) -> usize {
        self.pa_lo
    }
    pub fn start(&self) -> usize {
        self.pa_lo
    }
    pub fn end(&self) -> usize {
        self.pa_lo + (1 << self.log2len) - 1
    }
}

#[inline]
fn check_pmp_area_avaliable(slice: &PmpSlice) -> bool {
    let log2len = slice.log2len;
    let addr = slice.pa_lo;
    // len must be power of 2 and no less than 4, addr must be aligned to len
    if log2len < PMP_SHIFT || (addr.trailing_zeros() < log2len) {
        return false;
    }
    true
}

// TODO: Under 32-bit architecture, both length and address may overflow and need to be fixed
// Encode addr to PMP addr.
pub fn encode_pmp_addr(slice: &PmpSlice, range: Range) -> Option<usize> {
    let mut addr = slice.pa_lo;
    let log2len = slice.log2len & (usize::BITS | (usize::BITS - 1));
    match range {
        Range::NAPOT => {
            if check_pmp_area_avaliable(slice) {
                if log2len == usize::BITS {
                    Some(usize::MAX)
                } else {
                    let addrmask = (1usize << (log2len - PMP_SHIFT)) - 1;
                    addr = (addr >> PMP_SHIFT) & !addrmask;
                    Some(addr | (addrmask >> 1))
                }
            } else {
                None
            }
        }
        Range::NA4 => Some(addr >> PMP_SHIFT),
        Range::TOR => Some(addr >> PMP_SHIFT),
        Range::OFF => Some(0),
    }
}

// TODO: Under 32-bit architecture, both length and address may overflow and need to be fixed
// Decode addr from PMP addr.
pub fn decode_pmp_addr(pmpaddr: usize, range: Range) -> PmpSlice {
    let mut addr = pmpaddr;
    match range {
        Range::NAPOT => {
            if pmpaddr == usize::MAX {
                PmpSlice::new(usize::BITS, 0, 0)
            } else {
                let mut log2len = (!pmpaddr).trailing_zeros();
                addr = (addr & !((1usize << log2len) - 1)) << PMP_SHIFT;
                log2len = log2len + PMP_SHIFT + 1;
                PmpSlice::new(log2len, addr, 0)
            }
        }
        Range::NA4 => PmpSlice::new(2, pmpaddr << PMP_SHIFT, 0),
        Range::TOR => PmpSlice::new(0, pmpaddr << PMP_SHIFT, 0),
        Range::OFF => PmpSlice::new(0, 0, 0),
    }
}

#[allow(unused)]
#[inline]
/// Get PMP entry @idx on local hart.
pub fn get_pmp_entry(idx: u32) -> (PmpSlice, PmpConfig) {
    let (pmp_addr, pmp_config) = get_pmp_reg(idx);
    (
        decode_pmp_addr(pmp_addr, pmp_config.range),
        PmpConfig::new(pmp_config.range, pmp_config.permission),
    )
}

#[allow(unused)]
#[inline]
/// Set PMP entry @idx on local hart.
pub fn set_pmp_entry(idx: u32, slice: PmpSlice, config: PmpConfig) {
    if let Some(pmp_addr) = encode_pmp_addr(&slice, config.range) {
        set_pmp_reg(idx, pmp_addr, config.range, config.perm)
    }
}

fn set_pmp_reg(idx: u32, pmp_addr: usize, range: Range, perm: Permission) {
    unsafe {
        match idx {
            0 => {
                pmpaddr0::write(pmp_addr);
                pmpcfg0::set_pmp(0, range, perm, false);
            }
            1 => {
                pmpaddr1::write(pmp_addr);
                pmpcfg0::set_pmp(1, range, perm, false);
            }
            2 => {
                pmpaddr2::write(pmp_addr);
                pmpcfg0::set_pmp(2, range, perm, false);
            }
            3 => {
                pmpaddr3::write(pmp_addr);
                pmpcfg0::set_pmp(3, range, perm, false);
            }
            4 => {
                pmpaddr4::write(pmp_addr);
                pmpcfg0::set_pmp(4, range, perm, false);
            }
            5 => {
                pmpaddr5::write(pmp_addr);
                pmpcfg0::set_pmp(5, range, perm, false);
            }
            6 => {
                pmpaddr6::write(pmp_addr);
                pmpcfg0::set_pmp(6, range, perm, false);
            }
            7 => {
                pmpaddr7::write(pmp_addr);
                pmpcfg0::set_pmp(7, range, perm, false);
            }
            8 => {
                pmpaddr8::write(pmp_addr);
                pmpcfg2::set_pmp(0, range, perm, false);
            }
            9 => {
                pmpaddr9::write(pmp_addr);
                pmpcfg2::set_pmp(1, range, perm, false);
            }
            10 => {
                pmpaddr10::write(pmp_addr);
                pmpcfg2::set_pmp(2, range, perm, false);
            }
            11 => {
                pmpaddr11::write(pmp_addr);
                pmpcfg2::set_pmp(3, range, perm, false);
            }
            12 => {
                pmpaddr12::write(pmp_addr);
                pmpcfg2::set_pmp(4, range, perm, false);
            }
            13 => {
                pmpaddr13::write(pmp_addr);
                pmpcfg2::set_pmp(5, range, perm, false);
            }
            14 => {
                pmpaddr14::write(pmp_addr);
                pmpcfg2::set_pmp(6, range, perm, false);
            }
            _ => {
                pmpaddr15::write(pmp_addr);
                pmpcfg2::set_pmp(7, range, perm, false);
            }
        }
    }
}

fn get_pmp_reg(idx: u32) -> (usize, Pmp) {
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

#[cfg(test)]
mod tests {
    use super::*;

    // Re-use test case calculation from analysis for predictability
    // Helper to create test slices
    fn pmp_slice(log2len: u32, pa_lo: usize) -> PmpSlice {
        PmpSlice::new(log2len, pa_lo, 0)
    }

    #[test]
    fn test_encode_napot() {
        // E2: Full address space (XLEN=64)
        let slice = pmp_slice(64, 0x0);
        assert_eq!(
            encode_pmp_addr(&slice, Range::NAPOT),
            Some(usize::MAX),
            "E2"
        );

        // E3: 64KB region (2^16), pa_lo=0x10000
        // log2len=16, k=14. addrmask = 2^14-1. pmpaddr = (0x10000>>2) | (addrmask>>1)
        let slice = pmp_slice(16, 0x10000);
        let expected = 0x4000 | ((1usize << 14) - 1) >> 1; // 0x4000 | 0x1FFF = 0x5FFF
        assert_eq!(encode_pmp_addr(&slice, Range::NAPOT), Some(expected), "E3");

        // Custom Test: 2MB region (2^21), pa_lo=0x400000
        // log2len=21, k=19. pa_lo_comp = 0x400000>>2 = 0x100000.
        // addrmask = 2^19-1. pmpaddr = 0x100000 | (addrmask>>1)
        let slice = pmp_slice(21, 0x400000);
        let expected = 0x100000 | ((1usize << 19) - 1) >> 1; // 0x100000 | 0x3FFFF = 0x13FFFF
        assert_eq!(
            encode_pmp_addr(&slice, Range::NAPOT),
            Some(expected),
            "Custom 1"
        );
    }

    #[test]
    fn test_decode_napot() {
        // E2: Full address space (usize::MAX)
        let expected = pmp_slice(usize::BITS, 0x0);
        assert_eq!(
            decode_pmp_addr(usize::MAX, Range::NAPOT),
            expected,
            "E2 Decode"
        );

        // E3: 64KB region (0x5FFF)
        // t1 = (~0x5FFF).trailing_zeros() = 13. log2len = 13 + 2 + 1 = 16.
        // pa_lo = (0x5FFF & ~((1<<13)-1)) << 2 = (0x5FFF & ~0x1FFF) << 2 = 0x4000 << 2 = 0x10000
        let expected = pmp_slice(16, 0x10000);
        assert_eq!(decode_pmp_addr(0x5FFF, Range::NAPOT), expected, "E3 Decode");

        // Custom 1: 2MB region (0x13FFFF)
        // t1 = (~0x13FFFF).trailing_zeros() = 18. log2len = 18 + 2 + 1 = 21.
        // pa_lo = (0x13FFFF & ~((1<<18)-1)) << 2 = (0x13FFFF & ~0x3FFFF) << 2 = 0x100000 << 2 = 0x400000
        let expected = pmp_slice(21, 0x400000);
        assert_eq!(
            decode_pmp_addr(0x13FFFF, Range::NAPOT),
            expected,
            "Custom 1 Decode"
        );
    }

    #[test]
    fn test_na4_mode() {
        // E4: Encode 4-byte region
        let slice = pmp_slice(2, 0x12345678);
        let expected_addr = 0x12345678 >> PMP_SHIFT; // 0x048D159E
        assert_eq!(
            encode_pmp_addr(&slice, Range::NA4),
            Some(expected_addr),
            "E4 Encode"
        );

        // E4: Decode 4-byte region
        let expected_slice = pmp_slice(PMP_SHIFT, 0x12345678);
        assert_eq!(
            decode_pmp_addr(expected_addr, Range::NA4),
            expected_slice,
            "E4 Decode"
        );
    }

    #[test]
    fn test_tor_mode() {
        // E5: Encode TOR bottom address
        let slice = pmp_slice(30, 0x80000000);
        let expected_addr = 0x80000000 >> PMP_SHIFT; // 0x20000000
        assert_eq!(
            encode_pmp_addr(&slice, Range::TOR),
            Some(expected_addr),
            "E5 Encode"
        );

        // E5: Decode TOR bottom address
        let expected_slice = pmp_slice(0, 0x80000000);
        assert_eq!(
            decode_pmp_addr(expected_addr, Range::TOR),
            expected_slice,
            "E5 Decode"
        );
    }

    #[test]
    fn test_off_mode() {
        // E6: Encode OFF
        let slice = pmp_slice(0, 0xFFFFFFFF);
        assert_eq!(encode_pmp_addr(&slice, Range::OFF), Some(0), "E6 Encode");

        // E6: Decode OFF
        let expected_slice = pmp_slice(0, 0);
        assert_eq!(decode_pmp_addr(0, Range::OFF), expected_slice, "E6 Decode");
    }
}
