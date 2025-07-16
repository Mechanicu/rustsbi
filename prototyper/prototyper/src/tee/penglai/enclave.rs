//! Penglai Secure Monitor enclave-side implementation in RustSBI.
use rustsbi::SbiRet;

#[inline]
pub fn handle_ecall_fast(function: usize, param: [usize; 6]) -> rustsbi::SbiRet {
    return SbiRet::success(0);
}

// pub fn handle_ecall_full() -> rustsbi::SbiRet {}
