//! Penglai Secure Monitor host-side implementation in RustSBI.
use super::smm::*;
use ::penglai::host::*;
use rustsbi::SbiRet;

pub enum SMMRet {
    Success,
    NoMem,
    Error,
}

#[inline]
pub fn handle_ecall_fast(function: usize, param: [usize; 6]) -> SbiRet {
    let ret = match function {
        // secure memory management functions
        // alloc secure memory for enclave
        ALLOC_ENCLAVE_MM => secmem_alloc(),
        // free secure memory of enclave
        FREE_ENCLAVE_MEM => secmem_free(),
        // extend secure memory from host
        MEMORY_EXTEND => secmem_extend(),
        // reclaim secure memory to host
        MEMORY_RECLAIM => secmem_reclaim(),
        // init secure memory manager
        MM_INIT => secmem_init(param[0], param[1]),
        // unknown secure memory management function
        _ => SMMRet::Error,
    };
    SbiRet::success(0)
}

// pub fn handle_ecall_full() {}
