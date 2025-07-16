//! Penglai Secure Monitor host-side implementation in RustSBI.
use rustsbi::SbiRet;
use ::penglai::host::*;
use super::smm::*;

#[inline]
pub fn handle_ecall_fast(function: usize, param: [usize; 6]) -> rustsbi::SbiRet {
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
        MM_INIT => secmem_manager_init(param[0], param[1]),                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            
        // enclave management

        // unknown function
        _ => SbiRet::invalid_param(),
    };       
    ret
}

// pub fn handle_ecall_full() {}
