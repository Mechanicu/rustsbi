//! Penglai Secure Monitor host-side implementation in RustSBI.
use super::smm::*;
use crate::tee::penglai::PenglaiPmpIdx;
use ::penglai::host::*;
use core::sync::atomic::AtomicBool;
use core::sync::atomic::Ordering;
use rustsbi::SbiRet;

static IS_CREATE_ENCLAVE: AtomicBool = AtomicBool::new(false);

/// Request @PMPTemp or release it.
#[inline]
fn set_enclave_create_flag(flag: bool) -> SbiRet {
    match IS_CREATE_ENCLAVE.compare_exchange_weak(!flag, flag, Ordering::SeqCst, Ordering::SeqCst) {
        Ok(_) => SbiRet::success(0),
        Err(_) => SbiRet::failed(),
    }
}

/// Copy arguments from host to SM.
///
/// Be aware host2sm directly handle pointers, may be unsafe.
#[inline]
fn host2sm<T: Copy>(hptr: usize) -> Option<T> {
    let src_ptr = hptr as *const T;
    // Host ptr shouldn't been protected or NULL.
    if src_ptr.is_null() || None != is_data_protected(src_ptr as usize, size_of::<T>()) {
        return None;
    }
    unsafe { Some(*src_ptr) }
}

/// Copy arguments from SM to host.
///
/// Be aware the function is danger and may be used to attack SM!
#[inline]
fn sm2host<T: Copy>(hptr: usize, src: T) -> SbiRet {
    let dest_ptr = hptr as *mut T;
    if dest_ptr.is_null() {
        return SbiRet::invalid_param();
    }
    // Should not exposed address info about other enclaves to host.
    let src_ptr: *const T = &src;
    if let Some(idx) = is_data_protected(src_ptr as usize, size_of::<T>())
        && (idx != PenglaiPmpIdx::PmpSM as usize)
    {
        error!(
            "sm2host, data is protected by other region,{}!",
            src_ptr as usize
        );
        return SbiRet::invalid_param();
    }
    SbiRet::success(0)
}

#[inline]
/// Penglai PMP enclave memory allocation.
fn alloc_enclave_mem(hptr: usize) -> SbiRet {
    // Only one enclave can in CREATE status.
    if set_enclave_create_flag(true) == SbiRet::failed() {
        return SbiRet::already_started();
    }
    info!("Alloc enclave mem start, prepare enclave create");
    // Copy args from U/S to SM.
    let mut args = match host2sm::<EnclaveMemArgs>(hptr) {
        Some(args) if args.reqsize != 0 => args,
        _ => return SbiRet::invalid_param(),
    };
    info!("Alloc enclave mem req:{}", args.reqsize);
    if let Some((rspsize, rspaddr)) = secmem_alloc(args.reqsize) {
        args.addr = rspaddr;
        args.rspsize = rspsize;
        info!("Alloc enclave mem rsp:{}, {}", args.rspsize, args.addr);
    } else {
        return SbiRet::invalid_param();
    }
    // Temporary grant U/S with access to enclave mem, then copy request memory back to host.
    if (sm2host(hptr, args) != SbiRet::success(0))
        || (grant_kernel_access(args.addr, args.rspsize) != SbiRet::success(0))
    {
        secmem_free(args.addr, args.rspsize);
        return SbiRet::failed();
    }
    SbiRet::success(0)
}

#[inline]
/// Penglai PMP enclave memory free.
///
/// Be aware that SM cannot fully check if memory is legal,
/// return an memory not alloc by SM may cause PANIC.
fn free_enclave_mem(hptr: usize) -> SbiRet {
    // Get args from host.
    let args = match host2sm::<EnclaveMemArgs>(hptr) {
        Some(args) => args,
        None => {
            error!("Free enclave mem failed, {}", hptr);
            return SbiRet::invalid_param();
        }
    };
    // If U/S has temporary access for enclave mem, retrive it.
    let sbiret = retrive_kernel_access(args.addr, args.reqsize);
    if (sbiret == SbiRet::success(0)) || (sbiret == SbiRet::invalid_address()) {
        // Free enclave mem.
        return secmem_free(args.addr, args.rspsize);
    }
    return SbiRet::failed();
}

#[inline]
pub fn handle_ecall_fast(function: usize, param: [usize; 6]) -> SbiRet {
    match function {
        // secure memory management functions
        // alloc secure memory for enclave
        ALLOC_ENCLAVE_MM => alloc_enclave_mem(param[0]),
        // free secure memory of enclave
        FREE_ENCLAVE_MEM => free_enclave_mem(param[0]),
        // extend secure memory from host
        MEMORY_EXTEND => secmem_extend(),
        // reclaim secure memory to host
        MEMORY_RECLAIM => secmem_reclaim(),
        // init secure memory manager
        MM_INIT => secmem_init(param[0], param[1]),
        // unknown secure memory management function
        _ => return SbiRet::invalid_param(),
    };
    SbiRet::success(0)
}

// pub fn handle_ecall_full() {}
