//! Penglai PMP extension (Penglai Secure Monitor) implementation in RustSBI.
use ::penglai::enclave::EID_PENGLAI_ENCLAVE;
use ::penglai::host::EID_PENGLAI_HOST;
use rustsbi::{RustSBI, SbiRet};

pub const ENCLAVE_HASH_SIZE: u8 = 32;

struct phymem_region {
    hpa: usize,
    len: usize,
}

struct ocall_arg {
    func_id: usize,
    syscall_num: usize,
    args: [usize; 2],
}

enum enclave_state {
    DESTROYED = -1,
    INVALID = 0,
    FRESH = 1,
    RUNNABLE,
    RUNNING,
    STOPPED,
}

pub(crate) struct enclave_metadata {
    // Secure mem region, @free record unused mem size in @sec.
    sec: phymem_region,
    free: usize,
    // Unsecure mem: for enclave to host APP IPC.
    ubuf: phymem_region,
    // Unsecure mem: for enclave to host OS IPC.
    kbuf: phymem_region,

    // Enclave root page table.
    ept: usize,
    // Enclave entry PC.
    entry: usize,
    // Enclave current status.
    state: enclave_state,

    // Enclave measurement value.
    hash: [u8; ENCLAVE_HASH_SIZE as usize],
    // Enclave developer's public key.
    signer: [u8; ENCLAVE_HASH_SIZE as usize],
}

mod enclave;
mod host;
mod smm;

pub(crate) struct PenglaiPlatform {}

impl RustSBI for PenglaiPlatform {
    fn handle_ecall(
        &self,
        extension: usize,
        function: usize,
        param: [usize; 6],
    ) -> rustsbi::SbiRet {
        let ret = match extension {
            EID_PENGLAI_HOST => enclave::handle_ecall_fast(function, param),
            EID_PENGLAI_ENCLAVE => host::handle_ecall_fast(function, param),
            _ => SbiRet::invalid_param(),
        };
        ret
    }
}

pub(crate) static mut PENGLAI_PLATFORM: PenglaiPlatform = PenglaiPlatform {};
