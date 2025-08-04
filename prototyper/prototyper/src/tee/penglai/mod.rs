//! Penglai PMP extension (Penglai Secure Monitor) implementation in RustSBI.
use super::pmpm::PmpBitmap;
use ::penglai::enclave::EID_PENGLAI_ENCLAVE;
use ::penglai::host::EID_PENGLAI_HOST;
use rustsbi::{RustSBI, SbiRet};

mod smm;

pub const ENCLAVE_HASH_SIZE: u8 = 32;

#[repr(u8)]
pub enum PenglaiPmpIdx {
    PmpSM = 0,
    PmpTemp = 1,
    PmpDefault = PENGLAI_PMP_END,
}

struct PhyMemRegion {
    hpa: usize,
    len: usize,
}

struct OcallArgs {
    func_id: usize,
    syscall_num: usize,
    args: [usize; 2],
}

enum EnclaveState {
    DESTROYED = -1,
    INVALID = 0,
    FRESH = 1,
    RUNNABLE,
    RUNNING,
    STOPPED,
}

pub(crate) struct EnclaveMetadata {
    // Secure mem region, @free record unused mem size in @sec.
    sec: PhyMemRegion,
    free: usize,
    // Unsecure mem: for enclave to host APP IPC.
    ubuf: PhyMemRegion,
    // Unsecure mem: for enclave to host OS IPC.
    kbuf: PhyMemRegion,

    // Enclave root page table.
    ept: usize,
    // Enclave entry PC.
    entry: usize,
    // Enclave current status.
    state: EnclaveState,

    // Enclave measurement value.
    hash: [u8; ENCLAVE_HASH_SIZE as usize],
    // Enclave developer's public key.
    signer: [u8; ENCLAVE_HASH_SIZE as usize],
}

mod enclave;
mod host;

pub const PENGLAI_PMP_START: u8 = 0;
pub const PENGLAI_PMP_END: u8 = 15;
pub const PENGLAI_PMP_COUNT: u8 = PENGLAI_PMP_END - PENGLAI_PMP_START + 1;

pub const PENGLAI_DEFAULT_MASK: usize = 1 << (PenglaiPmpIdx::PmpSM as u8)
    | 1 << (PenglaiPmpIdx::PmpTemp as u8)
    | 1 << (PenglaiPmpIdx::PmpDefault as u8);
static PENGLAI_PMP_BITMAP: PmpBitmap =
    PmpBitmap::new(PENGLAI_PMP_START, PENGLAI_PMP_END, PENGLAI_DEFAULT_MASK);

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
