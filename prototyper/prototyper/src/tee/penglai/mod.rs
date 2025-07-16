//! Penglai PMP extension (Penglai Secure Monitor) implementation in RustSBI.

use ::rustsbi::RustSBI;
use ::penglai::host::EID_PENGLAI_HOST;
use ::penglai::enclave::EID_PENGLAI_ENCLAVE;
use rustsbi::SbiRet;

mod enclave;
mod host;
mod smm;

struct PenglaiPlatform {}

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
            _ => SbiRet::invalid_param()
        };
        ret
    }
}


