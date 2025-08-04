//! PMP management module of Penglai PMP.
//!
//! For now, the one using PMP most usually be secure monitor (SM) of TEE,
//! But in different SM, the way to manage PMP is different, so for now we
//! manage all PMP under Penglai PMP secure monitor when enable Penglai PMP
//! in current Rust Prototyper.
use crate::cfg::NUM_HART_MAX;
use crate::platform::PLATFORM;
use crate::riscv::current_hartid;
use crate::sbi::fifo::{Fifo, FifoError};
use core::mem::MaybeUninit;
use core::sync::atomic::AtomicUsize;
use core::sync::atomic::{AtomicU32, Ordering};
use riscv::register::{
    Permission, Pmp, Range, pmpaddr0, pmpaddr1, pmpaddr2, pmpaddr3, pmpaddr4, pmpaddr5, pmpaddr6,
    pmpaddr7, pmpaddr8, pmpaddr9, pmpaddr10, pmpaddr11, pmpaddr12, pmpaddr13, pmpaddr14, pmpaddr15,
    pmpcfg0, pmpcfg2,
};
use rustsbi::SbiRet;
use spin::mutex::Mutex;

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

/// PMP management bitmap.
impl PmpBitmap {
    pub const fn new(pmp_start: u8, pmp_end: u8, mask: usize) -> Self {
        Self {
            map: (AtomicUsize::new(mask)),
            start: (pmp_start),
            end: (pmp_end),
        }
    }
    fn check_idx(&self, idx: u8) {
        if idx < self.start || idx > self.end || idx & (idx - 1) != 0 {
            panic!(
                "Index {} out of bounds for Bitmap of {}~{}",
                idx, self.start, self.end
            );
        }
    }
    pub fn alloc(&self) -> Option<u8> {
        let mut cur_map = self.map.load(Ordering::SeqCst);
        loop {
            // Find idx of first zero bit in current PMP area bitmap and set used.
            // Beware of that every PMP slot record in PmpIdx will be set to used when init!!!.
            let first_zero = match (self.start..self.end).find(|&i| cur_map & (1 << i) == 0) {
                Some(bit) => bit,
                None => return None,
            };
            let new_map = cur_map | (1 << first_zero);

            // Try to update bitmap by CAS. If update successfully, then return idx.
            match self.map.compare_exchange_weak(
                cur_map,
                new_map,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => return Some(first_zero),
                Err(actual) => cur_map = actual,
            }
        }
    }
    pub fn free(&self, idx: u8, mask: usize) {
        self.check_idx(idx);
        let mask = (1 << idx) & mask;
        self.map.fetch_and(!mask, Ordering::SeqCst);
    }
}

/// Mailbox and operations for PMP synchronous.
pub(crate) struct PmpSyncCell {
    // Queue of PMP operations with PMP entry index
    mailbox: Mutex<Fifo<(PmpConfig, usize)>>,
    // Wait for complete flag.
    wait_sync_count: AtomicU32,
}

pub(crate) static mut ROOT_PMP_STACK: [PmpSyncCell; NUM_HART_MAX] = {
    let mut init_arr = MaybeUninit::<[PmpSyncCell; NUM_HART_MAX as usize]>::uninit();
    let ptr = init_arr.as_mut_ptr();
    let mut i = 0;
    while i < NUM_HART_MAX as usize {
        unsafe {
            let region_ptr = ptr.cast::<PmpSyncCell>().add(i);
            region_ptr.write(PmpSyncCell::new());
            i += 1;
        }
    }
    unsafe { init_arr.assume_init() }
};

// Mark PmpSyncCell as safe to share between threads
unsafe impl Sync for PmpSyncCell {}
unsafe impl Send for PmpSyncCell {}

impl PmpSyncCell {
    pub const fn new() -> Self {
        Self {
            mailbox: Mutex::new(Fifo::new()),
            wait_sync_count: AtomicU32::new(0),
        }
    }
    /// Gets a local view of this fence cell for the current hart.
    #[inline]
    pub fn local(&self) -> LocalPmpSyncCell<'_> {
        LocalPmpSyncCell(self)
    }
    /// Gets a remote view of this fence cell for accessing from other harts.
    #[inline]
    pub fn remote(&self) -> RemotePmpSyncCell<'_> {
        RemotePmpSyncCell(self)
    }
}

/// View of PmpSyncCell for operations on the current hart.
pub struct LocalPmpSyncCell<'a>(&'a PmpSyncCell);
/// View of PmpSyncCell for operations from other harts.
pub struct RemotePmpSyncCell<'a>(&'a PmpSyncCell);

impl LocalPmpSyncCell<'_> {
    /// Checks if all synchronization operations are complete.
    #[inline]
    pub fn is_sync(&self) -> bool {
        self.0.wait_sync_count.load(Ordering::Relaxed) == 0
    }

    /// Increments the synchronization counter.
    #[inline]
    pub fn add(&self) {
        self.0.wait_sync_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Checks if the operation queue is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.0.mailbox.lock().is_empty()
    }

    /// Gets the next fence operation from the queue.
    #[inline]
    pub fn get(&self) -> Option<(PmpConfig, usize)> {
        self.0.mailbox.lock().pop().ok()
    }

    /// Adds a fence operation to the queue, retrying if full.
    pub fn set(&self, ctx: PmpConfig) -> bool {
        loop {
            let mut mailbox = self.0.mailbox.lock();
            match mailbox.push((ctx, current_hartid())) {
                Ok(_) => return true,
                Err(FifoError::Full) => return false,
                Err(_) => panic!("Unable to push fence ops to fifo"),
            }
        }
    }
}

#[allow(unused)]
impl RemotePmpSyncCell<'_> {
    /// Adds a fence operation to the queue from a remote hart.
    pub fn set(&self, ctx: PmpConfig) -> bool {
        loop {
            let mut mailbox = self.0.mailbox.lock();
            match mailbox.push((ctx, current_hartid())) {
                Ok(_) => return true,
                Err(FifoError::Full) => return false,
                Err(_) => panic!("Unable to push fence ops to fifo"),
            }
        }
    }

    /// Decrements the synchronization counter.
    pub fn sub(&self) {
        self.0.wait_sync_count.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Gets the local fence context for the current hart.
#[inline]
pub(crate) fn local_pmpctx() -> Option<LocalPmpSyncCell<'static>> {
    unsafe { ROOT_PMP_STACK.get_mut(current_hartid()).map(|x| x.local()) }
}

/// Gets the remote fence context for a specific hart.
#[inline]
pub(crate) fn remote_pmpctx(hart_id: usize) -> Option<RemotePmpSyncCell<'static>> {
    unsafe { ROOT_PMP_STACK.get_mut(hart_id).map(|x| x.remote()) }
}

/// PMP synchronous IPI handler.
#[inline]
pub(crate) fn ipi_handler() {
    let receiver = local_pmpctx().unwrap();
    while !receiver.is_empty() {
        if let Some(config) = receiver.get() {
            // Set local PMP entry.
            set_pmp_reg(
                config.0.pmp_idx,
                config.0.pmp_addr,
                config.0.pmp_mode,
                config.0.pmp_perm,
            );
            // Notify sender process complete.
            if let Some(sender) = remote_pmpctx(config.1) {
                sender.sub();
            }
        }
    }
}
