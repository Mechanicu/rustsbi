use super::PmpConfig;
use crate::cfg::NUM_HART_MAX;
use crate::riscv::current_hartid;
use crate::sbi::fifo::{Fifo, FifoError};
use crate::tee::pmpm::set_pmp_reg;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicU32, Ordering};
use spin::mutex::Mutex;

pub(crate) struct PmpSyncCell {
    // Queue of PMP operations with PMP entry index
    mailbox: Mutex<Fifo<(PmpConfig, usize)>>,
    // Wait for complete flag.
    wait_sync_count: AtomicU32,
}

pub(crate) static mut ROOT_PMP_STACK: [PmpSyncCell; NUM_HART_MAX] = {
    // 初始化逻辑
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
