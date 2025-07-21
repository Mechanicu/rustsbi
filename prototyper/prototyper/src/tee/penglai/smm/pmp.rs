//! PMP management module of Penglai PMP.
//! 
//! For now, the one using PMP most usually be secure monitor (SM) of TEE, 
//! But in different SM, the way to manage PMP is different, so for now we
//! manage all PMP under Penglai PMP secure monitor when enable Penglai PMP
//! in current Rust Prototyper.
pub const N_AVAL_PMP_REGION: usize = 8;
pub const PMP_KERNEL: usize = 1;
pub const PMP_SM: usize = 0;
pub const PMP_DEFAULT: usize = 15;

/// Set PMP slot N configuration on every hart.
pub fn set_pmp_sync(slot: usize){

}

/// Clear PMP slot N configuration on every hart.
pub fn clear_pmp_sync(slot: usize){

}

/// Set PMP slot on current hart.
pub fn set_pmp(slot: usize){

}

pub fn clear_pmp(slot: usize){

}

pub fn dump_pmps(){

}