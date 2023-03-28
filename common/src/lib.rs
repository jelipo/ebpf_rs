#![feature(adt_const_params)]
#![feature(generic_const_exprs)]

pub mod convert;

use anyhow::{bail, Result};

pub fn bump_memlock_rlimit() -> Result<()> {
    let rlimit = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) } != 0 {
        bail!("Failed to increase rlimit");
    }

    Ok(())
}

pub fn check_root() -> Result<()> {
    Ok(())
}

