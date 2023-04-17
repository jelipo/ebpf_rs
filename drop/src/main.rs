#![feature(slice_group_by)]

use anyhow::Result;
use clap::Parser;

mod drop {
    include!("./drop.bpf.rs");
}

#[derive(Debug, Copy, Clone, Parser)]
#[clap(name = "drop", about = "drop net")]
struct Command {
    /// trace pid
    #[clap(short = 'p', long)]
    pid: u32,
    /// wait timeout (second)
    #[clap(short = 'f')]
    time: u64,
}

fn main() -> Result<()> {
    Ok(())
}
