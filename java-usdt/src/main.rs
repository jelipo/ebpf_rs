use crate::javausdt::JavausdtSkelBuilder;
use anyhow::{anyhow, Result};
use clap::Parser;
use std::thread;
use std::time::Duration;

mod javausdt {
    include!("./javausdt.bpf.rs");
}

#[derive(Debug, Copy, Clone, Parser)]
#[clap(name = "offcputime", about = "trace pid offcputime")]
struct Command {
    /// trace pid
    #[clap(short = 'p', long)]
    pid: i32,
}

fn main() -> Result<()> {
    let cmd = Command::parse();
    let builder = JavausdtSkelBuilder::default();
    let open_skel = builder.open()?;
    let mut skel = open_skel.load()?;
    let libjvm_path = find_libjvm(cmd.pid)?;
    let _link = skel.progs_mut().gc_begin().attach_usdt(cmd.pid, libjvm_path, "hotspot", "gc__begin")?;
    thread::sleep(Duration::from_secs(899999));
    Ok(())
}

fn find_libjvm(pid: i32) -> Result<String> {
    let maps = proc_maps::get_process_maps(pid)?;
    for map_range in maps.iter() {
        if let Some(path) = map_range.filename() {
            if path.ends_with("libjvm.so") {
                return Ok(format!("/proc/{}/root{}", pid, path.to_string_lossy()));
            }
        }
    }
    Err(anyhow!("can not found libjvm.so"))
}
