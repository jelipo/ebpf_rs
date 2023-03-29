use std::thread;
use std::time::Duration;

use anyhow::{anyhow, Result};
use byteorder::{ByteOrder, LittleEndian};
use clap::Parser;
use libbpf_rs::MapFlags;

use crate::kallsyms::KallsymsCache;
use crate::runqslower::{TracepointMaps, TracepointSkelBuilder};
use crate::runqslower::tracepoint_bss_types::key_t;

mod kallsyms;

mod runqslower {
    include!("./tracepoint.bpf.rs");
}

#[derive(Debug, Copy, Clone, Parser)]
#[clap(name = "offcputime", about = "trace pid offcputime")]
struct Command {
    /// trace pid
    #[clap(short = 'p', long)]
    pid: u32,
    /// wait timeout (second)
    #[clap(short = 'f')]
    time: u64,
}

fn main() -> Result<()> {
    let cmd = Command::parse();
    // 初始化
    common::bump_memlock_rlimit()?;
    let builder = TracepointSkelBuilder::default();
    let mut open_skel = builder.open()?;
    open_skel.rodata().listen_tgid = cmd.pid;
    let mut skel = open_skel.load()?;
    skel.attach()?;
    // 等待完成
    println!("wait {} seconds", cmd.time);
    thread::sleep(Duration::from_secs(cmd.time));
    // 开始处理
    println!("finished waiting");

    let maps = skel.maps();
    let key_iter = maps.pid_stack_counter().keys();
    for key_data in key_iter {
        let value_data = maps.pid_stack_counter().lookup(&key_data, MapFlags::ANY)?.expect("key not found");
        let key = unsafe { std::ptr::read_unaligned(key_data.as_ptr() as *const key_t) };
        let value = unsafe { std::ptr::read_unaligned(value_data.as_ptr() as *const u64) };
        print_kernel_stacks_by_id(&maps, key.kernel_stack_id as u32)?;
    }
    Ok(())
}

fn print_kernel_stacks_by_id(maps: &TracepointMaps, kernel_stack_id: u32) -> Result<()> {
    let cache = KallsymsCache::new()?;
    let symbols_data = maps.stack_traces().lookup(&kernel_stack_id.to_ne_bytes(), MapFlags::ANY)?.ok_or(anyhow!("not found"))?;
    let symbols = symbols_data.chunks(8).map(|chunk| LittleEndian::read_u64(chunk)).collect::<Vec<u64>>();
    for symbol in symbols {
        if symbol == 0 { continue; }
        print!(";{}", cache.search(symbol));
    }
    println!();
    Ok(())
}

fn print_user_stacks_by_id(maps: &TracepointMaps, stack_id: u32) -> Result<()> {
    let symbols = maps.stack_traces().lookup(&stack_id.to_ne_bytes(), MapFlags::ANY)?.ok_or(anyhow!("not found"))?;

    Ok(())
}
