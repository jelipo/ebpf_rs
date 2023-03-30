#![feature(slice_group_by)]

use std::thread;
use std::time::Duration;

use anyhow::{anyhow, Result};
use byteorder::{ByteOrder, NativeEndian};
use clap::Parser;
use libbpf_rs::MapFlags;

use crate::kallsyms::KallsymsCache;
use crate::offcputime::offcputime_bss_types::key_t;
use crate::offcputime::{OffcputimeMaps, OffcputimeSkelBuilder};
use crate::procsyms::ProcsymsCache;

mod kallsyms;
mod procsyms;

mod offcputime {
    include!("./offcputime.bpf.rs");
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
    let builder = OffcputimeSkelBuilder::default();
    let mut open_skel = builder.open()?;
    open_skel.rodata().listen_tgid = cmd.pid;
    let mut skel = open_skel.load()?;
    skel.attach()?;
    // 等待完成
    thread::sleep(Duration::from_secs(cmd.time));
    // 开始处理
    let maps = skel.maps();
    let key_iter = maps.pid_stack_counter().keys();
    let kallsyms_cache = KallsymsCache::new()?;
    let procsyms_cache = ProcsymsCache::new(cmd.pid)?;
    for key_data in key_iter {
        let value_data = maps.pid_stack_counter().lookup(&key_data, MapFlags::ANY)?.expect("key not found");
        let key = unsafe { std::ptr::read_unaligned(key_data.as_ptr() as *const key_t) };
        let value = unsafe { std::ptr::read_unaligned(value_data.as_ptr() as *const u64) };
        let comm_name = String::from_utf8_lossy(&key.comm);
        print!("{}", comm_name.trim_end_matches(char::from(0)));
        print_user_stacks_by_id(&maps, key.user_stack_id as u32, &procsyms_cache)?;
        print!(";-");
        print_kernel_stacks_by_id(&maps, key.kernel_stack_id as u32, &kallsyms_cache)?;
        println!(" {}", value);
    }
    Ok(())
}

fn print_kernel_stacks_by_id(maps: &OffcputimeMaps, kernel_stack_id: u32, cache: &KallsymsCache) -> Result<()> {
    let symbols_data = maps.stack_traces().lookup(&kernel_stack_id.to_ne_bytes(), MapFlags::ANY)?.ok_or(anyhow!("not found"))?;
    let symbols = symbols_data.chunks(8).map(NativeEndian::read_u64).collect::<Vec<_>>();
    for symbol in symbols.iter().rev() {
        if *symbol != 0 {
            print!(";{}", cache.search(*symbol));
        }
    }
    Ok(())
}

fn print_user_stacks_by_id(maps: &OffcputimeMaps, stack_id: u32, cache: &ProcsymsCache) -> Result<()> {
    let symbols_data = maps.stack_traces().lookup(&stack_id.to_ne_bytes(), MapFlags::ANY)?.ok_or(anyhow!("not found"))?;
    let symbols = symbols_data.chunks(8).map(NativeEndian::read_u64).collect::<Vec<_>>();
    for symbol in symbols.iter().rev() {
        if *symbol != 0 {
            print!(";{}", cache.search(*symbol)?);
        }
    }
    Ok(())
}
