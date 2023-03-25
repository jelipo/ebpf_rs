use std::env::current_dir;

use libbpf_cargo::SkeletonBuilder;

const SRC: &str = "src/hashmap.bpf.c";

fn main() {
    println!("当前目录：{:?}", current_dir());
    let result: libbpf_cargo::Result<()> = SkeletonBuilder::new()
        .source(SRC)
        .debug(true)
        .clang_args("-I../include/")
        .build_and_generate("./src/hashmap.bpf.rs");
    if let Err(err) = result {
        println!("{}", err);
        panic!("{}", err.to_string());
    }
    println!("cargo:rerun-if-changed={SRC}");
}