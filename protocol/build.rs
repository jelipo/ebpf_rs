use std::fs;
use std::path::Path;
use libbpf_cargo::SkeletonBuilder;
use anyhow::Result;


fn main() {
    if let Err(err) = build_bpf() {
        panic!("{}", err);
    }
}

fn build_bpf() -> Result<()> {
    let dir = fs::read_dir("src/bpf")?;
    for entry in dir {
        let path = entry?.path();
        if let Ok(dir) = fs::read_dir(path) {
            for entry in dir {
                let path = entry?.path();
                if path.is_file() {
                    let file_path = path.file_name().unwrap();
                    if file_path.to_string_lossy().ends_with(".bpf.c") {
                        println!("build bpf file {:?}", path);
                        build_single_bpf(&path)?;
                    }
                }
            }
        }
    }
    Ok(())
}

fn build_single_bpf(c_file_path: &Path) -> Result<()> {
    let bpf_c = c_file_path.to_string_lossy().to_string();
    let bpf_rs = bpf_c.replace(".c", ".rs");
    println!("bpf_rs:{}", bpf_rs);
    let result: libbpf_cargo::Result<()> =
        SkeletonBuilder::new().source(&bpf_c).debug(true).clang_args("-I../include/ -I./src/bpf/include/").build_and_generate(bpf_rs);
    if let Err(err) = result {
        println!("err:{}", err);
        panic!("{}", err.to_string());
    }
    println!("cargo:rerun-if-changed={}", bpf_c);
    Ok(())
}