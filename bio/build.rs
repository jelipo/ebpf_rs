use libbpf_cargo::SkeletonBuilder;

const SRC_NAME: &str = "src/bio";

fn main() {
    let bpf_c = format!("{}.bpf.c", SRC_NAME);
    let bpf_rs = format!("{}.bpf.rs", SRC_NAME);
    let result: libbpf_cargo::Result<()> =
        SkeletonBuilder::new().source(&bpf_c).debug(true).clang_args("-I../include/").build_and_generate(bpf_rs);
    if let Err(err) = result {
        println!("{}", err);
        panic!("{}", err.to_string());
    }
    println!("cargo:rerun-if-changed={}", bpf_c);
}
