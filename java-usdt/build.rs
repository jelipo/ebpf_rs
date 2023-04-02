use libbpf_cargo::SkeletonBuilder;

const SRC: &str = "src/javausdt.bpf.c";

fn main() {
    let result: libbpf_cargo::Result<()> =
        SkeletonBuilder::new().source(SRC).debug(true).clang_args("-I../include/").build_and_generate("./src/javausdt.bpf.rs");
    if let Err(err) = result {
        println!("{}", err);
        panic!("{}", err.to_string());
    }
}
