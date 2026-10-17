fn main() {
    let output = std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .expect("Failed to execute git");
    let rev = String::from_utf8(output.stdout).expect("Failed to parse git output");
    println!("cargo:rustc-env=GIT_COMMIT_SHA={rev}");
    println!("cargo:rustc-rerun-if-changed=.git/HEAD");
    ppu_signature_includes().expect("Could not embed per-function PPU signatures");
}

// DTK-compatible file-per-function PS3 signatures: include files at build time.
// This list is generated from the directory, not maintained manually.
#[allow(dead_code)]
fn ppu_signature_includes() -> std::io::Result<()> {
    use std::{fs, io::Write, path::PathBuf};
    let root = PathBuf::from("assets/signatures/ppu");
    println!("cargo:rerun-if-changed={}", root.display());
    let mut paths = Vec::new();
    for family in ["gcc-runtime", "ps3-sdk"] {
        let dir = root.join(family);
        if !dir.exists() {
            continue;
        }
        for entry in fs::read_dir(dir)? {
            let file = entry?.path();
            if file.extension().is_some_and(|ext| ext == "yml") {
                paths.push(file);
            }
        }
    }
    paths.sort();
    let destination =
        PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("ppu_signature_files.rs");
    let mut output = fs::File::create(destination)?;
    writeln!(output, "&[")?;
    for path in paths {
        let full = fs::canonicalize(path)?;
        writeln!(output, "include_str!({:?}),", full.to_string_lossy())?;
    }
    writeln!(output, "]")?;
    Ok(())
}
