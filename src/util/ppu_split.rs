//! Retains the original PPU command paths with the new PS3 object model.
pub use crate::ps3::util::ppu_split::{read_elf, split, verify};

pub fn is_ppu(path: &typed_path::Utf8NativePath) -> anyhow::Result<bool> {
    use std::io::Read;
    let mut file = std::fs::File::open(path)?;
    let mut header = [0u8; 20];
    let len = file.read(&mut header)?;
    Ok(len >= 20
        && header.starts_with(b"\x7FELF")
        && header[4] == 2
        && header[5] == 2
        && u16::from_be_bytes([header[18], header[19]]) == object::elf::EM_PPC64)
}

pub fn config(
    input: &typed_path::Utf8NativePath,
    out: &typed_path::Utf8NativePath,
) -> anyhow::Result<()> {
    crate::ps3::util::ppu_split::config_with_signatures(input, out, None)
}
