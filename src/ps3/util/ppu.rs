//! PS3 PPU function descriptors (ELF64 PowerPC64 with 32-bit addresses).

use anyhow::{Context, Result, ensure};
use object::{Architecture, BinaryFormat, Endianness, File, Object, ObjectSection};

/// The `.opd` table. Each descriptor stores its own code address and TOC (r2).
#[derive(Debug, Clone)]
pub struct PpuOpd {
    start: u64,
    descriptors: Vec<(u32, u32)>,
}

impl PpuOpd {
    pub fn parse(file: &File<'_>) -> Result<Self> {
        ensure!(file.format() == BinaryFormat::Elf, "Expected ELF file");
        ensure!(file.architecture() == Architecture::PowerPc64, "Expected PowerPC64 ELF");
        ensure!(file.endianness() == Endianness::Big, "Expected big-endian ELF");

        let section = file.section_by_name(".opd").context("Missing .opd section")?;
        let bytes = section.uncompressed_data()?;
        ensure!(bytes.len() % 8 == 0, "Invalid .opd size: {}", bytes.len());
        section.address().checked_add(bytes.len() as u64).context(".opd address overflow")?;

        let descriptors = bytes
            .chunks_exact(8)
            .map(|entry| {
                (
                    u32::from_be_bytes(entry[..4].try_into().unwrap()),
                    u32::from_be_bytes(entry[4..].try_into().unwrap()),
                )
            })
            .collect();
        Ok(Self { start: section.address(), descriptors })
    }

    /// Returns `(code, toc)` for a descriptor's virtual address.
    #[cfg(test)]
    pub fn get(&self, address: u64) -> Option<(u32, u32)> {
        let offset = address.checked_sub(self.start)?;
        if offset % 8 != 0 {
            return None;
        }
        self.descriptors.get(usize::try_from(offset / 8).ok()?).copied()
    }

    /// Iterates over `(descriptor_address, (code, toc))` pairs in address order.
    pub fn iter(&self) -> impl Iterator<Item = (u64, (u32, u32))> + '_ {
        self.descriptors
            .iter()
            .enumerate()
            .map(|(i, &descriptor)| (self.start + i as u64 * 8, descriptor))
    }

    #[cfg(test)]
    pub fn len(&self) -> usize { self.descriptors.len() }

    #[cfg(test)]
    pub fn is_empty(&self) -> bool { self.descriptors.is_empty() }
}

#[cfg(test)]
mod tests {
    use object::{BinaryFormat, SectionKind, write::Object as WriteObject};

    use super::*;

    fn elf(architecture: Architecture, opd: Option<&[u8]>) -> Vec<u8> {
        let mut object = WriteObject::new(BinaryFormat::Elf, architecture, Endianness::Big);
        if let Some(bytes) = opd {
            let section = object.add_section(Vec::new(), b".opd".to_vec(), SectionKind::Data);
            object.section_mut(section).set_data(bytes.to_vec(), 8);
        }
        object.write().unwrap()
    }

    #[test]
    fn descriptors_keep_individual_toc_anchors() {
        let mut bytes = elf(
            Architecture::PowerPc64,
            Some(&[
                0, 1, 2, 0, 0, 0x9a, 0xf2, 0xc0, 0, 1, 2, 4, 0, 0x9b, 0xe3, 0xf8, 0, 1, 2, 8, 0,
                0x9a, 0xf2, 0xc0,
            ]),
        );
        // Give the generated ELF section a PS3-style nonzero virtual address.
        let section_index =
            File::parse(bytes.as_slice()).unwrap().section_by_name(".opd").unwrap().index().0;
        let section_headers = u64::from_be_bytes(bytes[40..48].try_into().unwrap()) as usize;
        let section_header_size = u16::from_be_bytes(bytes[58..60].try_into().unwrap()) as usize;
        let address_offset = section_headers + section_index * section_header_size + 16;
        bytes[address_offset..address_offset + 8].copy_from_slice(&0x954ab0u64.to_be_bytes());

        let file = File::parse(bytes.as_slice()).unwrap();
        let opd = PpuOpd::parse(&file).unwrap();
        assert_eq!(opd.len(), 3);
        assert!(!opd.is_empty());
        assert_eq!(opd.get(0x954ab0), Some((0x10200, 0x9af2c0)));
        assert_eq!(opd.get(0x954ab8), Some((0x10204, 0x9be3f8)));
        assert_eq!(opd.get(0x954ac0), Some((0x10208, 0x9af2c0)));
        assert_eq!(opd.get(0x954ab1), None);
        assert_eq!(opd.get(0x954aa8), None);
        assert_eq!(opd.get(0x954ac8), None);
        assert_eq!(opd.iter().collect::<Vec<_>>(), vec![
            (0x954ab0, (0x10200, 0x9af2c0)),
            (0x954ab8, (0x10204, 0x9be3f8)),
            (0x954ac0, (0x10208, 0x9af2c0)),
        ]);
    }

    #[test]
    fn rejects_missing_or_truncated_opd_and_wrong_architecture() {
        let missing = elf(Architecture::PowerPc64, None);
        let file = File::parse(missing.as_slice()).unwrap();
        assert!(PpuOpd::parse(&file).is_err());

        let truncated = elf(Architecture::PowerPc64, Some(&[0; 9]));
        let file = File::parse(truncated.as_slice()).unwrap();
        assert!(PpuOpd::parse(&file).is_err());

        let wrong_arch = elf(Architecture::PowerPc, Some(&[0; 8]));
        let file = File::parse(wrong_arch.as_slice()).unwrap();
        assert!(PpuOpd::parse(&file).is_err());
    }
}
