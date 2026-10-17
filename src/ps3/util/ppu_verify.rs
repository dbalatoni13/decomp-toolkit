//! Executable-image verification for PS3 PPU relinks.

use std::fs;

use anyhow::{Context, Result, ensure};
use object::{Architecture, File, Object, ObjectSection, SectionFlags, SectionKind, elf};
use typed_path::Utf8NativePath;

use super::ppu_split::{ElfProjectConfig, project_path, read_elf};

/// Compares every nonempty allocated section after a fixed-address relink.
pub fn verify(config_path: &Utf8NativePath, linked_path: &Utf8NativePath) -> Result<usize> {
    let config: ElfProjectConfig = serde_yaml::from_slice(&fs::read(config_path)?)?;
    let original_path = project_path(config_path, &config.object);
    if let Some(hash) = &config.hash {
        let mut source = fs::File::open(&original_path)?;
        let original_sha1 = crate::cmd::shasum::file_sha1_string(&mut source)?;
        ensure!(
            original_sha1.eq_ignore_ascii_case(hash),
            "Original ELF SHA-1 mismatch: expected {hash}, got {original_sha1}"
        );
    }
    let original_bytes = read_elf(&original_path)?;
    let linked_bytes = read_elf(linked_path)?;
    let original = File::parse(original_bytes.as_slice())?;
    let linked = File::parse(linked_bytes.as_slice())?;
    ensure!(original.architecture() == Architecture::PowerPc64, "Input must be PowerPC64");
    ensure!(linked.kind() == object::ObjectKind::Executable, "Linked ELF is not executable");
    ensure!(
        original.entry() == linked.entry(),
        "ELF entry differs: {:#X} vs {:#X}",
        original.entry(),
        linked.entry()
    );
    let matched = compare_allocated_sections(&original, &linked)?;
    println!("Verified {matched} allocated sections and the entrypoint");
    Ok(matched)
}

fn compare_allocated_sections(original: &File<'_>, linked: &File<'_>) -> Result<usize> {
    let mut matched = 0;
    let mut expected_sections = std::collections::BTreeSet::new();
    for section in original.sections() {
        let alloc = matches!(section.flags(), SectionFlags::Elf { sh_flags }
            if sh_flags & u64::from(elf::SHF_ALLOC) != 0);
        if !alloc || section.size() == 0 {
            continue;
        }
        let name = section.name()?;
        expected_sections.insert(name.to_owned());
        let rebuilt = linked
            .section_by_name(name)
            .with_context(|| format!("Missing allocated section {name}"))?;
        let rebuilt_flags = match rebuilt.flags() {
            SectionFlags::Elf { sh_flags } => sh_flags,
            _ => 0,
        };
        let original_flags = match section.flags() {
            SectionFlags::Elf { sh_flags } => sh_flags,
            _ => 0,
        };
        let runtime_flags =
            u64::from(elf::SHF_ALLOC | elf::SHF_WRITE | elf::SHF_EXECINSTR | elf::SHF_TLS);
        ensure!(
            rebuilt_flags & runtime_flags == original_flags & runtime_flags,
            "Section {name}: runtime ELF flags differ ({:#X} vs {:#X})",
            original_flags & runtime_flags,
            rebuilt_flags & runtime_flags
        );
        ensure!(
            section.address() == rebuilt.address() && section.size() == rebuilt.size(),
            "Section {name}: address/size differs ({:#X}/{:#X} vs {:#X}/{:#X})",
            section.address(),
            section.size(),
            rebuilt.address(),
            rebuilt.size()
        );
        let original_data = section.data()?;
        let rebuilt_data = rebuilt.data()?;
        // Uninitialized sections have no file bytes but must still be zero at
        // runtime. The SDK sometimes encodes zero-filled TLS as PROGBITS.
        let equivalent_zero_storage = original_data.is_empty() || rebuilt_data.is_empty();
        if equivalent_zero_storage {
            ensure!(
                original_data.iter().all(|byte| *byte == 0)
                    && rebuilt_data.iter().all(|byte| *byte == 0)
                    && (original_data.is_empty()
                        || matches!(
                            section.kind(),
                            SectionKind::UninitializedData | SectionKind::UninitializedTls
                        )
                        || original_data.len() == section.size() as usize)
                    && (rebuilt_data.is_empty() || rebuilt_data.len() == rebuilt.size() as usize),
                "Section {name}: initialized data differs from zero-filled storage"
            );
        } else {
            ensure!(
                original_data == rebuilt_data,
                "Section {name} differs at offset {:#X}",
                original_data
                    .iter()
                    .zip(rebuilt_data)
                    .position(|(a, b)| a != b)
                    .unwrap_or(original_data.len())
            );
        }
        matched += 1;
    }
    for section in linked.sections() {
        let alloc = matches!(section.flags(), SectionFlags::Elf { sh_flags }
            if sh_flags & u64::from(elf::SHF_ALLOC) != 0);
        if alloc && section.size() != 0 {
            ensure!(
                expected_sections.contains(section.name()?),
                "Unexpected allocated section {} in relinked ELF",
                section.name()?
            );
        }
    }
    Ok(matched)
}

#[cfg(test)]
mod tests {
    use super::*;
    use object::{BinaryFormat, Endianness, write::Object as WriteObject};

    fn sample(text: &[u8], bss: Option<&[u8]>, extra: bool) -> Vec<u8> {
        let mut writer =
            WriteObject::new(BinaryFormat::Elf, Architecture::PowerPc64, Endianness::Big);
        let section = writer.add_section(Vec::new(), b".text".to_vec(), SectionKind::Text);
        writer.append_section_data(section, text, 4);
        let section = writer.add_section(
            Vec::new(),
            b".bss".to_vec(),
            if bss.is_some() { SectionKind::Data } else { SectionKind::UninitializedData },
        );
        if let Some(data) = bss {
            writer.append_section_data(section, data, 4);
        } else {
            writer.append_section_bss(section, 4, 4);
        }
        if extra {
            let section = writer.add_section(Vec::new(), b".extra".to_vec(), SectionKind::Data);
            writer.append_section_data(section, &[0, 0, 0, 0], 4);
        }
        writer.write().unwrap()
    }

    #[test]
    fn rejects_modified_data_or_extra_allocated_sections() {
        let original = sample(&[1, 2, 3, 4], None, false);
        let different = sample(&[1, 2, 3, 5], None, false);
        let extra = sample(&[1, 2, 3, 4], None, true);
        let original = File::parse(original.as_slice()).unwrap();
        assert_eq!(compare_allocated_sections(&original, &original).unwrap(), 2);
        assert!(
            compare_allocated_sections(&original, &File::parse(different.as_slice()).unwrap())
                .is_err()
        );
        assert!(
            compare_allocated_sections(&original, &File::parse(extra.as_slice()).unwrap()).is_err()
        );
    }

    #[test]
    fn rejects_nonzero_initialized_bytes_in_originally_uninitialized_section() {
        let original = sample(&[1, 2, 3, 4], None, false);
        let zero = sample(&[1, 2, 3, 4], Some(&[0; 4]), false);
        let nonzero = sample(&[1, 2, 3, 4], Some(&[0, 1, 0, 0]), false);
        let original = File::parse(original.as_slice()).unwrap();
        assert_eq!(
            compare_allocated_sections(&original, &File::parse(zero.as_slice()).unwrap()).unwrap(),
            2
        );
        assert!(
            compare_allocated_sections(&original, &File::parse(nonzero.as_slice()).unwrap())
                .is_err()
        );
    }

    #[test]
    fn rejects_dropped_allocation_flag() {
        let original = sample(&[1, 2, 3, 4], None, false);
        let mut unallocated = original.clone();
        let file = File::parse(unallocated.as_slice()).unwrap();
        let index = file.section_by_name(".text").unwrap().index().0;
        let shoff = u64::from_be_bytes(unallocated[40..48].try_into().unwrap()) as usize;
        let entsize = u16::from_be_bytes(unallocated[58..60].try_into().unwrap()) as usize;
        let offset = shoff + index * entsize + 8;
        unallocated[offset..offset + 8].fill(0);
        let original = File::parse(original.as_slice()).unwrap();
        assert!(
            compare_allocated_sections(&original, &File::parse(unallocated.as_slice()).unwrap())
                .is_err()
        );
    }
}
