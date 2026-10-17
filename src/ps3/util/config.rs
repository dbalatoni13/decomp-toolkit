//! DTK-compatible symbols.txt and splits.txt handling for PS3 PPU ELFs.
//! The formats are kept so existing project configurations remain editable.

use std::{collections::HashMap, fs, io::Write};

use anyhow::{Context, Result, bail, ensure};
use flagset::FlagSet;
use typed_path::Utf8NativePath;

use crate::ps3::obj::{
    ObjInfo, ObjSectionKind, ObjSplit, ObjSymbolFlagSet, ObjSymbolFlags, ObjSymbolKind, ObjUnit,
};

fn parse_number(value: &str) -> Result<u32> {
    Ok(if let Some(hex) = value.strip_prefix("0x").or_else(|| value.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16)?
    } else {
        value.parse()?
    })
}

fn attrs(text: &str) -> impl Iterator<Item = &str> {
    text.split_whitespace().filter(|attr| !attr.is_empty())
}

fn symbol_kind(kind: &str) -> Result<ObjSymbolKind> {
    Ok(match kind {
        "function" => ObjSymbolKind::Function,
        "object" => ObjSymbolKind::Object,
        "section" => ObjSymbolKind::Section,
        "label" => ObjSymbolKind::Unknown,
        _ => bail!("Unknown symbol type {kind}"),
    })
}

fn symbol_kind_name(kind: ObjSymbolKind) -> &'static str {
    match kind {
        ObjSymbolKind::Function => "function",
        ObjSymbolKind::Object => "object",
        ObjSymbolKind::Section => "section",
        ObjSymbolKind::Unknown => "label",
    }
}

fn section_kind(kind: &str) -> Result<ObjSectionKind> {
    Ok(match kind {
        "code" => ObjSectionKind::Code,
        "data" => ObjSectionKind::Data,
        "rodata" => ObjSectionKind::ReadOnlyData,
        "bss" => ObjSectionKind::Bss,
        _ => bail!("Unknown section type {kind}"),
    })
}

fn section_kind_name(kind: ObjSectionKind) -> &'static str {
    match kind {
        ObjSectionKind::Code => "code",
        ObjSectionKind::Data => "data",
        ObjSectionKind::ReadOnlyData => "rodata",
        ObjSectionKind::Bss => "bss",
    }
}

pub fn write_symbols_file(path: &Utf8NativePath, obj: &ObjInfo) -> Result<()> {
    let mut symbols: Vec<_> = obj.symbols.iter().map(|(_, symbol)| symbol).collect();
    symbols.sort_by_key(|symbol| (symbol.section, symbol.address));
    let mut out = Vec::new();
    for symbol in symbols {
        write_symbol(&mut out, obj, symbol)?;
    }
    fs::write(path, out)?;
    Ok(())
}

/// Add inferred labels without overwriting hand-edited DTK symbol definitions.
pub fn append_symbols_file(
    path: &Utf8NativePath,
    obj: &ObjInfo,
    symbols: &[crate::ps3::obj::ObjSymbol],
) -> Result<()> {
    let mut out = fs::OpenOptions::new().append(true).open(path)?;
    for symbol in symbols {
        write_symbol(&mut out, obj, symbol)?;
    }
    Ok(())
}

fn write_symbol(
    out: &mut impl Write,
    obj: &ObjInfo,
    symbol: &crate::ps3::obj::ObjSymbol,
) -> Result<()> {
    if symbol.kind == ObjSymbolKind::Section {
        return Ok(());
    }
    write!(out, "{} = ", symbol.name)?;
    if let Some(index) = symbol.section {
        write!(out, "{}:", obj.sections[index].name)?;
    }
    write!(out, "{:#010X}; // type:{}", symbol.address, symbol_kind_name(symbol.kind))?;
    if symbol.size_known && symbol.size > 0 {
        write!(out, " size:{:#X}", symbol.size)?;
    }
    if symbol.flags.is_local() {
        write!(out, " scope:local")?;
    } else if symbol.flags.is_weak() {
        write!(out, " scope:weak")?;
    } else if symbol.flags.0.contains(ObjSymbolFlags::Global) {
        write!(out, " scope:global")?;
    }
    if let Some(align) = symbol.align {
        write!(out, " align:{align}")?;
    }
    writeln!(out)?;
    Ok(())
}

pub fn apply_symbols_file(path: &Utf8NativePath, obj: &mut ObjInfo) -> Result<()> {
    if !fs::metadata(path).is_ok_and(|m| m.is_file()) {
        return Ok(());
    }
    // Names alone are not unique in linked C++ executables (e.g. local
    // constructors in different translation units). Match the exact symbol
    // definition instead of moving the last same-named symbol to every
    // address found in symbols.txt.
    let mut definitions = HashMap::new();
    for (i, sym) in obj.symbols.iter() {
        definitions.insert((sym.name.clone(), sym.section, sym.address), i);
    }
    for (line_no, raw) in fs::read_to_string(path)?.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
            continue;
        }
        let (name, rest) = line
            .split_once('=')
            .with_context(|| format!("{}:{}: Invalid symbol definition", path, line_no + 1))?;
        let name = name.trim();
        let (location, metadata) = rest
            .split_once(';')
            .with_context(|| format!("{}:{}: Missing semicolon", path, line_no + 1))?;
        let location = location.trim();
        let (section, address_text) = if let Some((section, address)) = location.split_once(':') {
            let index = obj
                .sections
                .iter()
                .find(|(_, s)| s.name == section.trim())
                .with_context(|| format!("Unknown symbol section {section}"))?
                .0;
            (Some(index), address.trim())
        } else {
            (None, location)
        };
        let address = u64::from(parse_number(address_text)?);
        let key = (name.to_owned(), section, address);
        let mut symbol =
            definitions.get(&key).and_then(|&id| obj.symbols.get(id)).cloned().unwrap_or_default();
        symbol.name = name.to_owned();
        symbol.address = address;
        symbol.section = section;
        for attr in attrs(metadata.trim().trim_start_matches("//")) {
            if let Some((key, value)) = attr.split_once(':') {
                match key {
                    "type" => symbol.kind = symbol_kind(value)?,
                    "size" => {
                        symbol.size = u64::from(parse_number(value)?);
                        symbol.size_known = true;
                    }
                    "scope" => {
                        symbol.flags = ObjSymbolFlagSet(match value {
                            "local" => FlagSet::from(ObjSymbolFlags::Local),
                            "weak" => FlagSet::from(ObjSymbolFlags::Weak),
                            "global" => FlagSet::from(ObjSymbolFlags::Global),
                            _ => bail!("Unknown symbol scope {value}"),
                        })
                    }
                    "align" => symbol.align = Some(parse_number(value)?),
                    // DTK metadata unrelated to ELF relinking is preserved in the
                    // original text file but not needed for the PPU object writer.
                    "data" | "hash" | "dhash" => {}
                    _ => bail!("Unknown symbol attribute {key}"),
                }
            } else if !matches!(
                attr,
                "hidden" | "force_active" | "stripped" | "noreloc" | "noexport"
            ) {
                bail!("Unknown symbol attribute {attr}");
            }
        }
        if let Some(&id) = definitions.get(&key) {
            *obj.symbols.get_mut(id).unwrap() = symbol;
        } else {
            definitions.insert(key, obj.symbols.len() as u32);
            obj.symbols.push(symbol);
        }
    }
    Ok(())
}

pub fn write_splits_file(path: &Utf8NativePath, obj: &ObjInfo) -> Result<()> {
    let mut out = Vec::new();
    writeln!(out, "Sections:")?;
    for (_, section) in obj.sections.iter() {
        writeln!(
            out,
            "\t{:<11} type:{} align:{}",
            section.name,
            section_kind_name(section.kind),
            section.align
        )?;
    }
    for unit in &obj.link_order {
        write!(out, "\n{}:", unit.name)?;
        if let Some(version) = unit.comment_version {
            write!(out, " comment:{version}")?;
        }
        if let Some(order) = unit.order {
            write!(out, " order:{order}")?;
        }
        writeln!(out)?;
        for (_, section) in obj.sections.iter() {
            for (start, split) in section.splits.iter().filter(|(_, split)| split.unit == unit.name)
            {
                write!(
                    out,
                    "\t{:<11} start:{:#010X} end:{:#010X}",
                    section.name, start, split.end
                )?;
                if let Some(align) = split.align {
                    write!(out, " align:{align}")?;
                }
                if split.common {
                    write!(out, " common")?;
                }
                if let Some(rename) = &split.rename {
                    write!(out, " rename:{rename}")?;
                }
                if split.skip {
                    write!(out, " skip")?;
                }
                writeln!(out)?;
            }
        }
    }
    fs::write(path, out)?;
    Ok(())
}

pub fn apply_splits_file(path: &Utf8NativePath, obj: &mut ObjInfo) -> Result<()> {
    if !fs::metadata(path).is_ok_and(|m| m.is_file()) {
        return Ok(());
    }
    obj.link_order.clear();
    let indices: Vec<_> = obj.sections.iter().map(|(i, _)| i).collect();
    for index in indices {
        obj.sections[index].splits.clear();
    }
    let mut unit: Option<String> = None;
    let mut section_header = false;
    let mut header_index = 0u32;
    for (line_no, raw) in fs::read_to_string(path)?.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with("//") || line.starts_with('#') {
            continue;
        }
        if line == "Sections:" {
            section_header = true;
            unit = None;
            continue;
        }
        if !raw.starts_with('\t')
            && !raw.starts_with(' ')
            && line.contains(':')
            && !line.contains("start:")
            && !line.contains("type:")
        {
            let (name, metadata) = line.split_once(':').unwrap();
            let mut new_unit = ObjUnit {
                name: name.to_owned(),
                autogenerated: name.starts_with("auto_"),
                comment_version: None,
                order: None,
            };
            for attr in attrs(metadata) {
                if let Some(value) = attr.strip_prefix("comment:") {
                    new_unit.comment_version = Some(value.parse()?);
                } else if let Some(value) = attr.strip_prefix("order:") {
                    new_unit.order = Some(value.parse()?);
                } else {
                    bail!("Unknown unit attribute {attr}");
                }
            }
            unit = Some(name.to_owned());
            section_header = false;
            obj.link_order.push(new_unit);
            continue;
        }
        let mut words = attrs(line);
        let name = words.next().context("Missing section name")?;
        if section_header {
            let section = obj
                .sections
                .get_mut(header_index)
                .with_context(|| format!("{}:{}: Too many sections", path, line_no + 1))?;
            ensure!(section.name == name, "Section {} differs from input {}", name, section.name);
            for attr in words {
                if let Some(value) = attr.strip_prefix("type:") {
                    section.kind = section_kind(value)?;
                } else if let Some(value) = attr.strip_prefix("align:") {
                    section.align = u64::from(parse_number(value)?);
                } else if !attr.starts_with("vaddr:") {
                    bail!("Unknown section attribute {attr}");
                }
            }
            header_index += 1;
            continue;
        }
        let unit = unit
            .as_ref()
            .with_context(|| format!("{}:{}: Split without unit", path, line_no + 1))?;
        let index = obj
            .sections
            .iter()
            .find(|(_, section)| section.name == name)
            .with_context(|| format!("Unknown split section {name}"))?
            .0;
        let mut start = None;
        let mut end = None;
        let mut split = ObjSplit {
            unit: unit.clone(),
            end: 0,
            align: None,
            common: false,
            // Generated auto_* units stay autogenerated after loading an
            // existing splits.txt. Otherwise size limits cannot be applied
            // when refreshing older projects.
            autogenerated: unit.starts_with("auto_"),
            skip: false,
            rename: None,
        };
        for attr in words {
            if let Some(value) = attr.strip_prefix("start:") {
                start = Some(parse_number(value)?);
            } else if let Some(value) = attr.strip_prefix("end:") {
                end = Some(parse_number(value)?);
            } else if let Some(value) = attr.strip_prefix("align:") {
                split.align = Some(parse_number(value)?);
            } else if let Some(value) = attr.strip_prefix("rename:") {
                split.rename = Some(value.to_owned());
            } else if attr == "common" {
                split.common = true;
            } else if attr == "skip" {
                split.skip = true;
            } else {
                bail!("Unknown split attribute {attr}");
            }
        }
        let start = start.context("Missing split start")?;
        split.end = end.context("Missing split end")?;
        let section = &obj.sections[index];
        ensure!(
            u64::from(start) >= section.address
                && u64::from(split.end) <= section.address + section.size
                && split.end > start,
            "Split {}: invalid {} {start:#X}..{:#X}",
            unit,
            name,
            split.end
        );
        obj.sections[index].splits.push(start, split);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ps3::obj::{ObjArchitecture, ObjKind, ObjSection, ObjSymbol};

    #[test]
    fn same_named_symbols_keep_their_own_addresses_and_metadata() {
        let section = ObjSection {
            name: ".text".into(),
            kind: ObjSectionKind::Code,
            address: 0x1000,
            size: 0x2000,
            data: vec![0; 0x2000],
            align: 4,
            elf_index: 1,
            splits: Default::default(),
        };
        let mut obj = ObjInfo::new(
            ObjKind::Executable,
            ObjArchitecture::PowerPc64,
            "test".into(),
            vec![
                ObjSymbol {
                    name: "repeated".into(),
                    address: 0x1000,
                    section: Some(0),
                    kind: ObjSymbolKind::Function,
                    size: 4,
                    size_known: true,
                    ..Default::default()
                },
                ObjSymbol {
                    name: "repeated".into(),
                    address: 0x2000,
                    section: Some(0),
                    kind: ObjSymbolKind::Function,
                    size: 8,
                    size_known: true,
                    ..Default::default()
                },
            ],
            vec![section],
        );
        let path = std::env::temp_dir().join(format!(
            "kevin-symbol-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        fs::write(&path, "repeated = .text:0x1000; // type:function size:0x10\nrepeated = .text:0x2000; // type:function size:0x20\n").unwrap();
        let result = apply_symbols_file(Utf8NativePath::new(path.to_str().unwrap()), &mut obj);
        let _ = fs::remove_file(&path);
        result.unwrap();
        let definitions: Vec<_> = obj
            .symbols
            .iter()
            .filter(|(_, s)| s.name == "repeated")
            .map(|(_, s)| (s.address, s.size))
            .collect();
        assert_eq!(definitions, [(0x1000, 16), (0x2000, 32)]);
    }

    #[test]
    fn loading_existing_splits_retains_generated_unit_identity() {
        let section = ObjSection {
            name: ".text".into(),
            kind: ObjSectionKind::Code,
            address: 0x1000,
            size: 0x2000,
            data: vec![0; 0x2000],
            align: 4,
            elf_index: 1,
            splits: Default::default(),
        };
        let mut obj = ObjInfo::new(
            ObjKind::Executable,
            ObjArchitecture::PowerPc64,
            "test".into(),
            vec![],
            vec![section],
        );
        let path = std::env::temp_dir().join(format!(
            "kevin-splits-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        fs::write(&path,
            "Sections:\n\t.text type:code align:4\n\nauto_00_00001000_text:\n\t.text start:0x1000 end:0x2000\n\nmanual.cpp:\n\t.text start:0x2000 end:0x3000\n"
        ).unwrap();
        let result = apply_splits_file(Utf8NativePath::new(path.to_str().unwrap()), &mut obj);
        let _ = fs::remove_file(path);
        result.unwrap();
        assert!(
            obj.sections[0]
                .splits
                .iter()
                .find(|(start, _)| *start == 0x1000)
                .unwrap()
                .1
                .autogenerated
        );
        assert!(
            !obj.sections[0]
                .splits
                .iter()
                .find(|(start, _)| *start == 0x2000)
                .unwrap()
                .1
                .autogenerated
        );
    }
}
