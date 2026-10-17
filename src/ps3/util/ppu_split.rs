//! PS3 PPU ELF64 executable splitting using DTK's symbol and split formats.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    fs,
    path::{Component, Path},
};

use anyhow::{Context, Result, bail, ensure};
use flagset::Flags;
use indexmap::IndexMap;
use object::{
    Architecture, BinaryFormat, Endianness, File, FileFlags, Object, ObjectSection, ObjectSymbol,
    RelocationFlags, SectionFlags, SectionKind, SymbolKind, SymbolScope, elf,
    write::{Object as WriteObject, Relocation, SectionId, Symbol, SymbolId, SymbolSection},
};
use serde::{Deserialize, Serialize};
use typed_path::Utf8NativePath;

use crate::ps3::{
    obj::{
        ObjArchitecture, ObjInfo, ObjKind, ObjSection, ObjSectionKind, ObjSplit, ObjSymbol,
        ObjSymbolFlagSet, ObjSymbolFlags, ObjSymbolKind, ObjUnit,
    },
    util::{
        config::{
            append_symbols_file, apply_splits_file, apply_symbols_file, write_splits_file,
            write_symbols_file,
        },
        ppu::PpuOpd,
        ppu_dwarf::{
            CompilationUnitRange, StaticVariable, compilation_unit_ranges, line_numbers,
            static_variables,
        },
        ppu_reloc::{Descriptor, piece_at, reconstruct_relocations},
        signatures,
    },
};

fn project_relative(path: &Utf8NativePath, base: &Utf8NativePath) -> Result<String> {
    let path = fs::canonicalize(path.as_str())?;
    let base = fs::canonicalize(base.as_str())?;
    let path_components: Vec<_> = path.components().collect();
    let base_components: Vec<_> = base.components().collect();
    let shared = path_components.iter().zip(&base_components).take_while(|(a, b)| a == b).count();
    if shared == 0 {
        return Ok(path.to_string_lossy().into_owned());
    }
    let mut relative = std::path::PathBuf::new();
    for _ in shared..base_components.len() {
        relative.push("..");
    }
    for component in &path_components[shared..] {
        relative.push(component.as_os_str());
    }
    Ok(relative.to_string_lossy().into_owned())
}

pub(super) fn project_path(config_path: &Utf8NativePath, value: &str) -> typed_path::Utf8NativePathBuf {
    let path = Utf8NativePath::new(value);
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        config_path.parent().unwrap_or(Utf8NativePath::new(".")).join(path)
    }
}

/// Preserve the original unit layout for the symbol-aware multi-TOC linker.
/// Use exactly the same capability test during configuration and linking.
fn symbol_aware_multi_toc_supported(toc_count: usize, line_count: usize, symbol_count: usize) -> bool {
    toc_count > 1 && line_count >= 1024 && symbol_count >= 1024
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ElfProjectConfig {
    pub object: String,
    pub symbols: String,
    pub splits: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
}

/// Fill a missing SHA-1 without rewriting the user's other YAML fields or
/// comments. Existing non-null hashes are intentionally not refreshed: `verify`
/// must still detect an input ELF that differs from the project's baseline.
fn populate_missing_config_hash(
    config_path: &Utf8NativePath,
    original_path: &Utf8NativePath,
    config: &mut ElfProjectConfig,
) -> Result<()> {
    if config.hash.is_some() {
        return Ok(());
    }
    let mut input = fs::File::open(original_path)?;
    let sha1 = crate::cmd::shasum::file_sha1_string(&mut input)?;
    let contents = fs::read_to_string(config_path)?;
    let yaml: serde_yaml::Value = serde_yaml::from_str(&contents)?;
    let has_hash = yaml
        .as_mapping()
        .is_some_and(|mapping| mapping.contains_key("hash"));

    let updated = if has_hash {
        // The hash is present but null (e.g. `hash:` or `hash: null`).
        // Modify just that line, preserving every other field and comment.
        let mut found = false;
        let mut result = String::with_capacity(contents.len() + sha1.len());
        for line in contents.split_inclusive('\n') {
            let body = line.trim_end_matches('\n').trim_end_matches('\r');
            let (key, value) = body.split_once(':').unwrap_or(("", ""));
            if !found && key.trim() == "hash" && !key.starts_with([' ', '\t']) {
                let (value, comment) = value.split_once('#').unwrap_or((value, ""));
                ensure!(
                    matches!(value.trim(), "" | "null" | "Null" | "NULL" | "~"),
                    "Cannot update non-null hash in {config_path}"
                );
                result.push_str(&format!("hash: {sha1}"));
                if !comment.is_empty() {
                    result.push_str(" #");
                    result.push_str(comment);
                }
                if line.ends_with("\r\n") {
                    result.push_str("\r\n");
                } else if line.ends_with('\n') {
                    result.push('\n');
                }
                found = true;
            } else {
                result.push_str(line);
            }
        }
        ensure!(found, "Cannot safely update null hash field in {config_path}");
        result
    } else {
        let mut result = contents;
        if !result.ends_with('\n') && !result.is_empty() {
            result.push('\n');
        }
        result.push_str(&format!("hash: {sha1}\n"));
        result
    };
    fs::write(config_path, updated)?;
    config.hash = Some(sha1);
    Ok(())
}

pub fn read_elf(path: &Utf8NativePath) -> Result<Vec<u8>> {
    let mut bytes = fs::read(path).with_context(|| format!("Reading {path}"))?;
    if bytes.len() >= 64
        && bytes.starts_with(b"\x7fELF")
        && bytes[4] == 2
        && bytes[5] == 2
        && u16::from_be_bytes([bytes[18], bytes[19]]) == elf::EM_PPC64
    {
        let header_offset = u64::from_be_bytes(bytes[40..48].try_into()?);
        let header_len = u64::from(u16::from_be_bytes(bytes[58..60].try_into()?))
            * u64::from(u16::from_be_bytes(bytes[60..62].try_into()?));
        let pad = (8 - header_offset % 8) % 8;
        if pad != 0 && header_offset.checked_add(header_len) == Some(bytes.len() as u64) {
            // TODO: Upstream support for unaligned ELF64 section headers to the `object` crate.
            // Some PS3 linkers place section headers at 4-byte-aligned offsets.
            bytes.splice(
                header_offset as usize..header_offset as usize,
                std::iter::repeat_n(0, pad as usize),
            );
            bytes[40..48].copy_from_slice(&(header_offset + pad).to_be_bytes());
        }
    }
    if bytes.len() >= 64
        && bytes.starts_with(b"\x7fELF")
        && bytes[4] == 2
        && bytes[5] == 2
        && u16::from_be_bytes([bytes[18], bytes[19]]) == elf::EM_PPC64
    {
        let shoff = u64::from_be_bytes(bytes[40..48].try_into()?) as usize;
        let count = u16::from_be_bytes(bytes[60..62].try_into()?) as usize;
        let entry_size = u16::from_be_bytes(bytes[58..60].try_into()?) as usize;
        ensure!(
            entry_size == 64
                && shoff <= bytes.len()
                && count.checked_mul(entry_size).is_some_and(|n| n <= bytes.len() - shoff),
            "Invalid PPU ELF section table"
        );
        for i in 0..count {
            let sh = shoff + i * entry_size;
            let sh_type = u32::from_be_bytes(bytes[sh + 4..sh + 8].try_into()?);
            if !matches!(sh_type, elf::SHT_SYMTAB | elf::SHT_DYNSYM) {
                continue;
            }
            let offset = u64::from_be_bytes(bytes[sh + 24..sh + 32].try_into()?) as usize;
            let size = u64::from_be_bytes(bytes[sh + 32..sh + 40].try_into()?) as usize;
            if offset % 8 == 0 {
                continue;
            }
            ensure!(
                offset.checked_add(size).is_some_and(|end| end <= bytes.len()),
                "Invalid PPU ELF symbol table range"
            );
            let aligned = (bytes.len() + 7) & !7;
            let copy = bytes[offset..offset + size].to_vec();
            bytes.resize(aligned, 0);
            bytes.extend_from_slice(&copy);
            bytes[sh + 24..sh + 32].copy_from_slice(&(aligned as u64).to_be_bytes());
        }
    }
    Ok(bytes)
}

pub fn load(path: &Utf8NativePath) -> Result<ObjInfo> {
    let bytes = read_elf(path)?;
    let file = File::parse(bytes.as_slice()).context("Parsing PPU ELF")?;
    load_file(path, &file)
}

/// Decode the section and symbol model from an already parsed ELF, avoiding
/// a second full-file read during both configuration and object generation.
fn load_file(path: &Utf8NativePath, file: &File<'_>) -> Result<ObjInfo> {
    ensure!(
        file.architecture() == Architecture::PowerPc64
            && file.is_64()
            && file.endianness() == Endianness::Big,
        "Expected big-endian PPC64 ELF"
    );
    ensure!(file.kind() == object::ObjectKind::Executable, "Expected executable ELF");
    let mut sections = Vec::new();
    let mut indices = HashMap::new();
    for section in file.sections() {
        let alloc = matches!(section.flags(), SectionFlags::Elf { sh_flags }
            if sh_flags & u64::from(elf::SHF_ALLOC) != 0);
        if !alloc || section.size() == 0 {
            continue;
        }
        ensure!(
            section.address().checked_add(section.size()).is_some_and(|end| end <= u32::MAX as u64),
            "PPU section {} exceeds the 32-bit PS3 address space",
            section.name()?
        );
        let name = section.name()?.to_owned();
        let kind = if section.kind() == SectionKind::UninitializedTls
            || section.kind() == SectionKind::UninitializedData
            || section.data()?.is_empty()
        {
            ObjSectionKind::Bss
        } else {
            match section.kind() {
                SectionKind::Text => ObjSectionKind::Code,
                SectionKind::UninitializedData | SectionKind::UninitializedTls => {
                    ObjSectionKind::Bss
                }
                SectionKind::ReadOnlyData => ObjSectionKind::ReadOnlyData,
                _ => ObjSectionKind::Data,
            }
        };
        let data = if kind == ObjSectionKind::Bss { vec![] } else { section.data()?.to_vec() };
        let i = sections.len() as u32;
        indices.insert(section.index().0, i);
        sections.push(ObjSection {
            name,
            kind,
            address: section.address(),
            size: section.size(),
            data,
            align: section.align().max(1),
            elf_index: section.index().0 as u32,
            splits: Default::default(),
        });
    }
    let mut symbols = Vec::new();
    for symbol in file.symbols() {
        let Some(section) = symbol.section_index().and_then(|i| indices.get(&i.0).copied()) else {
            continue;
        };
        if matches!(symbol.kind(), SymbolKind::Section | SymbolKind::File) {
            continue;
        }
        let name = symbol.name()?;
        if name.is_empty() {
            continue;
        }
        let sec = &sections[section as usize];
        if symbol.address() < sec.address || symbol.address() >= sec.address + sec.size {
            continue;
        }
        let symbol_size = symbol.size().min(sec.address + sec.size - symbol.address());
        let kind = match (symbol.kind(), sec.kind) {
            (SymbolKind::Text, ObjSectionKind::Code) => ObjSymbolKind::Function,
            (SymbolKind::Text, _) | (SymbolKind::Data, _) => ObjSymbolKind::Object,
            _ => ObjSymbolKind::Unknown,
        };
        let mut flags = ObjSymbolFlags::none();
        if symbol.is_global() {
            flags |= ObjSymbolFlags::Global;
        }
        if symbol.is_local() {
            flags |= ObjSymbolFlags::Local;
        }
        if symbol.is_weak() {
            flags |= ObjSymbolFlags::Weak;
        }
        symbols.push(ObjSymbol {
            name: name.to_owned(),
            address: symbol.address(),
            section: Some(section),
            size: symbol_size,
            size_known: symbol_size != 0,
            kind,
            flags: ObjSymbolFlagSet(flags),
            ..Default::default()
        });
    }
    let mut obj = ObjInfo::new(
        ObjKind::Executable,
        ObjArchitecture::PowerPc64,
        path.file_name().unwrap_or("ppu").to_owned(),
        symbols,
        sections,
    );
    obj.entry = Some(file.entry());
    Ok(obj)
}

/// Preserve the directory structure recorded by DWARF while making it a safe,
/// relative output path. `D:\\path\\file.cpp` becomes `path/file.cpp`.
fn source_unit_path(source: &str) -> Option<String> {
    let normalized = source.replace('\\', "/");
    let without_drive = if normalized.as_bytes().get(1) == Some(&b':')
        && normalized.as_bytes()[0].is_ascii_alphabetic()
    {
        &normalized[2..]
    } else {
        &normalized
    };
    let mut parts = Vec::new();
    for part in without_drive.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            _ => parts.push(part),
        }
    }
    if parts.is_empty() || parts.iter().any(|p| p.contains(':') || p.contains('\0')) {
        return None;
    }
    Some(parts.join("/"))
}

fn append_split(
    obj: &mut ObjInfo,
    section_index: u32,
    start: u64,
    end: u64,
    unit: String,
    autogenerated: bool,
) {
    append_split_cached(obj, section_index, start, end, unit, autogenerated, None);
}

fn append_split_cached(
    obj: &mut ObjInfo,
    section_index: u32,
    start: u64,
    end: u64,
    unit: String,
    autogenerated: bool,
    seen: Option<&mut HashSet<String>>,
) {
    let is_new = match seen {
        Some(seen) => seen.insert(unit.clone()),
        None => obj.link_order.iter().all(|u| u.name != unit),
    };
    if is_new {
        obj.link_order.push(ObjUnit {
            name: unit.clone(),
            autogenerated,
            comment_version: None,
            order: None,
        });
    }
    obj.sections.get_mut(section_index).unwrap().splits.push(start as u32, ObjSplit {
        unit,
        end: end as u32,
        align: None,
        common: false,
        autogenerated,
        skip: false,
        rename: None,
    });
}

/// Match DTK's address-based name for an unidentified region. Every separate
/// uncovered range becomes a separate object, rather than combining unrelated
/// bytes into e.g. `sections/text.o`.
fn auto_unit_name(section_index: u32, start: u64, section_name: &str) -> String {
    format!("auto_{section_index:02}_{start:08X}_{}", section_name.trim_start_matches('.'),)
}

/// Use the DWARF CU address ranges as the initial ownership map for executable
/// sections. Shared inline ranges can be present in multiple CUs; the first
/// owner in CU order wins. Uncovered bytes get DTK-style `auto_` units.
fn initialize_source_splits(obj: &mut ObjInfo, ranges: &[CompilationUnitRange]) {
    let mut seen: HashSet<_> = obj.link_order.iter().map(|unit| unit.name.clone()).collect();
    let sections: Vec<_> = obj
        .sections
        .iter()
        .map(|(i, s)| (i, s.address, s.address + s.size, s.name.clone(), s.kind))
        .collect();
    for (section_index, start, end, name, kind) in sections {
        if kind != ObjSectionKind::Code {
            append_split_cached(
                obj, section_index, start, end,
                auto_unit_name(section_index, start, &name), true, Some(&mut seen),
            );
            continue;
        }

        // A sweep-line allows hundreds of interleaved CUs without duplicating
        // executable bytes or generating overlapping split ranges.
        let mut events = BTreeMap::<u64, Vec<(bool, usize)>>::new();
        let mut owners = Vec::<String>::new();
        for range in ranges {
            let lo = start.max(range.start);
            let hi = end.min(range.end);
            if hi <= lo {
                continue;
            }
            let Some(unit) = source_unit_path(&range.source) else {
                continue;
            };
            let id = owners.len();
            owners.push(unit);
            events.entry(lo).or_default().push((true, id));
            events.entry(hi).or_default().push((false, id));
        }
        events.entry(start).or_default();
        events.entry(end).or_default();
        let mut active = BTreeSet::<usize>::new();
        let mut raw = Vec::<(u64, u64, Option<String>)>::new();
        let mut previous = start;
        let mut owner: Option<String> = None;
        for (address, changes) in events {
            if address > previous {
                if let Some((_, prev_end, prev_owner)) = raw.last_mut() {
                    if *prev_end == previous && *prev_owner == owner {
                        *prev_end = address;
                    } else {
                        raw.push((previous, address, owner.clone()));
                    }
                } else {
                    raw.push((previous, address, owner.clone()));
                }
            }
            for (enter, id) in changes {
                if enter {
                    active.insert(id);
                } else {
                    active.remove(&id);
                }
            }
            owner = active.first().map(|&id| owners[id].clone());
            previous = address;
        }

        // A split must never cut through a known function. Drop internal
        // boundaries and let the range containing the function start own it.
        let mut function_spans: Vec<_> = obj
            .symbols
            .iter()
            .filter(|(_, sym)| {
                sym.section == Some(section_index)
                    && sym.kind == ObjSymbolKind::Function
                    && sym.size_known
                    && sym.size > 0
            })
            .map(|(_, sym)| (sym.address, sym.address + sym.size))
            .collect();
        function_spans.sort_unstable();
        let mut merged = Vec::<(u64, u64, Option<String>)>::new();
        let mut current_function = 0;
        let mut function_end = 0;
        for (piece_start, piece_end, piece_owner) in raw {
            while current_function < function_spans.len()
                && function_spans[current_function].0 < piece_start
            {
                function_end = function_end.max(function_spans[current_function].1);
                current_function += 1;
            }
            if let Some((_, last_end, last_owner)) = merged.last_mut() {
                if (*last_owner == piece_owner || piece_start < function_end)
                    && *last_end == piece_start
                {
                    *last_end = piece_end;
                    continue;
                }
            }
            merged.push((piece_start, piece_end, piece_owner));
        }
        // GCC often omits DWARF ranges for `this`-adjusting thunks.
        // A single uncovered range can contain many consecutive 8-byte
        // thunks; associate the *whole range* with its targets only when
        // every instruction pair and every target resolves to the same CU.
        let thunks: BTreeMap<u64, u64> = obj
            .symbols
            .iter()
            .filter(|(_, sym)| {
                sym.section == Some(section_index)
                    && sym.kind == ObjSymbolKind::Function
                    && sym.size_known
                    && sym.size == 8
                    && (sym.name.starts_with("._ZTh") || sym.name.starts_with("._ZTv"))
            })
            .map(|(_, sym)| (sym.address, sym.size))
            .collect();
        let data = &obj.sections.get(section_index).unwrap().data;
        let mut resolved = merged.clone();
        for (i, (lo, hi, source)) in merged.iter().enumerate() {
            if source.is_some() || (hi - lo) % 8 != 0 {
                continue;
            }
            let mut target_source: Option<String> = None;
            let mut address = *lo;
            while address < *hi {
                if !thunks.contains_key(&address) {
                    break;
                }
                let offset = (address - start) as usize;
                let Some(code) = data.get(offset..offset + 8) else {
                    break;
                };
                let Some(destination) = thunk_branch_target(code, address) else {
                    break;
                };
                let index = merged.partition_point(|(_, end, _)| *end <= destination);
                let Some((begin, end, Some(owner))) = merged.get(index) else {
                    break;
                };
                if destination < *begin
                    || destination >= *end
                    || target_source.as_ref().is_some_and(|s| s != owner)
                {
                    break;
                }
                target_source = Some(owner.clone());
                address += 8;
            }
            if address == *hi {
                resolved[i].2 = target_source;
            }
        }
        // Thunks and their target functions may now be adjacent.
        let mut combined = Vec::<(u64, u64, Option<String>)>::new();
        for (lo, hi, source) in resolved {
            if let Some((_, last_end, last_source)) = combined.last_mut()
                && *last_end == lo
                && *last_source == source
            {
                *last_end = hi;
                continue;
            }
            combined.push((lo, hi, source));
        }
        for (lo, hi, source) in combined {
            let autogenerated = source.is_none();
            let unit = source.unwrap_or_else(|| auto_unit_name(section_index, lo, &name));
            append_split_cached(obj, section_index, lo, hi, unit, autogenerated, Some(&mut seen));
        }
    }
}

/// Link the variables' DW_OP_addr locations back to their declaring source
/// objects. Ownership is per contiguous data interval, not per global section.
/// Conflicting CU claims remain in an auto unit; never choose an arbitrary CU.
fn initialize_data_splits(obj: &mut ObjInfo, variables: &[StaticVariable]) {
    let mut seen: HashSet<_> = obj.link_order.iter().map(|unit| unit.name.clone()).collect();
    let mut claims = BTreeMap::<u64, BTreeSet<String>>::new();
    for var in variables {
        if let Some(unit) = source_unit_path(&var.source) {
            claims.entry(var.address).or_default().insert(unit);
        }
    }
    let sections: Vec<_> = obj
        .sections
        .iter()
        .filter(|(_, s)| {
            matches!(
                s.kind,
                ObjSectionKind::Bss | ObjSectionKind::Data | ObjSectionKind::ReadOnlyData
            ) && matches!(
                s.name.as_str(),
                ".data" | ".rodata" | ".bss" | ".data.rel.ro" | ".sdata" | ".sbss"
            )
        })
        .map(|(i, s)| (i, s.address, s.address + s.size, s.name.clone()))
        .collect();
    for (section_index, start, end, name) in sections {
        let mut starts = BTreeMap::<u64, Option<String>>::new();
        for (&addr, sources) in claims.range(start..end) {
            starts.insert(
                addr,
                if sources.len() == 1 { sources.iter().next().cloned() } else { None },
            );
        }
        if starts.is_empty() {
            continue;
        }
        // A split cannot cut through an existing sized symbol. Align claimed
        // boundaries with that symbol's beginning, and reject ambiguous spans.
        let mut spans: Vec<_> = obj
            .symbols
            .iter()
            .filter(|(_, sym)| sym.section == Some(section_index) && sym.size_known && sym.size > 0)
            .map(|(_, sym)| (sym.address, sym.address.saturating_add(sym.size).min(end)))
            .collect();
        spans.sort_unstable();
        let mut owners = BTreeMap::<u64, BTreeSet<String>>::new();
        for (address, owner) in starts {
            let enclosing = spans.partition_point(|(begin, _)| *begin <= address);
            let anchor = spans[..enclosing]
                .iter()
                .rev()
                .find(|(_, limit)| *limit > address)
                .map(|(begin, _)| *begin)
                .unwrap_or(address);
            if let Some(owner) = owner {
                owners.entry(anchor).or_default().insert(owner);
            } else {
                owners.entry(anchor).or_default().insert(String::new());
            }
        }
        let mut segments = Vec::<(u64, u64, Option<String>)>::new();
        let mut cursor = start;
        let mut current: Option<String> = None;
        for (addr, sources) in owners {
            if addr > cursor {
                segments.push((cursor, addr, current.clone()));
            }
            current = if sources.len() == 1 {
                sources.iter().next().filter(|s| !s.is_empty()).cloned()
            } else {
                None
            };
            cursor = addr;
        }
        if cursor < end {
            segments.push((cursor, end, current));
        }
        // Merge adjacent stretches belonging to the same CU.
        let mut merged = Vec::<(u64, u64, Option<String>)>::new();
        for (begin, finish, owner) in segments {
            if begin == finish {
                continue;
            }
            if let Some((_, last_end, last_owner)) = merged.last_mut()
                && *last_end == begin
                && *last_owner == owner
            {
                *last_end = finish;
                continue;
            }
            merged.push((begin, finish, owner));
        }
        obj.sections.get_mut(section_index).unwrap().splits.clear();
        for (begin, finish, owner) in merged {
            let autogenerated = owner.is_none();
            let unit = owner.unwrap_or_else(|| auto_unit_name(section_index, begin, &name));
            append_split_cached(obj, section_index, begin, finish, unit, autogenerated, Some(&mut seen));
        }
    }
}

/// GCC places PPC64 function descriptors in `.opd`. DWARF describes the
/// *code* entrypoint, not the descriptor address, so pair each descriptor's
/// first word with the already attributed executable-section ranges. Keep
/// adjacent descriptors together when their translation-unit owner agrees.
/// Descriptor order is never changed: it determines the linked `.opd` bytes.
fn initialize_opd_splits(obj: &mut ObjInfo, descriptors: &[Descriptor]) -> Result<()> {
    let Some((opd_index, opd_start, opd_end)) = obj
        .sections
        .iter()
        .find(|(_, section)| section.name == ".opd")
        .map(|(index, section)| (index, section.address, section.address + section.size))
    else {
        return Ok(());
    };
    if descriptors.is_empty() {
        return Ok(());
    }
    ensure!(
        descriptors.len() * 8 == (opd_end - opd_start) as usize,
        "OPD descriptor count does not match .opd section size"
    );
    let mut owners = BTreeMap::<u64, (u64, String)>::new();
    for (_, section) in obj.sections.iter() {
        if section.kind != ObjSectionKind::Code {
            continue;
        }
        for (begin, split) in section.splits.iter() {
            owners.insert(u64::from(begin), (u64::from(split.end), split.unit.clone()));
        }
    }
    let fallback = auto_unit_name(opd_index, opd_start, ".opd");
    let mut grouped = Vec::<(u64, u64, String)>::new();
    for (index, descriptor) in descriptors.iter().enumerate() {
        let address = opd_start + (index * 8) as u64;
        ensure!(descriptor.address == address, "Noncontiguous .opd descriptor at {address:#x}");
        let unit = owners
            .range(..=descriptor.code)
            .next_back()
            .filter(|(_, (end, _))| descriptor.code < *end)
            .map(|(_, (_, unit))| unit.clone())
            .unwrap_or_else(|| fallback.clone());
        if let Some((_, end, last_unit)) = grouped.last_mut()
            && *end == address
            && *last_unit == unit
        {
            *end += 8;
        } else {
            grouped.push((address, address + 8, unit));
        }
    }
    obj.sections[opd_index].splits.clear();
    for (begin, end, unit) in grouped {
        let autogenerated = unit.starts_with("auto_");
        append_split(obj, opd_index, begin, end, unit, autogenerated);
    }
    Ok(())
}

/// Linked PS3 ELF output merges per-input `.toc` contributions into `.got`.
/// The linker may have generated multiple TOC groups, each with its own
/// `r2` base at the beginning of that contribution + 0x8000. Recover their
/// exact input boundaries from `.opd` descriptors instead of treating the
/// whole merged .got as a single input TOC (which causes TOC16 overflow).
fn initialize_toc_splits(obj: &mut ObjInfo, descriptors: &[Descriptor]) -> Result<()> {
    let Some((section_index, begin, end)) = obj
        .sections
        .iter()
        .find(|(_, section)| section.name == ".got")
        .map(|(index, section)| (index, section.address, section.address + section.size))
    else {
        return Ok(());
    };
    let mut boundaries = BTreeSet::new();
    for d in descriptors {
        if let Some(base) = d.toc.checked_sub(0x8000)
            && base >= begin
            && base < end
        {
            ensure!(base % 4 == 0, "Unaligned PPU TOC segment {base:#x}");
            boundaries.insert(base);
        }
    }
    if boundaries.is_empty() {
        return Ok(());
    }
    ensure!(
        *boundaries.first().unwrap() == begin,
        "PPU TOC segment does not start at GOT beginning: {begin:#x}"
    );
    // Do not overwrite a manual .got layout, only the synthesized whole-GOT
    // fallback created during `initialize_source_splits`.
    let section = &obj.sections[section_index];
    let current: Vec<_> = section.splits.iter().collect();
    if current.len() != 1
        || u64::from(current[0].0) != begin
        || u64::from(current[0].1.end) != end
        || !current[0].1.unit.starts_with("auto_")
    {
        return Ok(());
    }
    obj.sections[section_index].splits.clear();
    let mut start = begin;
    for next in boundaries.into_iter().skip(1).chain(std::iter::once(end)) {
        append_split(
            obj,
            section_index,
            start,
            next,
            auto_unit_name(section_index, start, "toc"),
            true,
        );
        start = next;
    }
    Ok(())
}

/// Recover the original translation unit of individual TOC slots from the
/// code that refers to them. The linked .got contains consecutive 32-bit TOC
/// entries; function code and DWARF already identify the calling unit.
/// Shared/ambiguous or unreferenced slots remain in automatic objects.
///
/// Only replace our generated auto-TOC layout. User-edited .got splits are
/// authoritative, even when the inferred ownership disagrees.
fn attribute_toc_splits(obj: &mut ObjInfo, descriptors: &[Descriptor]) -> Result<bool> {
    let Some((section_index, start, end)) = obj
        .sections
        .iter()
        .find(|(_, section)| section.name == ".got")
        .map(|(index, section)| (index, section.address, section.address + section.size))
    else {
        return Ok(false);
    };
    let original: Vec<_> = obj.sections[section_index]
        .splits
        .iter()
        .map(|(start, split)| (start, split.clone()))
        .collect();
    if original.is_empty()
        || original.iter().any(|(_, split)| {
            !split.unit.starts_with("auto_")
                || !split.unit.ends_with("_toc")
                || split.rename.is_some()
                || split.align.is_some()
                || split.skip
                || split.common
        })
    {
        return Ok(false);
    }
    ensure!(start % 4 == 0 && end % 4 == 0, "Unaligned PS3 TOC data");
    let text_pieces = compiler_text_sections(obj, pieces(obj)?);
    let (relocations, _) = reconstruct_relocations(obj, &text_pieces, descriptors);
    let mut claims = HashMap::<u64, String>::new();
    let mut ambiguous = BTreeSet::new();
    let mut auto_references = BTreeMap::<String, BTreeMap<u64, usize>>::new();
    for (piece, relocs) in text_pieces.iter().zip(relocations) {
        if obj.sections[piece.original_section].kind != ObjSectionKind::Code {
            continue;
        }
        for reloc in relocs {
            if !matches!(reloc.r_type, elf::R_PPC64_TOC16 | elf::R_PPC64_TOC16_DS)
                || reloc.target < start
                || reloc.target >= end
            {
                continue;
            }
            if piece.unit.starts_with("auto_") {
                *auto_references
                    .entry(piece.unit.clone())
                    .or_default()
                    .entry(reloc.target)
                    .or_default() += 1;
            }
            if let Some(previous) = claims.insert(reloc.target, piece.unit.clone())
                && previous != piece.unit
            {
                ambiguous.insert(reloc.target);
            }
        }
    }
    // A conflict cannot be cleared by a later reference from the first unit.
    for address in &ambiguous {
        claims.remove(address);
    }
    // An automatically attributed text object can exclusively reference
    // *shared* TOC slots, leaving it without a real `.toc`. objdiff ignores
    // empty sections, so a zero-sized placeholder is not enough. In this
    // narrow case, place one already-unattributed shared slot with that auto
    // object. This doesn't assert a false named CU owner and doesn't duplicate
    // any original bytes. The original linked slot order remains unchanged.
    let mut owners_with_toc: BTreeSet<String> = claims.values().cloned().collect();
    for (unit, candidates) in auto_references {
        if owners_with_toc.contains(&unit) {
            continue;
        }
        let choice = candidates
            .iter()
            .filter(|(address, _)| !claims.contains_key(*address))
            .max_by_key(|(address, count)| (**count, std::cmp::Reverse(**address)))
            .map(|(address, _)| *address);
        if let Some(address) = choice {
            claims.insert(address, unit.clone());
            owners_with_toc.insert(unit);
        }
    }
    let mut fragments = Vec::<(u64, u64, Option<String>)>::new();
    for address in (start..end).step_by(4) {
        let owner = claims.get(&address).cloned();
        if let Some((_, finish, previous)) = fragments.last_mut()
            && *finish == address
            && *previous == owner
        {
            *finish += 4;
        } else {
            fragments.push((address, address + 4, owner));
        }
    }
    if fragments.is_empty() {
        return Ok(false);
    }
    if original.len() == fragments.len()
        && original.iter().zip(&fragments).all(|((begin, split), (start, end, owner))| {
            u64::from(*begin) == *start
                && u64::from(split.end) == *end
                && owner.as_ref().is_some_and(|name| *name == split.unit)
        })
    {
        return Ok(false);
    }

    obj.sections[section_index].splits.clear();
    for (begin, end, owner) in fragments {
        let autogenerated = owner.is_none();
        let unit = owner.unwrap_or_else(|| auto_unit_name(section_index, begin, "toc"));
        append_split(obj, section_index, begin, end, unit, autogenerated);
    }
    Ok(true)
}

/// In these linked PS3 ELFs the size on an `.opd` STT_FUNC symbol often
/// describes the function *body* in `.text` (e.g. 0x470), even though an OPD
/// entry is just eight bytes. Respect the size of the descriptor itself when
/// checking object boundaries and writing relocatable ELF symbols.
fn normalize_opd_symbol_sizes(obj: &mut ObjInfo) {
    let opd = obj.sections.iter().find(|(_, s)| s.name == ".opd").map(|(index, _)| index);
    for sym in obj.symbols.iter_mut() {
        if sym.section == opd {
            sym.size = 8;
            sym.size_known = true;
        }
    }
}

pub fn initialize_splits(obj: &mut ObjInfo) {
    // When DWARF ranges are absent, mark each section as one autogenerated unit.
    // This is a conservative fallback until more split boundaries are known.
    let sections: Vec<_> = obj
        .sections
        .iter()
        .map(|(i, s)| (i, s.address, s.address + s.size, s.name.clone()))
        .collect();
    for (section_index, start, end, name) in sections {
        append_split(
            obj,
            section_index,
            start,
            end,
            auto_unit_name(section_index, start, &name),
            true,
        );
    }
}

// Keep fallback ELF inputs comfortably below the PPC64 linker's stub-group
// limit. The on-disk .o also includes ELF symbol and relocation tables,
// sometimes several times larger than the raw data section.
// This is a soft size target: never cut a known function or data symbol.
const MAX_AUTO_TEXT_BYTES: u64 = 256 * 1024;
const MAX_AUTO_DATA_BYTES: u64 = 128 * 1024;

/// Fragment only autogenerated sections. DWARF-owned compilation units and
/// manually configured units must stay intact for source replacement.
/// Function descriptor entrypoints are preferred for executable boundaries;
/// ordinary section alignment is used for data and for code without OPD.
fn limit_automatic_section_sizes(obj: &mut ObjInfo, descriptors: &[Descriptor]) -> usize {
    let mut function_starts: Vec<u64> = descriptors.iter().map(|d| d.code).collect();
    for (_, symbol) in obj.symbols.iter() {
        if symbol.kind == ObjSymbolKind::Function {
            function_starts.push(symbol.address);
        }
    }
    function_starts.sort_unstable();
    function_starts.dedup();

    let mut sized_symbols = BTreeMap::<u32, Vec<(u64, u64)>>::new();
    for (_, symbol) in obj.symbols.iter() {
        if symbol.size_known && symbol.size > 0
            && let Some(section) = symbol.section
            && let Some(end) = symbol.address.checked_add(symbol.size)
        {
            sized_symbols.entry(section).or_default().push((symbol.address, end));
        }
    }
    for values in sized_symbols.values_mut() {
        values.sort_unstable();
    }

    let mut modified = 0;
    let sections: Vec<_> = obj.sections.iter().map(|(i, section)| {
        (i, section.name.clone(), section.kind, section.align)
    }).collect();
    for (index, name, kind, align) in sections {
        let max_bytes = if kind == ObjSectionKind::Code { MAX_AUTO_TEXT_BYTES } else { MAX_AUTO_DATA_BYTES };
        // The OPD and GOT have special linker semantics and dedicated split
        // logic. Embedded SPU images can be split into contiguous byte ranges
        // without changing their linked payload.
        if matches!(name.as_str(), ".opd" | ".got") {
            continue;
        }
        let splits: Vec<_> = obj.sections[index]
            .splits.iter().map(|(start, split)| (u64::from(start), split.clone())).collect();
        if splits.is_empty() {
            continue;
        }
        let mut new_splits = Vec::new();
        let mut changed_section = false;
        for (start, split) in splits {
            let end = u64::from(split.end);
            if end - start <= max_bytes
                || !split.autogenerated || !split.unit.starts_with("auto_")
                || split.rename.is_some() || split.skip || split.common
            {
                new_splits.push((start, end, split.unit.clone(), split.autogenerated));
                continue;
            }
            let step = align.max(4).next_power_of_two();
            let mut cursor = start;
            while end - cursor > max_bytes {
                let target = cursor + max_bytes;
                let mut next = if kind == ObjSectionKind::Code {
                    let first = function_starts.partition_point(|&a| a <= cursor);
                    let last = function_starts.partition_point(|&a| a <= target);
                    let end_index = function_starts.partition_point(|&a| a < end);
                    // Prefer a real function boundary, even if the next
                    // function starts beyond the target. Never cut an
                    // instruction sequence in half just to meet the cap.
                    if last > first {
                        function_starts[last - 1]
                    } else if first < end_index {
                        function_starts[first]
                    } else if function_starts.partition_point(|&a| a < start) == end_index {
                        // No function descriptors in this entire region.
                        (target / step) * step
                    } else {
                        end
                    }
                } else {
                    (target / step) * step
                };
                if next <= cursor {
                    next = target;
                }
                // Never split a known sized symbol across two units.
                if let Some(symbols) = sized_symbols.get(&index) {
                    loop {
                        let previous = next;
                        for &(begin, finish) in symbols {
                            if begin >= next {
                                break;
                            }
                            if begin < next && next < finish {
                                next = finish;
                            }
                        }
                        if previous == next {
                            break;
                        }
                    }
                }
                if next >= end {
                    break;
                }
                new_splits.push((cursor, next,
                    if cursor == start { split.unit.clone() } else { auto_unit_name(index, cursor, &name) },
                    true));
                cursor = next;
            }
            new_splits.push((cursor, end,
                if cursor == start { split.unit.clone() } else { auto_unit_name(index, cursor, &name) },
                true));
            changed_section = true;
            modified += 1;
        }
        if changed_section {
            obj.sections[index].splits.clear();
            for (start, end, unit, auto) in new_splits {
                append_split(obj, index, start, end, unit, auto);
            }
        }
    }
    if modified > 0 {
        let used: BTreeSet<_> = obj.sections.iter()
            .flat_map(|(_, section)| section.splits.iter().map(|(_, split)| split.unit.clone()))
            .collect();
        obj.link_order.retain(|unit| used.contains(&unit.name));
    }
    modified
}

pub fn config_with_signatures(
    input: &Utf8NativePath,
    out: &Utf8NativePath,
    signatures_path: Option<&Utf8NativePath>,
) -> Result<()> {
    let elf_data = read_elf(input)?;
    let file = File::parse(elf_data.as_slice())?;
    let mut obj = load_file(input, &file)?;
    // Some shipped PS3 ELFs contain partial/unsupported SN Systems DWARF.
    // Function descriptors and ELF symbols still permit a correct relink;
    // malformed optional debug metadata must not prevent splitting.
    let ranges = compilation_unit_ranges(&file).unwrap_or_else(|err| {
        eprintln!("Warning: ignoring unusable PPU DWARF CU ranges: {err:#}");
        Vec::new()
    });
    let variables = static_variables(&file).unwrap_or_else(|err| {
        eprintln!("Warning: ignoring unusable PPU DWARF static-variable metadata: {err:#}");
        Vec::new()
    });
    if ranges.is_empty() {
        initialize_splits(&mut obj);
    } else {
        initialize_source_splits(&mut obj, &ranges);
    }
    initialize_data_splits(&mut obj, &variables);
    let opd: Vec<Descriptor> = PpuOpd::parse(&file)?
        .iter()
        .map(|(address, (code, toc))| Descriptor {
            address,
            code: u64::from(code),
            toc: u64::from(toc),
        })
        .collect();
    let divided = limit_automatic_section_sizes(&mut obj, &opd);
    if divided > 0 {
        println!("Divided {divided} oversized automatic sections (256 KiB code, 128 KiB data)");
    }
    initialize_opd_splits(&mut obj, &opd)?;
    initialize_toc_splits(&mut obj, &opd)?;
    fs::create_dir_all(out)?;
    let symbols_path = out.join("symbols.txt");
    let splits_path = out.join("splits.txt");
    let config_path = out.join("config.yml");
    let existing_symbols = fs::metadata(&symbols_path).is_ok_and(|m| m.is_file());
    if existing_symbols {
        apply_symbols_file(&symbols_path, &mut obj)?;
    }
    normalize_opd_symbol_sizes(&mut obj);
    let previously_generated_data: Vec<_> = obj
        .sections
        .iter()
        .filter(|(_, section)| {
            matches!(
                section.name.as_str(),
                ".data"
                    | ".bss"
                    | ".rodata"
                    | ".data.rel.ro"
                    | ".sdata"
                    | ".sbss"
                    | ".opd"
                    | ".got"
            )
        })
        .map(|(i, section)| {
            (
                i,
                section
                    .splits
                    .iter()
                    .map(|(start, split)| (start, split.clone()))
                    .collect::<Vec<_>>(),
            )
        })
        .collect();
    let existing_splits = fs::metadata(&splits_path).is_ok_and(|m| m.is_file());
    let mut upgraded_data = 0;
    let mut resized_existing = 0;
    if existing_splits {
        apply_splits_file(&splits_path, &mut obj)?;
        // Upgrade only whole-section *automatic* data splits. Explicit
        // per-variable/per-CU layouts and manual text splits are untouched.
        for (section_id, inferred) in previously_generated_data {
            let section = &obj.sections[section_id];
            let current: Vec<_> = section.splits.iter().collect();
            if inferred.len() <= 1 || current.len() != 1 {
                continue;
            }
            let (start, split) = current[0];
            if u64::from(start) != section.address
                || u64::from(split.end) != section.address + section.size
                || !split.unit.starts_with("auto_")
                || split.rename.is_some()
                || split.skip
                || split.common
                || split.align.is_some()
            {
                continue;
            }
            obj.sections.get_mut(section_id).unwrap().splits.clear();
            for (start, split) in inferred {
                if !obj.link_order.iter().any(|unit| unit.name == split.unit) {
                    obj.link_order.push(ObjUnit {
                        name: split.unit.clone(),
                        autogenerated: split.autogenerated,
                        comment_version: None,
                        order: None,
                    });
                }
                obj.sections.get_mut(section_id).unwrap().splits.push(start, split);
            }
            upgraded_data += 1;
        }
        if upgraded_data > 0 {
            let used: BTreeSet<String> = obj
                .sections
                .iter()
                .flat_map(|(_, s)| s.splits.iter().map(|(_, split)| split.unit.clone()))
                .collect();
            obj.link_order.retain(|unit| used.contains(&unit.name));
        }
        // Older generated configurations may still contain giant auto_ text
        // objects. The symbol-aware multi-TOC linker path must retain its
        // original unit boundaries: splitting one of those units changes
        // how the SDK linker assigns TOCs and can crash the legacy linker.
        // Fixed-image multi-TOC and ordinary single-TOC targets can safely
        // resize generated units; source-backed/manual units remain intact.
        let toc_count = opd.iter().map(|d| d.toc).collect::<BTreeSet<_>>().len();
        let line_count = if toc_count > 1 && obj.symbols.len() >= 1024 {
            line_numbers(&file).map_or(0, |lines| lines.len())
        } else {
            0
        };
        let symbol_aware_multi_toc =
            symbol_aware_multi_toc_supported(toc_count, line_count, obj.symbols.len());
        if !symbol_aware_multi_toc {
            resized_existing = limit_automatic_section_sizes(&mut obj, &opd);
        }
        if resized_existing > 0 {
            // Regenerate automatic function-descriptor ownership after text
            // fragmentation, but preserve any manually attributed descriptors.
            let automatic_opd = obj.sections.iter().filter(|(_, s)| s.name == ".opd")
                .all(|(_, section)| section.splits.iter().all(|(_, split)| {
                    split.autogenerated && split.rename.is_none() && !split.skip && !split.common
                }));
            if automatic_opd {
                initialize_opd_splits(&mut obj, &opd)?;
            }
            println!("Resized {resized_existing} oversized existing automatic splits");
        }
    }
    // DTK records inferred symbols in symbols.txt at configuration time, so
    // they can be renamed before writing relocatable objects. Do not generate
    // them solely in `elf split`, where they become uneditable.
    let descriptors: Vec<Descriptor> = PpuOpd::parse(&file)?
        .iter()
        .map(|(address, (code, toc))| Descriptor {
            address,
            code: u64::from(code),
            toc: u64::from(toc),
        })
        .collect();
    let database = if let Some(path) = signatures_path {
        if fs::metadata(path)?.is_dir() {
            signatures::load_directory(path)?
        } else {
            signatures::parse(
                &fs::read_to_string(path).with_context(|| format!("Reading signatures {path}"))?,
            )?
        }
    } else {
        signatures::bundled()?
    };
    let recognized = signatures::identify(&mut obj, &database, &PpuOpd::parse(&file)?)?;
    if recognized.report.inserted > 0 || recognized.report.renamed > 0 {
        println!(
            "Signatures: {} names recovered ({} new, {} renamed); {} ambiguous targets",
            recognized.report.inserted + recognized.report.renamed,
            recognized.report.inserted,
            recognized.report.renamed,
            recognized.report.ambiguous
        );
    }
    let address_aliases = name_referenced_data(&mut obj, &descriptors)?;
    let new_labels = infer_relocation_labels(&mut obj, &descriptors)?;
    let attributed_toc = attribute_toc_splits(&mut obj, &descriptors)?;
    if attributed_toc {
        let used: BTreeSet<String> = obj
            .sections
            .iter()
            .flat_map(|(_, section)| section.splits.iter().map(|(_, split)| split.unit.clone()))
            .collect();
        obj.link_order.retain(|unit| used.contains(&unit.name));
    }
    if !existing_symbols {
        write_symbols_file(&symbols_path, &obj)?;
    } else {
        signatures::rename_config_labels(&symbols_path, &recognized.renames)?;
        let mut additions = recognized.added;
        additions.extend(address_aliases);
        additions.extend(new_labels);
        if !additions.is_empty() {
            append_symbols_file(&symbols_path, &obj, &additions)?;
        }
    }
    if !existing_splits || upgraded_data > 0 || resized_existing > 0 || attributed_toc {
        write_splits_file(&splits_path, &obj)?;
        if upgraded_data > 0 {
            println!("Updated {upgraded_data} automatic data sections with DWARF CU ownership");
        }
        if attributed_toc {
            println!("Assigned TOC entries to their referencing compilation units");
        }
    }
    // Preserve user edits in config.yml, but populate the original
    // executable's SHA-1 for new projects and older projects without one.
    // It is *not* a hash of the re-linked, debug-stripped executable.
    let mut config: ElfProjectConfig = if fs::metadata(&config_path).is_ok_and(|m| m.is_file()) {
        serde_yaml::from_slice(&fs::read(&config_path)?)?
    } else {
        let generated = ElfProjectConfig {
            object: project_relative(input, out)?,
            symbols: "symbols.txt".to_string(),
            splits: "splits.txt".to_string(),
            hash: None,
        };
        fs::write(&config_path, serde_yaml::to_string(&generated)?)?;
        generated
    };
    populate_missing_config_hash(&config_path, input, &mut config)?;
    Ok(())
}

/// Cross-object references to static variables must be exported under unique
/// names, and GOT slots should identify the variable they actually contain.
/// A GOT load is *not* a relocation to the variable itself: it addresses an
/// indirection slot. We name that slot rather than falsifying the relocation.
fn name_referenced_data(obj: &mut ObjInfo, descriptors: &[Descriptor]) -> Result<Vec<ObjSymbol>> {
    let code_pieces = compiler_text_sections(obj, pieces(obj)?);
    let (_, targets) = reconstruct_relocations(obj, &code_pieces, descriptors);
    let mut objects = BTreeMap::<u64, &ObjSymbol>::new();
    for (_, sym) in obj.symbols.iter() {
        let Some(index) = sym.section else { continue };
        if obj.sections[index].kind == ObjSectionKind::Code
            || sym.kind != ObjSymbolKind::Object
            || !valid_symbol_name(&sym.name)
        {
            continue;
        }
        let old = objects.entry(sym.address).or_insert(sym);
        if (old.flags.is_local() && !sym.flags.is_local()) || (!old.size_known && sym.size_known) {
            *old = sym;
        }
    }
    let closest = |address: u64| -> Option<&ObjSymbol> {
        if let Some(sym) = objects.get(&address) {
            return Some(*sym);
        }
        let (_, sym) = objects.range(..=address).next_back()?;
        (sym.size_known && address < sym.address + sym.size).then_some(*sym)
    };
    let mut aliases = Vec::new();
    let mut existing: BTreeSet<u64> = obj
        .symbols
        .iter()
        .filter(|(_, sym)| {
            sym.section.is_some() && !sym.flags.is_local() && !sym.name.starts_with("lbl_")
        })
        .map(|(_, s)| s.address)
        .collect();
    let got = obj
        .sections
        .iter()
        .find(|(_, s)| s.name == ".got")
        .map(|(index, s)| (index, s.address, s.address + s.size, s.data.clone()));
    for target in targets {
        if existing.contains(&target) {
            continue;
        }
        let (symbol, prefix, size) = if let Some((_, base, end, ref data)) = got
            && target >= base
            && target + 4 <= end
            && target % 4 == 0
        {
            let offset = (target - base) as usize;
            let value = u64::from(u32::from_be_bytes(data[offset..offset + 4].try_into()?));
            let Some(symbol) = closest(value) else { continue };
            (symbol, "got", 4)
        } else {
            let Some(sym) = closest(target) else { continue };
            // Only a referenced local *base* needs a global alias. Interior
            // addresses will use the base plus a relocation addend instead.
            if sym.address != target || !sym.flags.is_local() {
                continue;
            }
            (sym, "ref", sym.size)
        };
        let sanitized: String = symbol
            .name
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() || c == '_' { c } else { '_' })
            .take(64)
            .collect();
        let name = format!("__{prefix}_{sanitized}_{target:08X}");
        let section = obj
            .sections
            .iter()
            .find(|(_, s)| target >= s.address && target < s.address + s.size)
            .map(|(i, _)| i)
            .context("Missing target section")?;
        let alias = ObjSymbol {
            name,
            address: target,
            section: Some(section),
            size,
            size_known: size > 0,
            kind: ObjSymbolKind::Object,
            flags: ObjSymbolFlagSet(ObjSymbolFlags::Global.into()),
            ..Default::default()
        };
        aliases.push(alias);
        existing.insert(target);
    }
    for sym in &aliases {
        obj.symbols.push(sym.clone());
    }
    Ok(aliases)
}

/// Discover missing relocation targets before generating symbols.txt. Every
/// inserted symbol is globally visible so a branch from another split object
/// can refer to the renamed label. Local-only symbols cannot serve this role.
fn infer_relocation_labels(
    obj: &mut ObjInfo,
    descriptors: &[Descriptor],
) -> Result<Vec<ObjSymbol>> {
    let mut new_labels = Vec::new();
    // Adding a label can reveal further address references in pointer tables.
    // Repeat until the same target set is reconstructed by `elf config` and
    // `elf split` after the labels are applied.
    loop {
        let ranges = compiler_text_sections(obj, pieces(obj)?);
        let (_, targets) = reconstruct_relocations(obj, &ranges, descriptors);
        let starts: BTreeMap<_, _> = ranges.iter().enumerate().map(|(i, p)| (p.start, i)).collect();
        let mut available = BTreeSet::new();
        let mut used_names = BTreeSet::new();
        for (_, symbol) in obj.symbols.iter() {
            used_names.insert(symbol.name.clone());
            if symbol.flags.is_local() || !valid_symbol_name(&symbol.name) {
                continue;
            }
            let Some(index) = piece_at(&starts, &ranges, symbol.address) else {
                continue;
            };
            if symbol.section == Some(ranges[index].original_section) {
                available.insert(symbol.address);
            }
        }
        let mut batch = Vec::new();
        for address in targets.difference(&available) {
            let Some(index) = piece_at(&starts, &ranges, *address) else {
                continue;
            };
            let name = format!("lbl_{address:08X}");
            ensure!(
                used_names.insert(name.clone()),
                "Inferred label {name} conflicts with a different existing symbol"
            );
            batch.push(ObjSymbol {
                name,
                address: *address,
                section: Some(ranges[index].original_section),
                kind: ObjSymbolKind::Unknown,
                flags: ObjSymbolFlagSet(ObjSymbolFlags::Global.into()),
                ..Default::default()
            });
        }
        if batch.is_empty() {
            break;
        }
        for symbol in &batch {
            obj.symbols.push(symbol.clone());
        }
        new_labels.extend(batch);
    }
    Ok(new_labels)
}

#[derive(Debug, Clone)]
pub(super) struct Piece {
    pub(super) original_section: u32,
    pub(super) start: u64,
    pub(super) end: u64,
    pub(super) unit: String,
    pub(super) align: u64,
    pub(super) name: String,
}

fn pieces(obj: &ObjInfo) -> Result<Vec<Piece>> {
    let mut result = Vec::new();
    for (index, section) in obj.sections.iter() {
        let mut ranges: Vec<_> = section.splits.iter().collect();
        ranges.sort_by_key(|(start, _)| *start);
        let mut current = section.address;
        for (start, split) in ranges {
            if split.skip {
                bail!("Skipping allocated bytes is not supported in PPU split: {}", section.name);
            }
            let start = u64::from(start);
            let end = u64::from(split.end);
            ensure!(
                start == current && end > start && end <= section.address + section.size,
                "Incomplete/overlapping split {} @ {start:#x}, expected {current:#x}",
                section.name
            );
            result.push(Piece {
                original_section: index,
                start,
                end,
                unit: split.unit.clone(),
                align: u64::from(split.align.unwrap_or(section.align as u32)),
                name: split.rename.clone().unwrap_or_else(|| {
                    if section.name == ".eh_frame" {
                        ".kevin.eh_frame".to_string()
                    } else {
                        section.name.clone()
                    }
                }),
            });
            current = end;
        }
        ensure!(
            current == section.address + section.size,
            "Section {} not fully covered: {current:#x} < {:#x}",
            section.name,
            section.address + section.size
        );
    }
    // Index ranges by section once. Scanning every piece for every sized
    // symbol is quadratic on large PPU executables with dense symbol tables.
    let mut by_section = HashMap::<u32, Vec<(u64, u64)>>::new();
    for piece in &result {
        by_section.entry(piece.original_section).or_default().push((piece.start, piece.end));
    }
    for ranges in by_section.values_mut() {
        ranges.sort_unstable_by_key(|(start, _)| *start);
    }
    for (_, symbol) in obj.symbols.iter() {
        if !matches!(symbol.kind, ObjSymbolKind::Function | ObjSymbolKind::Object)
            || !symbol.size_known
            || symbol.size == 0
        {
            continue;
        }
        let Some(section_index) = symbol.section else {
            continue;
        };
        let Some(ranges) = by_section.get(&section_index) else { continue };
        let next = ranges.partition_point(|(start, _)| *start <= symbol.address);
        if let Some(&(start, end)) = next.checked_sub(1).and_then(|i| ranges.get(i))
            && symbol.address >= start && symbol.address < end
        {
            ensure!(
                symbol.address.checked_add(symbol.size).is_some_and(|symbol_end| symbol_end <= end),
                "Split cuts through sized symbol {} at {:#X}",
                symbol.name,
                end
            );
        }
    }
    Ok(result)
}

/// Use GCC's named-section convention when reconstructing source objects.
///
/// The main translation-unit code stays in `.text`. GCC 4.0.2 generates
/// `.gnu.linkonce.t.<symbol>` for one-only C++ functions, often including
/// their adjusting thunks in the same section. The linked executable has
/// lost the exact input-section headers, so boundaries here are inferred
/// conservatively from surviving weak function symbols.
fn compiler_text_sections(obj: &ObjInfo, pieces: Vec<Piece>) -> Vec<Piece> {
    let mut functions = BTreeMap::<u32, Vec<&ObjSymbol>>::new();
    for (_, symbol) in obj.symbols.iter() {
        if symbol.kind == ObjSymbolKind::Function && symbol.size_known && symbol.size > 0 {
            if let Some(index) = symbol.section {
                functions.entry(index).or_default().push(symbol);
            }
        }
    }
    for values in functions.values_mut() {
        values.sort_by_key(|sym| sym.address);
    }
    let mut out = Vec::new();
    for piece in pieces {
        if piece.name != ".text" {
            out.push(piece);
            continue;
        }
        let Some(all) = functions.get(&piece.original_section) else {
            out.push(piece);
            continue;
        };
        let first = all.partition_point(|s| s.address < piece.start);
        let last = all.partition_point(|s| s.address < piece.end);
        let symbols = &all[first..last];
        if !symbols.iter().any(|sym| sym.flags.is_weak()) {
            out.push(piece);
            continue;
        }
        let mut starts = BTreeMap::<u64, (bool, &str, u64)>::new();
        // Multiple constructor/destructor aliases can have the same address.
        for sym in symbols {
            let entry =
                starts.entry(sym.address).or_insert((sym.flags.is_weak(), &sym.name, sym.size));
            entry.2 = entry.2.max(sym.size);
            if (entry.1.starts_with("._ZTh") || entry.1.starts_with("._ZTv"))
                && !sym.name.starts_with("._ZTh")
                && !sym.name.starts_with("._ZTv")
            {
                entry.0 = sym.flags.is_weak();
                entry.1 = &sym.name;
            }
        }
        let bounds: Vec<_> =
            starts.iter().map(|(&addr, &(weak, name, size))| (addr, weak, name, size)).collect();
        // GCC can place the entire sequence of consecutive adjusting thunks
        // and the weak target method in one link-once section. Don't split
        // that sequence into artificial sections at each 8-byte instruction.
        let mut grouped = BTreeSet::new();
        let source = &obj.sections[piece.original_section];
        for (i, &(target, weak, name, _)) in bounds.iter().enumerate() {
            if !weak || name.starts_with("._ZTh") || name.starts_with("._ZTv") {
                continue;
            }
            let mut j = i;
            while j > 0 && bounds[j - 1].0 + 8 == bounds[j].0 {
                let (address, thunk_weak, thunk_name, size) = bounds[j - 1];
                if !thunk_weak
                    || size != 8
                    || !(thunk_name.starts_with("._ZTh") || thunk_name.starts_with("._ZTv"))
                {
                    break;
                }
                let offset = (address - source.address) as usize;
                let Some(code) = source.data.get(offset..offset + 8) else {
                    break;
                };
                if thunk_branch_target(code, address) != Some(target) {
                    break;
                }
                j -= 1;
            }
            if j < i {
                grouped.extend(bounds[j + 1..=i].iter().map(|&(addr, _, _, _)| addr));
            }
        }
        let mut boundaries = vec![piece.start];
        let mut current_weak =
            bounds.first().is_some_and(|(addr, weak, _, _)| *addr == piece.start && *weak);
        let mut function_end = piece.start;
        for &(addr, weak, _, size) in &bounds {
            if addr > piece.start && addr >= function_end {
                if (weak || current_weak != weak) && !grouped.contains(&addr) {
                    boundaries.push(addr);
                }
                current_weak = weak;
            }
            function_end = function_end.max(addr + size);
        }
        boundaries.push(piece.end);
        for pair in boundaries.windows(2) {
            let (start, end) = (pair[0], pair[1]);
            let mut segment = piece.clone();
            segment.start = start;
            segment.end = end;
            // `bounds` is sorted. Scanning every symbol for each fragment
            // makes large linked .text sections quadratic (5039 has tens of
            // thousands of fragments).
            let first = bounds.partition_point(|(address, _, _, _)| *address < start);
            let last = bounds.partition_point(|(address, _, _, _)| *address < end);
            let local = &bounds[first..last];
            if let Some((_, true, symbol, _)) = local.first()
            {
                // Name the section after the actual method, not a prefix
                // thunk, when the code shares one link-once section.
                let name = local
                    .iter()
                    .find(|(_, _, n, _)| !(n.starts_with("._ZTh") || n.starts_with("._ZTv")))
                    .map_or(*symbol, |(_, _, name, _)| *name);
                segment.name = format!(".gnu.linkonce.t.{}", name.trim_start_matches('.'));
            } else {
                segment.name = ".text".into();
            }
            out.push(segment);
        }
    }
    out
}

/// Decode the narrow two-instruction thunk emitted by PS3 GCC. A return-by-
/// structure function adjusts r4 rather than r3.
fn thunk_branch_target(code: &[u8], address: u64) -> Option<u64> {
    let first = u32::from_be_bytes(code.get(..4)?.try_into().ok()?);
    let second = u32::from_be_bytes(code.get(4..8)?.try_into().ok()?);
    let reg = (first >> 21) & 31;
    if first >> 26 != 14 || !matches!(reg, 3 | 4) || (first >> 16) & 31 != reg || second >> 26 != 18
    {
        return None;
    }
    let displacement = ((second << 6) as i32 >> 6) as i64 & !3;
    let target = if second & 2 != 0 { displacement } else { address as i64 + 4 + displacement };
    u64::try_from(target).ok()
}

fn section_kind(kind: ObjSectionKind) -> SectionKind {
    match kind {
        ObjSectionKind::Code => SectionKind::Text,
        ObjSectionKind::ReadOnlyData => SectionKind::ReadOnlyData,
        ObjSectionKind::Bss => SectionKind::UninitializedData,
        ObjSectionKind::Data => SectionKind::Data,
    }
}

fn valid_symbol_name(name: &str) -> bool { !name.is_empty() && !name.as_bytes().contains(&0) }

/// An ELF relocatable input must contain the *unlinked* PPC branch operand.
/// The source executable contains the resolved PC-relative displacement;
/// retaining it alongside R_PPC64_REL24 produces an invalid negative `bl`
/// destination when objdiff disassembles a section starting at address zero,
/// and the linker would apply the displacement a second time.
/// Preserve the opcode, AA/LK bits, and conditional branch BO/BI fields.
fn clear_relocated_branch_operand(data: &mut [u8], offset: u64, r_type: u32) -> Result<()> {
    let (mask, opcode) = match r_type {
        elf::R_PPC64_REL24 => (0x03ff_fffc, 18),
        elf::R_PPC64_ADDR24 => (0x03ff_fffc, 18),
        elf::R_PPC64_REL14 => (0x0000_fffc, 16),
        elf::R_PPC64_ADDR14 => (0x0000_fffc, 16),
        _ => return Ok(()),
    };
    let offset = usize::try_from(offset)?;
    ensure!(offset % 4 == 0, "Unaligned PPC branch relocation at {offset:#x}");
    let word = data.get_mut(offset..offset + 4).context("Branch relocation outside section")?;
    let ins = u32::from_be_bytes(word.try_into()?);
    ensure!(ins >> 26 == opcode, "Branch relocation targets non-branch {ins:#010x}");
    ensure!(
        (ins & 2 == 0) == matches!(r_type, elf::R_PPC64_REL24 | elf::R_PPC64_REL14),
        "Branch AA flag contradicts relocation kind at {offset:#x}"
    );
    word.copy_from_slice(&(ins & !mask).to_be_bytes());
    Ok(())
}

fn output_name(unit: &str) -> Result<String> {
    let path = Path::new(unit);
    ensure!(
        !path.is_absolute()
            && path.components().all(|c| matches!(c, Component::Normal(_) | Component::CurDir)),
        "Unsafe unit path: {unit}"
    );
    Ok(if unit.ends_with(".o") { unit.to_string() } else { format!("{unit}.o") })
}

/// Emit an independent DWARF2 line table for each extracted compilation unit.
/// Objdiff reads the *first* DWARF CU and associates each line sequence with
/// the next input text section. Use one sequence for every code section,
/// including pieces without line rows, to keep their indices aligned.
/// Each sequence starts at section-relative offset zero. No addresses from
/// the original linked executable may leak into the relocatable objects.
fn add_unit_line_numbers(
    writer: &mut WriteObject,
    unit_name: &str,
    code_ranges: &[(u64, u64)],
    original_lines: &BTreeMap<u64, u32>,
) -> Result<()> {
    if original_lines.is_empty() || code_ranges.is_empty() {
        return Ok(());
    }
    let has_lines = code_ranges
        .iter()
        .any(|&(start, end)| original_lines.range(start..end).next().is_some());
    if !has_lines {
        return Ok(());
    }
    use gimli::write::{Address, DwarfUnit, EndianVec, LineProgram, LineString, Sections};
    let encoding = gimli::Encoding {
        format: gimli::Format::Dwarf32,
        version: 2,
        address_size: 8,
    };
    let mut line_program = LineProgram::new(
        encoding,
        gimli::LineEncoding::default(),
        LineString::String(b".".to_vec()),
        None,
        LineString::String(unit_name.as_bytes().to_vec()),
        None,
    );
    // In DWARF2, the primary file is explicitly added to the file table.
    let source_file = line_program.add_file(
        LineString::String(unit_name.as_bytes().to_vec()),
        line_program.default_directory(),
        None,
    );
    for &(start, end) in code_ranges {
        line_program.begin_sequence(Some(Address::Constant(0)));
        for (&address, &line) in original_lines.range(start..end) {
            let row = line_program.row();
            row.address_offset = address - start;
            row.file = source_file;
            row.line = u64::from(line);
            line_program.generate_row();
        }
        line_program.end_sequence(end - start);
    }
    let mut dwarf = DwarfUnit::new(encoding);
    dwarf.unit.line_program = line_program;
    let mut sections = Sections::new(EndianVec::new(gimli::BigEndian));
    dwarf.write(&mut sections)?;
    for (name, data) in [
        (".debug_info", sections.debug_info.slice()),
        (".debug_abbrev", sections.debug_abbrev.slice()),
        (".debug_line", sections.debug_line.slice()),
    ] {
        if !data.is_empty() {
            let id = writer.add_section(Vec::new(), name.as_bytes().to_vec(), SectionKind::Debug);
            writer.append_section_data(id, data, 1);
        }
    }
    Ok(())
}

/// PPC64 ELFs with several original TOC bases cannot reliably be re-linked
/// using inferred TOC16 / cross-TOC call relocations: the SDK linker chooses
/// different TOC groups and introduces new stubs. Emit a separate fixed-image
/// reference for those builds, without changing the relocation-bearing object
/// used by objdiff and source matching. This is still an ELF relocatable input
/// to the original linker, but its allocated bytes have already been bound.
fn fixed_image_reference(
    relocatable: &[u8],
    indexes: &[usize],
    pieces: &[Piece],
    section_names: &[String],
    obj: &ObjInfo,
) -> Result<Vec<u8>> {
    let file = File::parse(relocatable)?;
    let mut patches = Vec::new();
    for &index in indexes {
        let piece = &pieces[index];
        let original = &obj.sections[piece.original_section];
        if original.kind == ObjSectionKind::Bss {
            continue;
        }
        let section = file
            .section_by_name(&section_names[index])
            .with_context(|| format!("Missing reference section {}", section_names[index]))?;
        let (file_offset, file_size) = section
            .file_range()
            .with_context(|| format!("Section {} has no file data", section_names[index]))?;
        let start = usize::try_from(piece.start - original.address)?;
        let size = usize::try_from(piece.end - piece.start)?;
        ensure!(file_size == size as u64, "Reference section size changed");
        let data = original
            .data
            .get(start..start + size)
            .with_context(|| format!("Missing original bytes for {}", section_names[index]))?;
        patches.push((usize::try_from(file_offset)?, data));
    }
    let mut fixed = relocatable.to_vec();
    for (offset, data) in patches {
        fixed[offset..offset + data.len()].copy_from_slice(data);
    }
    // ELF64 big-endian section headers are 64 bytes. Invalidate REL(A)
    // headers, not the symbol table: the linker still needs the original
    // function symbols for ENTRY and for source object substitution.
    let shoff = usize::try_from(u64::from_be_bytes(fixed[40..48].try_into()?))?;
    let shentsize = usize::from(u16::from_be_bytes(fixed[58..60].try_into()?));
    let shnum = usize::from(u16::from_be_bytes(fixed[60..62].try_into()?));
    ensure!(shentsize == 64, "Expected ELF64 section headers");
    ensure!(
        shoff.checked_add(shentsize * shnum).is_some_and(|end| end <= fixed.len()),
        "Invalid reference section headers"
    );
    for i in 0..shnum {
        let offset = shoff + i * shentsize + 4;
        let kind = u32::from_be_bytes(fixed[offset..offset + 4].try_into()?);
        if matches!(kind, elf::SHT_RELA | elf::SHT_REL) {
            fixed[offset..offset + 4].copy_from_slice(&elf::SHT_NULL.to_be_bytes());
        }
    }
    Ok(fixed)
}

/// Link reference for multi-TOC binaries with enough source metadata to
/// retain the actual relocation-bearing ELF rather than a frozen image.
/// The original executable contains linker-resolved branches and r2-relative
/// displacements. Until the original TOC partitions can be reproduced, keep
/// those operands, but preserve other relocations (including .opd function
/// pointers and data references). The SDK accepts a single TOC with per-OPD
/// marker addends to reconstruct the original per-function r2 values.
fn symbol_aware_link_reference(
    relocatable: &[u8],
    indexes: &[usize],
    pieces: &[Piece],
    section_names: &[String],
    obj: &ObjInfo,
    descriptors: &[Descriptor],
    first_toc: u64,
) -> Result<Vec<u8>> {
    let mut output = relocatable.to_vec();
    let shoff = usize::try_from(u64::from_be_bytes(output[40..48].try_into()?))?;
    let entsize = usize::from(u16::from_be_bytes(output[58..60].try_into()?));
    let count = usize::from(u16::from_be_bytes(output[60..62].try_into()?));
    let names_index = usize::from(u16::from_be_bytes(output[62..64].try_into()?));
    ensure!(entsize == 64 && names_index < count, "Invalid PPC64 section table");
    ensure!(
        shoff.checked_add(count * entsize).is_some_and(|end| end <= output.len()),
        "PPC64 section headers outside file"
    );
    let name_hdr = shoff + names_index * entsize;
    let name_start =
        usize::try_from(u64::from_be_bytes(output[name_hdr + 24..name_hdr + 32].try_into()?))?;
    let name_size =
        usize::try_from(u64::from_be_bytes(output[name_hdr + 32..name_hdr + 40].try_into()?))?;
    let names = output
        .get(name_start..name_start + name_size)
        .context("Invalid PPC64 section names")?
        .to_vec();
    let mut section_names_by_index = Vec::with_capacity(count);
    for i in 0..count {
        let header = shoff + i * entsize;
        let offset = usize::try_from(u32::from_be_bytes(output[header..header + 4].try_into()?))?;
        let name = names
            .get(offset..)
            .and_then(|rest| rest.split(|&byte| byte == 0).next())
            .context("Invalid PPC64 section name offset")?;
        section_names_by_index.push(String::from_utf8_lossy(name).into_owned());
    }
    let piece_for_name: HashMap<_, _> =
        indexes.iter().map(|&i| (section_names[i].as_str(), &pieces[i])).collect();
    let original_opd_tocs: BTreeMap<_, _> =
        descriptors.iter().map(|d| (d.address, d.toc)).collect();
    for section_index in 0..count {
        let header = shoff + section_index * entsize;
        let kind = u32::from_be_bytes(output[header + 4..header + 8].try_into()?);
        if kind != elf::SHT_RELA {
            continue;
        }
        let target_index =
            usize::try_from(u32::from_be_bytes(output[header + 44..header + 48].try_into()?))?;
        let Some(name) = section_names_by_index.get(target_index) else { continue };
        let Some(piece) = piece_for_name.get(name.as_str()) else { continue };
        let source = &obj.sections[piece.original_section];
        let start =
            usize::try_from(u64::from_be_bytes(output[header + 24..header + 32].try_into()?))?;
        let size =
            usize::try_from(u64::from_be_bytes(output[header + 32..header + 40].try_into()?))?;
        ensure!(
            size % 24 == 0 && start.checked_add(size).is_some_and(|end| end <= output.len()),
            "Invalid PPC64 RELA entries"
        );
        let target_hdr = shoff + target_index * entsize;
        let target_start = usize::try_from(u64::from_be_bytes(
            output[target_hdr + 24..target_hdr + 32].try_into()?,
        ))?;
        let mut kept = Vec::with_capacity(size);
        for at in (start..start + size).step_by(24) {
            let reloc_offset = u64::from_be_bytes(output[at..at + 8].try_into()?);
            let info = u64::from_be_bytes(output[at + 8..at + 16].try_into()?);
            let relocation_type = info as u32;
            let is_branch = matches!(
                relocation_type,
                elf::R_PPC64_REL24 | elf::R_PPC64_REL14 | elf::R_PPC64_ADDR24 | elf::R_PPC64_ADDR14
            );
            let is_toc = matches!(relocation_type, elf::R_PPC64_TOC16 | elf::R_PPC64_TOC16_DS);
            if source.kind == ObjSectionKind::Code && (is_branch || is_toc) {
                if is_branch {
                    let pos = usize::try_from(reloc_offset)?;
                    let original_pos =
                        usize::try_from(piece.start - source.address + reloc_offset)?;
                    let restored = source
                        .data
                        .get(original_pos..original_pos + 4)
                        .context("Branch outside original PPU section")?
                        .to_vec();
                    let write_at = target_start + pos;
                    output
                        .get_mut(write_at..write_at + 4)
                        .context("Branch outside linked reference")?
                        .copy_from_slice(&restored);
                }
                continue;
            }
            let mut entry = output[at..at + 24].to_vec();
            if source.name == ".opd"
                && relocation_type == elf::R_PPC64_TLSGD
                && reloc_offset % 8 == 4
            {
                let descriptor_address = piece.start + reloc_offset - 4;
                let toc = original_opd_tocs.get(&descriptor_address).with_context(|| {
                    format!("Missing PPU descriptor at {descriptor_address:#x}")
                })?;
                let addend = i64::try_from(*toc)? - i64::try_from(first_toc)?;
                entry[16..24].copy_from_slice(&addend.to_be_bytes());
            }
            kept.extend_from_slice(&entry);
        }
        output[start..start + kept.len()].copy_from_slice(&kept);
        output[header + 32..header + 40].copy_from_slice(&(kept.len() as u64).to_be_bytes());
    }
    Ok(output)
}

pub fn split(config_path: &Utf8NativePath, out: &Utf8NativePath) -> Result<()> {
    let mut config: ElfProjectConfig = serde_yaml::from_slice(&fs::read(config_path)?)?;
    let object_path = project_path(config_path, &config.object);
    populate_missing_config_hash(config_path, &object_path, &mut config)?;
    let bytes = read_elf(&object_path)?;
    let file = File::parse(bytes.as_slice())?;
    let mut obj = load_file(&object_path, &file)?;
    apply_symbols_file(&project_path(config_path, &config.symbols), &mut obj)?;
    normalize_opd_symbol_sizes(&mut obj);
    apply_splits_file(&project_path(config_path, &config.splits), &mut obj)?;
    let pieces = compiler_text_sections(&obj, pieces(&obj)?);
    let mut section_name_counts = HashMap::<(String, String), usize>::new();
    for piece in &pieces {
        *section_name_counts.entry((piece.unit.clone(), piece.name.clone())).or_default() += 1;
    }
    // objdiff expects an actual `.toc` section in the calling object. The
    // first contiguous TOC contribution keeps that canonical name. Further
    // disjoint contributions are address-qualified so the linker script can
    // place every interval in its exact original order.
    let mut first_toc = BTreeSet::new();
    let output_sections: Vec<String> = pieces
        .iter()
        .map(|piece| {
            if piece.name == ".got" {
                if first_toc.insert(piece.unit.clone()) {
                    ".toc".to_owned()
                } else {
                    format!(".toc.{:08X}", piece.start)
                }
            } else if section_name_counts[&(piece.unit.clone(), piece.name.clone())] > 1 {
                format!("{}.{:08X}", piece.name, piece.start)
            } else {
                piece.name.clone()
            }
        })
        .collect();
    let mut by_unit: IndexMap<String, Vec<usize>> = IndexMap::new();
    for (i, piece) in pieces.iter().enumerate() {
        by_unit.entry(piece.unit.clone()).or_default().push(i);
    }
    let original_lines = line_numbers(&file).unwrap_or_else(|err| {
        eprintln!("Warning: ignoring unusable PPU DWARF line numbers: {err:#}");
        BTreeMap::new()
    });
    let descriptors: Vec<Descriptor> = PpuOpd::parse(&file)?
        .iter()
        .map(|(address, (code, toc))| Descriptor {
            address,
            code: u64::from(code),
            toc: u64::from(toc),
        })
        .collect();
    let mut anchors = BTreeMap::<u64, String>::new();
    for d in descriptors.iter() {
        anchors.entry(d.toc).or_insert_with(|| format!("__kevin_toc_{:08X}", d.toc));
    }
    // EBOOT has extensive DWARF and named ELF symbols. Use an ordinary,
    // relocation-bearing link reference instead of freezing all the input
    // sections. Sparse-DWARF multi-TOC targets retain the conservative
    // fixed-image fallback until their TOC/call provenance can be recovered.
    let symbol_aware_multi_toc =
        symbol_aware_multi_toc_supported(anchors.len(), original_lines.len(), obj.symbols.len());
    let needs_fixed_references = anchors.len() > 1 && !symbol_aware_multi_toc;
    let (relocations, targets) = reconstruct_relocations(&obj, &pieces, &descriptors);
    let starts: BTreeMap<u64, usize> =
        pieces.iter().enumerate().map(|(i, p)| (p.start, i)).collect();
    // Use existing externally visible symbols for cross-object relocations.
    // A linked function's code-entry symbol (e.g. `._Z...`) is already in
    // the input symbol table, so an address-only alias is unnecessary.
    // Local symbols cannot be referenced from another relocatable object.
    let mut global_targets = HashMap::<u64, String>::new();
    let mut global_score = HashMap::<u64, u8>::new();
    let mut global_data_cover = BTreeMap::<u64, (u64, String)>::new();
    for (_, symbol) in obj.symbols.iter() {
        if symbol.flags.is_local() || !valid_symbol_name(&symbol.name) {
            continue;
        }
        let Some(piece_index) = piece_at(&starts, &pieces, symbol.address) else { continue };
        if symbol.section != Some(pieces[piece_index].original_section) {
            continue;
        }
        let score = if symbol.name.starts_with("lbl_") {
            0
        } else if symbol.name.starts_with("__got_") || symbol.name.starts_with("__ref_") {
            3
        } else {
            2
        };
        if symbol.kind == ObjSymbolKind::Object
            && symbol.size_known
            && symbol.size > 0
            && !symbol.name.starts_with("lbl_")
        {
            global_data_cover
                .insert(symbol.address, (symbol.address + symbol.size, symbol.name.clone()));
        }
        if targets.contains(&symbol.address)
            && global_score.get(&symbol.address).is_none_or(|&old| score > old)
        {
            global_targets.insert(symbol.address, symbol.name.clone());
            global_score.insert(symbol.address, score);
        }
    }
    let mut targets_by_piece = vec![Vec::new(); pieces.len()];
    for target in targets {
        // The entrypoint in link.ld still needs a defined synthetic anchor;
        // otherwise create anchors only for addresses without global names.
        if (target == obj.entry.unwrap_or_default() || !global_targets.contains_key(&target))
            && let Some(index) = piece_at(&starts, &pieces, target)
        {
            targets_by_piece[index].push(target);
        }
    }
    // Each symbol has one owning fragment. Index it once rather than scanning
    // every symbol against every fragment in every object (particularly slow
    // for large CUs with many GCC link-once sections).
    let mut symbols_by_piece = vec![Vec::<&ObjSymbol>::new(); pieces.len()];
    for (_, symbol) in obj.symbols.iter() {
        if let Some(index) = piece_at(&starts, &pieces, symbol.address)
            && symbol.section == Some(pieces[index].original_section)
        {
            symbols_by_piece[index].push(symbol);
        }
    }
    let mut generated = BTreeSet::<String>::new();
    fs::create_dir_all(out.join("obj"))?;
    if needs_fixed_references {
        fs::create_dir_all(out.join("obj_link"))?;
    }
    if symbol_aware_multi_toc {
        fs::create_dir_all(out.join("obj_relink"))?;
    }
    let mut order = String::new();
    for (unit, indexes) in &by_unit {
        let mut writer =
            WriteObject::new(BinaryFormat::Elf, Architecture::PowerPc64, Endianness::Big);
        // PS3 GCC 4.1.1 emits 0x01000000 for PowerPC64 ELFv1 relocatable
        // objects. The final executable clears this flag, but the original
        // linker expects it on its inputs.
        writer.flags = FileFlags::Elf { os_abi: 0x66, abi_version: 0, e_flags: 0x01000000 };
        let mut ids = HashMap::<usize, SectionId>::new();
        for &piece_index in indexes {
            let piece = &pieces[piece_index];
            let source = &obj.sections[piece.original_section];
            let original_section =
                file.section_by_index(object::SectionIndex(source.elf_index as usize))?;
            let original_kind = original_section.kind();
            let out_kind = match original_kind {
                SectionKind::Tls => SectionKind::Tls,
                SectionKind::UninitializedTls => SectionKind::UninitializedTls,
                _ => section_kind(source.kind),
            };
            let id = writer.add_section(
                Vec::new(),
                output_sections[piece_index].as_bytes().to_vec(),
                out_kind,
            );
            writer.section_mut(id).flags = original_section.flags();
            let size = piece.end - piece.start;
            let mut align = piece.align.max(1).next_power_of_two();
            while align > 1 && piece.start % align != 0 {
                align /= 2;
            }
            if source.kind == ObjSectionKind::Bss {
                writer.append_section_bss(id, size, align);
            } else if source.name == ".opd" {
                // GCC emits zero-initialized descriptor words. Its linked
                // executable contains the code address and TOC base, but
                // those values belong to the linker's .rela.opd handling,
                // not to the input object's initial section bytes.
                writer.append_section_data(id, &vec![0; size as usize], align);
            } else {
                let start = (piece.start - source.address) as usize;
                ensure!(
                    source.data.len() >= start + size as usize,
                    "Section {} has no data for range {:#x}..{:#x} ({} bytes, kind {:?})",
                    source.name,
                    piece.start,
                    piece.end,
                    source.data.len(),
                    source.kind
                );
                writer.append_section_data(id, &source.data[start..start + size as usize], align);
            }
            ids.insert(piece_index, id);
        }
        // GCC may use a TOC slot emitted by a different object. An object
        // containing TOC16 relocations still needs its own (possibly empty)
        // `.toc` section for PowerPC64 analysis tools such as objdiff.
        if indexes.iter().any(|&i| {
            relocations[i]
                .iter()
                .any(|r| matches!(r.r_type, elf::R_PPC64_TOC16 | elf::R_PPC64_TOC16_DS))
        }) && !indexes.iter().any(|&i| output_sections[i] == ".toc")
        {
            writer.add_section(Vec::new(), b".toc".to_vec(), SectionKind::Data);
        }
        let mut emitted = HashMap::<u64, SymbolId>::new();
        let mut emitted_score = HashMap::<u64, u8>::new();
        let mut emitted_names = BTreeSet::<String>::new();
        // Resolve addresses to original symbols, or synthetic cross-unit symbols.
        for &piece_index in indexes {
            let piece = &pieces[piece_index];
            for symbol in &symbols_by_piece[piece_index] {
                if !valid_symbol_name(&symbol.name) {
                    continue;
                }
                let section = ids[&piece_index];
                let id = writer.add_symbol(Symbol {
                    name: symbol.name.as_bytes().to_vec(),
                    value: symbol.address - piece.start,
                    size: symbol.size.min(piece.end - symbol.address),
                    kind: if piece.name == ".opd" || symbol.kind == ObjSymbolKind::Unknown {
                        SymbolKind::Label
                    } else if obj.sections[piece.original_section].kind == ObjSectionKind::Code {
                        SymbolKind::Text
                    } else {
                        SymbolKind::Data
                    },
                    scope: if symbol.flags.is_local() {
                        SymbolScope::Compilation
                    } else {
                        // Keep ELF default visibility for original global names.
                        SymbolScope::Dynamic
                    },
                    weak: symbol.flags.is_weak(),
                    section: SymbolSection::Section(section),
                    flags: object::SymbolFlags::None,
                });
                emitted_names.insert(symbol.name.clone());
                let score = if symbol.name.starts_with("lbl_") {
                    0
                } else if symbol.flags.is_local() {
                    1
                } else if symbol.name.starts_with("__got_") || symbol.name.starts_with("__ref_") {
                    3
                } else {
                    2
                };
                if emitted_score.get(&symbol.address).is_none_or(|&old| score > old) {
                    emitted.insert(symbol.address, id);
                    emitted_score.insert(symbol.address, score);
                }
            }
        }
        for &piece_index in indexes {
            let p = &pieces[piece_index];
            for &address in &targets_by_piece[piece_index] {
                let label = format!("lbl_{address:08X}");
                // The stripped input has already inferred `lbl_<entry>` in
                // symbols.txt. Do not define that same global a second time:
                // the original PS3 linker rejects duplicate input symbols
                // even when both definitions point to the same address.
                if !emitted_names.insert(label.clone()) {
                    continue;
                }
                let id = writer.add_symbol(Symbol {
                    name: label.into_bytes(),
                    value: address - p.start,
                    size: 0,
                    kind: SymbolKind::Label,
                    scope: SymbolScope::Linkage,
                    weak: false,
                    section: SymbolSection::Section(ids[&piece_index]),
                    flags: object::SymbolFlags::None,
                });
                // Do not replace an original function/data symbol at this
                // address with a synthetic label for same-object references.
                emitted.entry(address).or_insert(id);
            }
        }
        let mut externs = HashMap::<u64, SymbolId>::new();
        for &piece_index in indexes {
            let section_id = ids[&piece_index];
            for reloc in &relocations[piece_index] {
                // References into an existing data object should use the
                // object's name plus the interior offset, not lbl_<address>.
                let (target, interior) = if global_targets.contains_key(&reloc.target) {
                    (reloc.target, 0)
                } else if let Some((&base, (end, _))) =
                    global_data_cover.range(..=reloc.target).next_back()
                    && reloc.target < *end
                {
                    (base, (reloc.target - base) as i64)
                } else {
                    (reloc.target, 0)
                };
                let symbol = if let Some(&id) = emitted.get(&target) {
                    id
                } else {
                    *externs.entry(target).or_insert_with(|| {
                        writer.add_symbol(Symbol {
                            name: global_targets
                                .get(&target)
                                .or_else(|| global_data_cover.get(&target).map(|(_, n)| n))
                                .cloned()
                                .unwrap_or_else(|| format!("lbl_{target:08X}"))
                                .into_bytes(),
                            value: 0,
                            size: 0,
                            kind: SymbolKind::Unknown,
                            scope: SymbolScope::Linkage,
                            weak: false,
                            section: SymbolSection::Undefined,
                            flags: object::SymbolFlags::None,
                        })
                    })
                };
                writer.add_relocation(section_id, Relocation {
                    offset: reloc.offset,
                    symbol,
                    addend: reloc.addend + interior,
                    flags: RelocationFlags::Elf { r_type: reloc.r_type },
                })?;
                clear_relocated_branch_operand(
                    writer.section_mut(section_id).data_mut(),
                    reloc.offset,
                    reloc.r_type,
                )?;
            }
        }
        // Nonallocated DWARF metadata must not alter section placement or
        // the byte-exact executable-image verification.
        let text_ranges: Vec<_> = indexes
            .iter()
            .filter_map(|&i| {
                (obj.sections[pieces[i].original_section].kind == ObjSectionKind::Code)
                    .then_some((pieces[i].start, pieces[i].end))
            })
            .collect();
        add_unit_line_numbers(&mut writer, unit, &text_ranges, &original_lines)?;
        let mut output = writer.write()?;
        fix_sdk_opd_markers(&mut output)?;
        let out_name = output_name(unit)?;
        if needs_fixed_references {
            let fixed = fixed_image_reference(&output, indexes, &pieces, &output_sections, &obj)?;
            let fixed_path = out.join("obj_link").join(&out_name);
            if let Some(parent) = fixed_path.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(fixed_path, fixed)?;
        }
        if symbol_aware_multi_toc {
            let linkable = symbol_aware_link_reference(
                &output, indexes, &pieces, &output_sections, &obj,
                &descriptors, *anchors.first_key_value().unwrap().0,
            )?;
            let path = out.join("obj_relink").join(&out_name);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(path, linkable)?;
        }
        ensure!(generated.insert(out_name.clone()), "Duplicate output object");
        let path = out.join("obj").join(&out_name);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, output)?;
        order.push_str(&format!("obj/{out_name} # {unit}\n"));
    }
    fs::write(out.join("link_order.txt"), order)?;
    // Use the same DTK build manifest as `dol split`. The downstream project
    // generator selects between the extracted object listed here and a
    // separately compiled replacement without touching the reference object.
    let units = by_unit
        .iter()
        .map(|(unit, indexes)| {
            let mut code_size = 0u32;
            let mut data_size = 0u32;
            for &index in indexes {
                let piece = &pieces[index];
                let size = u32::try_from(piece.end - piece.start)?;
                if obj.sections[piece.original_section].kind == ObjSectionKind::Code {
                    code_size = code_size.checked_add(size).context("Code size overflow")?;
                } else {
                    data_size = data_size.checked_add(size).context("Data size overflow")?;
                }
            }
            let generated_name = output_name(unit)?;
            Ok(crate::cmd::dol::OutputUnit {
                object: typed_path::Utf8UnixPathBuf::from(format!("{out}/obj/{generated_name}")),
                name: unit.clone(),
                autogenerated: obj
                    .link_order
                    .iter()
                    .find(|entry| entry.name == *unit)
                    .is_some_and(|entry| entry.autogenerated),
                code_size,
                data_size,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    fs::write(
        out.join("toc_bases.txt"),
        anchors.iter().map(|(a, n)| format!("{n} = {a:#X}\n")).collect::<String>(),
    )?;
    let entry = obj.entry.unwrap_or_default();
    let entry_name =
        global_targets.get(&entry).cloned().unwrap_or_else(|| format!("lbl_{entry:08X}"));
    // Keep the original section layout separate from the selected object
    // paths. The build system can substitute compiled objects using the DTK
    // unit names in config.json, rendering a new script without touching the
    // reference objects. Preserve the exact original address constraints
    // until a looser layout passes `kevin elf verify` on real executables.
    let layout = crate::ps3::util::ppu_link::LinkLayout {
        entry: entry_name.clone(),
        toc: anchors.first_key_value().map(|(&toc, _)| toc),
        sections: obj
            .sections
            .iter()
            .map(|(index, section)| crate::ps3::util::ppu_link::LinkSection {
                name: section.name.clone(),
                address: section.address,
                inputs: pieces
                    .iter()
                    .enumerate()
                    .filter(|(_, piece)| piece.original_section == index)
                    .map(|(i, piece)| crate::ps3::util::ppu_link::LinkInput {
                        unit: piece.unit.clone(),
                        section: output_sections[i].clone(),
                    })
                    .collect(),
            })
            .collect(),
    };
    let mut reference_objects = BTreeMap::new();
    for unit in by_unit.keys() {
        reference_objects.insert(unit.clone(), format!("obj/{}", output_name(unit)?));
    }
    fs::write(out.join("link_layout.json"), serde_json::to_vec_pretty(&layout)?)?;
    fs::write(out.join("link.ld"), layout.script(&reference_objects)?)?;
    let manifest = crate::cmd::dol::OutputConfig {
        version: env!("CARGO_PKG_VERSION").to_owned(),
        base: crate::cmd::dol::OutputModule {
            name: object_path.file_stem().unwrap_or("ppu").to_owned(),
            module_id: 0,
            ldscript: typed_path::Utf8UnixPathBuf::from(format!("{out}/link.ld")),
            entry: Some(entry_name.clone()),
            units,
            extract: Vec::new(),
        },
        modules: Vec::new(),
        links: Vec::new(),
    };
    let mut json = serde_json::to_value(&manifest)?;
    if needs_fixed_references {
        json["link_reference_objects"] = serde_json::to_value(
            by_unit
                .keys()
                .map(|unit| Ok((unit.clone(), format!("{out}/obj_link/{}", output_name(unit)?))))
                .collect::<Result<BTreeMap<_, _>>>()?,
        )?;
    }

    if symbol_aware_multi_toc {
        json["link_reference_objects"] = serde_json::to_value(
            by_unit.keys().map(|unit| {
                Ok((unit.clone(), format!("{out}/obj_relink/{}", output_name(unit)?)))
            }).collect::<Result<BTreeMap<_, _>>>()?,
        )?;
        json["link_ldflags"] = serde_json::json!(["--no-multi-toc"]);
    }
    fs::write(out.join("config.json"), serde_json::to_vec_pretty(&json)?)?;
    fs::write(
        out.join("link.sh"),
        r##"#!/usr/bin/env bash
set -euo pipefail
# Set WIBO and PPU_LD to absolute paths before running this script.
# The original PS3 linker accepts neither -m elf64ppc nor the
# multi-line response-file format used by the old prototype.
: "${WIBO:?Set WIBO to the Windows binary runner (absolute path)}"
: "${PPU_LD:?Set PPU_LD to target/ppu/bin/ppu-lv2-ld.exe (absolute path)}"
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
objects=()
while IFS= read -r entry; do
    [[ -z "$entry" ]] && continue
    objects+=("${entry%% # *}")
done < link_order.txt
"$WIBO" "$PPU_LD" -T link.ld -o linked.elf "${objects[@]}"
"##,
    )?;
    Ok(())
}

/// The SDK GCC 4.1.1 assembler emits a symbol-less ELF relocation 107 on the
/// second 32-bit word of an `.opd` descriptor. Modern ELF tools call type 107
/// R_PPC64_TLSGD, but the *original* PS3 linker consumes it as a descriptor
/// TOC marker. `object::write` has no relocation API with symbol index zero,
/// so translate the emitted ELF64BE RELA entries after serialization.
fn fix_sdk_opd_markers(output: &mut [u8]) -> Result<()> {
    let mut positions = Vec::new();
    {
        let elf_file = File::parse(&*output)?;
        for section in elf_file.sections() {
            if !section.name()?.starts_with(".rela.opd") {
                continue;
            }
            let Some((start, size)) = section.file_range() else {
                continue;
            };
            ensure!(size % 24 == 0, "Invalid SDK OPD RELA section size");
            for offset in (start as usize..(start + size) as usize).step_by(24) {
                let entry_offset = u64::from_be_bytes(output[offset..offset + 8].try_into()?);
                let info = u64::from_be_bytes(output[offset + 8..offset + 16].try_into()?);
                if entry_offset % 8 == 4 && info as u32 == elf::R_PPC64_ADDR32 {
                    positions.push(offset);
                }
            }
        }
    }
    for offset in positions {
        output[offset + 8..offset + 16]
            .copy_from_slice(&u64::from(elf::R_PPC64_TLSGD).to_be_bytes());
        output[offset + 16..offset + 24].fill(0);
    }
    Ok(())
}

pub use super::ppu_verify::verify;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_config_hash_is_filled_without_rewriting_other_yaml() {
        let root = std::env::temp_dir().join(format!(
            "kevin-hash-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&root).unwrap();
        let elf_path = root.join("original.elf");
        fs::write(&elf_path, b"abc").unwrap();
        let config_path = root.join("config.yml");
        let elf = Utf8NativePath::new(elf_path.to_str().unwrap());
        let config_file = Utf8NativePath::new(config_path.to_str().unwrap());
        let sha1 = "a9993e364706816aba3e25717850c26c9cd0d89d";

        let missing = "# Important project comment\nobject: original.elf\nsymbols: symbols.txt\nsplits: splits.txt\ncustom: preserved\n";
        fs::write(&config_path, missing).unwrap();
        let mut config: ElfProjectConfig = serde_yaml::from_str(missing).unwrap();
        populate_missing_config_hash(config_file, elf, &mut config).unwrap();
        assert_eq!(config.hash.as_deref(), Some(sha1));
        assert_eq!(fs::read_to_string(&config_path).unwrap(), format!("{missing}hash: {sha1}\n"));

        // Explicit null is also missing, but its inline comment survives.
        let null = "object: original.elf\nsymbols: symbols.txt\nsplits: splits.txt\nhash: null # keep me\ncustom: preserved\n";
        fs::write(&config_path, null).unwrap();
        let mut config: ElfProjectConfig = serde_yaml::from_str(null).unwrap();
        populate_missing_config_hash(config_file, elf, &mut config).unwrap();
        assert_eq!(fs::read_to_string(&config_path).unwrap(), format!(
            "object: original.elf\nsymbols: symbols.txt\nsplits: splits.txt\nhash: {sha1} # keep me\ncustom: preserved\n"
        ));

        // A known baseline is never silently changed, even when incorrect.
        let existing = "object: original.elf\nsymbols: symbols.txt\nsplits: splits.txt\nhash: deadbeef\n";
        fs::write(&config_path, existing).unwrap();
        let mut config: ElfProjectConfig = serde_yaml::from_str(existing).unwrap();
        populate_missing_config_hash(config_file, elf, &mut config).unwrap();
        assert_eq!(fs::read_to_string(&config_path).unwrap(), existing);

        fs::remove_file(&elf_path).unwrap();
        fs::write(&config_path, missing).unwrap();
        let mut config: ElfProjectConfig = serde_yaml::from_str(missing).unwrap();
        assert!(populate_missing_config_hash(config_file, elf, &mut config).is_err());
        assert_eq!(fs::read_to_string(&config_path).unwrap(), missing);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn multi_toc_linker_capability_is_consistent_with_config_refresh() {
        assert!(symbol_aware_multi_toc_supported(2, 1024, 1024));
        assert!(!symbol_aware_multi_toc_supported(1, 1024, 1024));
        assert!(!symbol_aware_multi_toc_supported(2, 1023, 1024));
        assert!(!symbol_aware_multi_toc_supported(2, 1024, 1023));
    }

    #[test]
    fn splits_large_automatic_units_on_function_boundaries_only() {
        let mut obj = ObjInfo::new(
            ObjKind::Executable, ObjArchitecture::PowerPc64, "fixture".into(), Vec::new(),
            vec![
                section(".text", ObjSectionKind::Code, 0x1000, vec![0; 0x90_000]),
                section(".rodata", ObjSectionKind::ReadOnlyData, 0x100_000, vec![0; 0x60_000]),
                section(".data", ObjSectionKind::Data, 0x200_000, vec![0; 0x50_000]),
            ],
        );
        append_split(&mut obj, 0, 0x1000, 0x91_000, "auto_00_00001000_text".into(), true);
        append_split(&mut obj, 1, 0x100_000, 0x160_000, "auto_01_00100000_rodata".into(), true);
        append_split(&mut obj, 2, 0x200_000, 0x250_000, "source.cpp".into(), false);
        let descriptors = (0x1000..0x91_000).step_by(0x1000)
            .map(|code| Descriptor { address: 0, code, toc: 0xA000 }).collect::<Vec<_>>();
        assert_eq!(limit_automatic_section_sizes(&mut obj, &descriptors), 2);
        let text: Vec<_> = obj.sections[0].splits.iter().collect();
        assert!(text.len() > 1);
        assert!(text.iter().all(|(start, split)| {
            u64::from(split.end) - u64::from(*start) <= MAX_AUTO_TEXT_BYTES
                && (u64::from(*start) - 0x1000) % 0x1000 == 0
        }));
        let rodata: Vec<_> = obj.sections[1].splits.iter().collect();
        assert!(rodata.len() > 1);
        assert!(rodata.iter().all(|(start, split)| {
            u64::from(split.end) - u64::from(*start) <= MAX_AUTO_DATA_BYTES
        }));
        let named: Vec<_> = obj.sections[2].splits.iter().collect();
        assert_eq!(named.len(), 1);
        assert_eq!(named[0].1.unit, "source.cpp");
    }

    #[test]
    fn multi_toc_link_reference_restores_bound_instructions_and_drops_relocations() {
        let original_instruction = 0x4be6_cb9d_u32.to_be_bytes();
        let original = ObjInfo::new(
            ObjKind::Executable,
            ObjArchitecture::PowerPc64,
            "fixture".into(),
            Vec::new(),
            vec![section(".text", ObjSectionKind::Code, 0x1000, original_instruction.to_vec())],
        );
        let pieces = [Piece {
            original_section: 0,
            start: 0x1000,
            end: 0x1004,
            unit: "test.cpp".into(),
            align: 4,
            name: ".text".into(),
        }];
        let mut writer =
            WriteObject::new(BinaryFormat::Elf, Architecture::PowerPc64, Endianness::Big);
        writer.flags = FileFlags::Elf { os_abi: 0x66, abi_version: 0, e_flags: 0x0100_0000 };
        let text = writer.add_section(Vec::new(), b".text".to_vec(), SectionKind::Text);
        writer.append_section_data(text, &0x4800_0001_u32.to_be_bytes(), 4);
        let extern_sym = writer.add_symbol(Symbol {
            name: b"callee".to_vec(),
            value: 0,
            size: 0,
            kind: SymbolKind::Text,
            scope: SymbolScope::Linkage,
            weak: false,
            section: SymbolSection::Undefined,
            flags: object::SymbolFlags::None,
        });
        writer
            .add_relocation(text, Relocation {
                offset: 0,
                symbol: extern_sym,
                addend: 0,
                flags: RelocationFlags::Elf { r_type: elf::R_PPC64_REL24 },
            })
            .unwrap();
        let rich = writer.write().unwrap();
        let snapshot = fixed_image_reference(
            &rich,
            &[0],
            &pieces,
            &[".text".to_owned()],
            &original,
        )
        .unwrap();
        let rich_file = File::parse(rich.as_slice()).unwrap();
        assert_eq!(rich_file.section_by_name(".text").unwrap().relocations().count(), 1);
        let fixed_file = File::parse(snapshot.as_slice()).unwrap();
        assert_eq!(fixed_file.section_by_name(".text").unwrap().data().unwrap(), original_instruction);
        assert_eq!(fixed_file.section_by_name(".text").unwrap().relocations().count(), 0);
        assert_eq!(fixed_file.architecture(), Architecture::PowerPc64);
    }

    #[test]
    fn symbol_aware_reference_retains_data_relocs_and_restores_opd_toc() {
        let mut writer = WriteObject::new(BinaryFormat::Elf, Architecture::PowerPc64, Endianness::Big);
        writer.flags = FileFlags::Elf { os_abi: 0x66, abi_version: 0, e_flags: 0x0100_0000 };
        let text = writer.add_section(Vec::new(), b".text".to_vec(), SectionKind::Text);
        let opd = writer.add_section(Vec::new(), b".opd".to_vec(), SectionKind::Data);
        let data = writer.add_section(Vec::new(), b".data".to_vec(), SectionKind::Data);
        writer.append_section_data(text, &0x4800_0001_u32.to_be_bytes(), 4);
        writer.append_section_data(opd, &[0; 8], 4);
        writer.append_section_data(data, &[0; 4], 4);
        let symbol = writer.add_symbol(Symbol {
            name: b"external".to_vec(), value: 0, size: 0,
            kind: SymbolKind::Text, scope: SymbolScope::Linkage, weak: false,
            section: SymbolSection::Undefined, flags: object::SymbolFlags::None,
        });
        for (section, offset, ty) in [
            (text, 0, elf::R_PPC64_REL24),
            (opd, 0, elf::R_PPC64_ADDR32),
            (opd, 4, elf::R_PPC64_ADDR32),
            (data, 0, elf::R_PPC64_ADDR32),
        ] {
            writer.add_relocation(section, Relocation {
                offset, symbol, addend: 0, flags: RelocationFlags::Elf { r_type: ty },
            }).unwrap();
        }
        let mut rich = writer.write().unwrap();
        fix_sdk_opd_markers(&mut rich).unwrap();
        let original = ObjInfo::new(
            ObjKind::Executable, ObjArchitecture::PowerPc64, "fixture".into(), Vec::new(),
            vec![
                section(".text", ObjSectionKind::Code, 0x1000, 0x4be6_cb9d_u32.to_be_bytes().to_vec()),
                section(".opd", ObjSectionKind::Data, 0x2000, vec![0; 8]),
                section(".data", ObjSectionKind::Data, 0x3000, vec![0; 4]),
            ],
        );
        let pieces: Vec<_> = [(0, 0x1000, 0x1004, ".text"),
            (1, 0x2000, 0x2008, ".opd"), (2, 0x3000, 0x3004, ".data")]
            .into_iter().map(|(section, start, end, name)| Piece {
                original_section: section, start, end, unit: "a.cpp".into(),
                align: 4, name: name.into(),
            }).collect();
        let names = [".text".into(), ".opd".into(), ".data".into()];
        let output = symbol_aware_link_reference(
            &rich, &[0, 1, 2], &pieces, &names, &original,
            &[Descriptor { address: 0x2000, code: 0x1000, toc: 0x4000 }], 0x3000,
        ).unwrap();
        let file = File::parse(output.as_slice()).unwrap();
        assert_eq!(file.section_by_name(".text").unwrap().data().unwrap(), &0x4be6_cb9d_u32.to_be_bytes());
        assert_eq!(file.section_by_name(".text").unwrap().relocations().count(), 0);
        assert_eq!(file.section_by_name(".data").unwrap().relocations().count(), 1);
        let opd_relocs: Vec<_> = file.section_by_name(".opd").unwrap().relocations().collect();
        assert_eq!(opd_relocs.len(), 2);
        assert_eq!(opd_relocs[1].0, 4);
        assert_eq!(opd_relocs[1].1.addend(), 0x1000);
    }

    #[test]
    fn dwarf_lines_are_rebased_and_recognized_by_objdiff() {
        let mut output =
            WriteObject::new(BinaryFormat::Elf, Architecture::PowerPc64, Endianness::Big);
        output.flags = FileFlags::Elf { os_abi: 0x66, abi_version: 0, e_flags: 0x0100_0000 };
        // Real split units can contain multiple disjoint text sections.
        for name in [".text", ".text.00002000"] {
            let section = output.add_section(Vec::new(), name.as_bytes().to_vec(), SectionKind::Text);
            output.append_section_data(section, &0x6000_0000u32.to_be_bytes().repeat(4), 4);
        }
        let lines = BTreeMap::from([(0x1000, 17), (0x1004, 18), (0x2000, 33), (0x2008, 42)]);
        add_unit_line_numbers(&mut output, "source/file.cpp", &[(0x1000, 0x1010), (0x2000, 0x2010)], &lines)
            .unwrap();
        let bytes = output.write().unwrap();
        // objdiff-core 2.2's architecture dispatch only accepts EM_PPC,
        // not EM_PPC64. Use its identical DWARF reader with a synthetic
        // EM_PPC header here; the actual PPU split objects remain PPC64.
        let mut objdiff_bytes = bytes.clone();
        objdiff_bytes[18..20].copy_from_slice(&elf::EM_PPC.to_be_bytes());
        let obj = objdiff_core::obj::read::parse(
            &objdiff_bytes,
            &objdiff_core::diff::DiffObjConfig::default(),
        )
        .unwrap();
        let text: Vec<_> = obj.sections.iter().filter(|s| s.name.starts_with(".text")).collect();
        assert_eq!(text.len(), 2);
        assert_eq!(text[0].line_info.get(&0), Some(&17));
        assert_eq!(text[0].line_info.get(&4), Some(&18));
        assert_eq!(text[1].line_info.get(&0), Some(&33));
        assert_eq!(text[1].line_info.get(&8), Some(&42));
        assert!(object::File::parse(bytes.as_slice()).unwrap().section_by_name(".debug_line").is_some());
    }

    #[test]
    fn reconstructed_external_bl_uses_original_gcc_relocation_operand() {
        // SndStrmWrapper::CreateStream at EBOOT 0x001A6400 calls the
        // linker-generated branch stub at 0x00012F9C. GCC's input object
        // must contain `bl 0` plus R_PPC64_REL24, *not* the prelinked
        // negative branch displacement 0x4BE6CB9D.
        let mut branch = 0x4be6_cb9d_u32.to_be_bytes();
        clear_relocated_branch_operand(&mut branch, 0, elf::R_PPC64_REL24).unwrap();
        assert_eq!(branch, 0x4800_0001_u32.to_be_bytes());
        // An internal beq is left as-is (no relocation was constructed).
        let local = 0x419c_0054_u32.to_be_bytes();
        assert_eq!(local, 0x419c_0054_u32.to_be_bytes());

        // A reconstructed conditional cross-unit branch also has its
        // displacement cleared, while BO/BI and condition bits remain.
        let mut conditional = 0x419c_0054_u32.to_be_bytes();
        clear_relocated_branch_operand(&mut conditional, 0, elf::R_PPC64_REL14).unwrap();
        assert_eq!(conditional, 0x419c_0000_u32.to_be_bytes());

        // Absolute branch retains AA and LK flags.
        let mut absolute = 0x4801_2347_u32.to_be_bytes();
        clear_relocated_branch_operand(&mut absolute, 0, elf::R_PPC64_ADDR24).unwrap();
        assert_eq!(absolute, 0x4800_0003_u32.to_be_bytes());
    }

    fn section(name: &str, kind: ObjSectionKind, address: u64, data: Vec<u8>) -> ObjSection {
        ObjSection {
            name: name.to_owned(),
            kind,
            address,
            size: data.len() as u64,
            data,
            align: 4,
            elf_index: 1,
            splits: Default::default(),
        }
    }

    #[test]
    fn source_paths_preserve_directories_without_drives() {
        assert_eq!(
            source_unit_path(r"D:\EAX-BUILD1-S04-PS3\Carbon\SourceLists\zAI.cpp"),
            Some("EAX-BUILD1-S04-PS3/Carbon/SourceLists/zAI.cpp".into())
        );
        assert_eq!(
            source_unit_path("../../GameShared/GameClasses/test.cpp"),
            Some("GameShared/GameClasses/test.cpp".into())
        );
        assert_eq!(source_unit_path("a/b/../c.cpp"), Some("a/c.cpp".into()));
        assert_eq!(source_unit_path("C:\\"), None);
    }

    #[test]
    fn source_ranges_handle_overlap_gaps_and_function_boundaries() {
        let symbols = vec![ObjSymbol {
            name: "function".into(),
            address: 0x1008,
            section: Some(0),
            size: 0x10,
            size_known: true,
            kind: ObjSymbolKind::Function,
            ..Default::default()
        }];
        let mut obj = ObjInfo::new(
            ObjKind::Executable,
            ObjArchitecture::PowerPc64,
            "synthetic".into(),
            symbols,
            vec![section(".text", ObjSectionKind::Code, 0x1000, vec![0; 0x50])],
        );
        initialize_source_splits(&mut obj, &[
            CompilationUnitRange { source: r"D:\source\a.cpp".into(), start: 0x1000, end: 0x1014 },
            CompilationUnitRange { source: r"D:\source\b.cpp".into(), start: 0x100c, end: 0x1024 },
            CompilationUnitRange { source: r"D:\source\c.cpp".into(), start: 0x1024, end: 0x1040 },
        ]);
        let actual: Vec<_> = obj
            .sections
            .get(0)
            .unwrap()
            .splits
            .iter()
            .map(|(start, split)| (start, split.end, split.unit.as_str()))
            .collect();
        assert_eq!(actual, vec![
            (0x1000, 0x1024, "source/a.cpp"),
            (0x1024, 0x1040, "source/c.cpp"),
            (0x1040, 0x1050, "auto_00_00001040_text"),
        ]);
        assert!(
            obj.link_order.iter().any(|u| u.name == "auto_00_00001040_text" && u.autogenerated)
        );
        assert!(obj.link_order.iter().any(|u| u.name == "source/a.cpp" && !u.autogenerated));
    }

    #[test]
    fn static_data_variables_follow_their_compilation_units() {
        let mut obj = ObjInfo::new(
            ObjKind::Executable,
            ObjArchitecture::PowerPc64,
            "test".into(),
            vec![ObjSymbol {
                name: "owned_data".into(),
                address: 0x2000,
                section: Some(0),
                size: 16,
                size_known: true,
                kind: ObjSymbolKind::Object,
                ..Default::default()
            }],
            vec![
                section(".data", ObjSectionKind::Data, 0x2000, vec![0; 0x30]),
                section(".rodata", ObjSectionKind::ReadOnlyData, 0x3000, vec![0; 0x20]),
                section(".bss", ObjSectionKind::Bss, 0x4000, vec![0; 0x20]),
            ],
        );
        initialize_splits(&mut obj);
        initialize_data_splits(&mut obj, &[
            StaticVariable {
                source: "source/one.cpp".into(),
                address: 0x2000,
                name: Some("owned_data".into()),
            },
            StaticVariable { source: "source/two.cpp".into(), address: 0x2010, name: None },
            StaticVariable { source: "source/one.cpp".into(), address: 0x3000, name: None },
            StaticVariable { source: "source/one.cpp".into(), address: 0x4000, name: None },
        ]);
        let data: Vec<_> =
            obj.sections[0].splits.iter().map(|(a, s)| (a, s.end, s.unit.as_str())).collect();
        assert_eq!(data, vec![
            (0x2000, 0x2010, "source/one.cpp"),
            (0x2010, 0x2030, "source/two.cpp")
        ]);
        assert_eq!(obj.sections[1].splits.iter().next().unwrap().1.unit, "source/one.cpp");
        assert_eq!(obj.sections[2].splits.iter().next().unwrap().1.unit, "source/one.cpp");
        // Conflicting claims at the same address remain unattributed.
        let mut obj2 = ObjInfo::new(
            ObjKind::Executable,
            ObjArchitecture::PowerPc64,
            "test".into(),
            vec![],
            vec![section(".data", ObjSectionKind::Data, 0x2000, vec![0; 0x20])],
        );
        initialize_splits(&mut obj2);
        initialize_data_splits(&mut obj2, &[
            StaticVariable { source: "source/one.cpp".into(), address: 0x2000, name: None },
            StaticVariable { source: "source/two.cpp".into(), address: 0x2000, name: None },
        ]);
        assert!(obj2.sections[0].splits.iter().all(|(_, s)| s.autogenerated));
    }

    #[test]
    fn opd_entries_follow_their_code_object_without_reordering() {
        let mut obj = ObjInfo::new(
            ObjKind::Executable,
            ObjArchitecture::PowerPc64,
            "test".into(),
            vec![],
            vec![
                section(".text", ObjSectionKind::Code, 0x1000, vec![0; 0x20]),
                section(".opd", ObjSectionKind::Data, 0x3000, vec![0; 16]),
            ],
        );
        initialize_splits(&mut obj);
        obj.sections[0].splits.clear();
        append_split(&mut obj, 0, 0x1000, 0x1010, "source/a.cpp".into(), false);
        append_split(&mut obj, 0, 0x1010, 0x1020, "source/b.cpp".into(), false);
        initialize_opd_splits(&mut obj, &[
            Descriptor { address: 0x3000, code: 0x1004, toc: 0x9000 },
            Descriptor { address: 0x3008, code: 0x1014, toc: 0x9000 },
        ])
        .unwrap();
        let entries: Vec<_> = obj.sections[1]
            .splits
            .iter()
            .map(|(address, split)| (address, split.end, split.unit.as_str()))
            .collect();
        assert_eq!(entries, [(0x3000, 0x3008, "source/a.cpp"), (0x3008, 0x3010, "source/b.cpp")]);
    }

    #[test]
    fn got_splits_follow_distinct_linked_toc_bases() {
        let mut obj = ObjInfo::new(
            ObjKind::Executable,
            ObjArchitecture::PowerPc64,
            "test".into(),
            vec![],
            vec![section(".got", ObjSectionKind::Data, 0x1000, vec![0; 0x100])],
        );
        initialize_splits(&mut obj);
        initialize_toc_splits(&mut obj, &[
            Descriptor { address: 0x3000, code: 0x2000, toc: 0x9000 },
            Descriptor { address: 0x3008, code: 0x2010, toc: 0x9080 },
        ])
        .unwrap();
        let entries: Vec<_> = obj.sections[0]
            .splits
            .iter()
            .map(|(address, split)| (address, split.end, split.unit.clone()))
            .collect();
        assert_eq!(entries.len(), 2);
        assert_eq!((entries[0].0, entries[0].1), (0x1000, 0x1080));
        assert_eq!((entries[1].0, entries[1].1), (0x1080, 0x1100));
        assert_ne!(entries[0].2, entries[1].2);
    }

    #[test]
    fn toc_entries_follow_referencing_code_units_and_preserve_ambiguous_slots() {
        let mut text = vec![0; 0x30];
        // lwz r3,-0x8000(r2) and lwz r3,-0x7ffc(r2), with r2=0xa000.
        text[0..4].copy_from_slice(&0x8062_8000u32.to_be_bytes());
        text[0x10..0x14].copy_from_slice(&0x8062_8004u32.to_be_bytes());
        let mut obj = ObjInfo::new(
            ObjKind::Executable,
            ObjArchitecture::PowerPc64,
            "synthetic".into(),
            vec![],
            vec![
                section(".text", ObjSectionKind::Code, 0x1000, text),
                section(".got", ObjSectionKind::Data, 0x2000, vec![0; 16]),
            ],
        );
        initialize_splits(&mut obj);
        obj.sections[0].splits.clear();
        append_split(&mut obj, 0, 0x1000, 0x1010, "source/first.cpp".into(), false);
        append_split(&mut obj, 0, 0x1010, 0x1030, "source/second.cpp".into(), false);
        let descriptors = [Descriptor { address: 0x3000, code: 0x1000, toc: 0xa000 }, Descriptor {
            address: 0x3008,
            code: 0x1010,
            toc: 0xa000,
        }];
        initialize_toc_splits(&mut obj, &descriptors).unwrap();
        assert!(attribute_toc_splits(&mut obj, &descriptors).unwrap());
        let ranges: Vec<_> = obj.sections[1]
            .splits
            .iter()
            .map(|(start, split)| (start, split.end, split.unit.clone()))
            .collect();
        assert_eq!(
            (ranges[0].0, ranges[0].1, ranges[0].2.as_str()),
            (0x2000, 0x2004, "source/first.cpp")
        );
        assert_eq!(
            (ranges[1].0, ranges[1].1, ranges[1].2.as_str()),
            (0x2004, 0x2008, "source/second.cpp")
        );
        assert!(ranges[2].2.starts_with("auto_"));

        // A TOC slot referenced by two different compilation units must not
        // be assigned to whichever function happened to appear last.
        obj.sections[0].data[0x10..0x14].copy_from_slice(&0x8062_8000u32.to_be_bytes());
        obj.sections[1].splits.clear();
        append_split(&mut obj, 1, 0x2000, 0x2010, "auto_01_00002000_toc".into(), true);
        assert!(attribute_toc_splits(&mut obj, &descriptors).unwrap());
        let first = obj.sections[1].splits.iter().next().unwrap().1;
        assert!(first.unit.starts_with("auto_"), "Conflicting slot was assigned a CU");
    }

    #[test]
    fn unattributed_code_with_shared_toc_references_receives_real_slot() {
        let mut code = vec![0; 0x20];
        code[0..4].copy_from_slice(&0x8062_8000u32.to_be_bytes());
        code[4..8].copy_from_slice(&0x8062_8004u32.to_be_bytes());
        code[0x10..0x14].copy_from_slice(&0x8062_8000u32.to_be_bytes());
        let mut obj = ObjInfo::new(
            ObjKind::Executable,
            ObjArchitecture::PowerPc64,
            "synthetic".into(),
            vec![],
            vec![
                section(".text", ObjSectionKind::Code, 0x1000, code),
                section(".got", ObjSectionKind::Data, 0x2000, vec![0; 8]),
            ],
        );
        initialize_splits(&mut obj);
        obj.sections[0].splits.clear();
        append_split(&mut obj, 0, 0x1000, 0x1010, "source/main.cpp".into(), false);
        append_split(&mut obj, 0, 0x1010, 0x1020, "auto_00_00001010_text".into(), true);
        let descriptors = [Descriptor { address: 0x3000, code: 0x1000, toc: 0xa000 }, Descriptor {
            address: 0x3008,
            code: 0x1010,
            toc: 0xa000,
        }];
        initialize_toc_splits(&mut obj, &descriptors).unwrap();
        assert!(attribute_toc_splits(&mut obj, &descriptors).unwrap());
        let ranges: Vec<_> = obj.sections[1]
            .splits
            .iter()
            .map(|(address, split)| (address, split.end, split.unit.as_str()))
            .collect();
        assert_eq!(ranges, [
            (0x2000, 0x2004, "auto_00_00001010_text"),
            (0x2004, 0x2008, "source/main.cpp"),
        ]);
    }

    #[test]
    fn separate_unidentified_ranges_get_distinct_auto_units() {
        let mut obj = ObjInfo::new(
            ObjKind::Executable,
            ObjArchitecture::PowerPc64,
            "synthetic".into(),
            Vec::new(),
            vec![
                section(".text", ObjSectionKind::Code, 0x1000, vec![0; 0x40]),
                section(".data", ObjSectionKind::Data, 0x2000, vec![0; 8]),
            ],
        );
        initialize_source_splits(&mut obj, &[
            CompilationUnitRange { source: "source/first.cpp".into(), start: 0x1010, end: 0x1020 },
            CompilationUnitRange { source: "source/second.cpp".into(), start: 0x1030, end: 0x1034 },
        ]);
        let actual: Vec<_> = obj
            .sections
            .get(0)
            .unwrap()
            .splits
            .iter()
            .map(|(start, split)| (start, split.end, split.unit.as_str(), split.autogenerated))
            .collect();
        assert_eq!(actual, vec![
            (0x1000, 0x1010, "auto_00_00001000_text", true),
            (0x1010, 0x1020, "source/first.cpp", false),
            (0x1020, 0x1030, "auto_00_00001020_text", true),
            (0x1030, 0x1034, "source/second.cpp", false),
            (0x1034, 0x1040, "auto_00_00001034_text", true),
        ]);
        assert_eq!(
            obj.sections.get(1).unwrap().splits.iter().next().unwrap().1.unit,
            "auto_01_00002000_data",
        );
        assert!(obj.link_order.iter().filter(|unit| unit.autogenerated).count() == 4);
    }

    #[test]
    fn source_split_absorbs_adjusting_thunks_with_known_targets() {
        let mut data = vec![0; 0x40];
        // A this-adjusting thunk at 0x1000 targeting the sourced function at
        // 0x1008, followed by a regular unclaimed region.
        data[..8].copy_from_slice(&[0x38, 0x63, 0xff, 0xf8, 0x48, 0, 0, 4]);
        let mut obj = ObjInfo::new(
            ObjKind::Executable,
            ObjArchitecture::PowerPc64,
            "test".into(),
            vec![
                ObjSymbol {
                    name: "._ZThn8_N4Test3fooEv".into(),
                    address: 0x1000,
                    section: Some(0),
                    size: 8,
                    size_known: true,
                    kind: ObjSymbolKind::Function,
                    ..Default::default()
                },
                ObjSymbol {
                    name: "._ZN4Test3fooEv".into(),
                    address: 0x1008,
                    section: Some(0),
                    size: 16,
                    size_known: true,
                    kind: ObjSymbolKind::Function,
                    ..Default::default()
                },
            ],
            vec![section(".text", ObjSectionKind::Code, 0x1000, data)],
        );
        initialize_source_splits(&mut obj, &[CompilationUnitRange {
            source: "source/test.cpp".into(),
            start: 0x1008,
            end: 0x1020,
        }]);
        let actual: Vec<_> = obj
            .sections
            .get(0)
            .unwrap()
            .splits
            .iter()
            .map(|(start, split)| (start, split.end, split.unit.as_str()))
            .collect();
        assert_eq!(actual, vec![
            (0x1000, 0x1020, "source/test.cpp"),
            (0x1020, 0x1040, "auto_00_00001020_text"),
        ]);
    }

    #[test]
    fn source_split_absorbs_contiguous_groups_of_thunks() {
        let mut data = vec![0; 0x40];
        data[0x00..0x08].copy_from_slice(&[0x38, 0x63, 0xff, 0xf8, 0x48, 0, 0, 12]);
        data[0x08..0x10].copy_from_slice(&[0x38, 0x84, 0xff, 0xf8, 0x48, 0, 0, 4]);
        let symbols = [
            ("._ZThn8_N4Test3fooEv", 0x1000, 8),
            ("._ZThn16_N4Test3fooEv", 0x1008, 8),
            ("._ZN4Test3fooEv", 0x1010, 0x10),
        ]
        .into_iter()
        .map(|(name, address, size)| ObjSymbol {
            name: name.into(),
            address,
            size,
            section: Some(0),
            size_known: true,
            kind: ObjSymbolKind::Function,
            ..Default::default()
        })
        .collect();
        let mut obj = ObjInfo::new(
            ObjKind::Executable,
            ObjArchitecture::PowerPc64,
            "synthetic".into(),
            symbols,
            vec![section(".text", ObjSectionKind::Code, 0x1000, data)],
        );
        initialize_source_splits(&mut obj, &[CompilationUnitRange {
            source: "source/test.cpp".into(),
            start: 0x1010,
            end: 0x1020,
        }]);
        let ranges: Vec<_> = obj
            .sections
            .get(0)
            .unwrap()
            .splits
            .iter()
            .map(|(start, split)| (start, split.end, split.unit.as_str()))
            .collect();
        assert_eq!(ranges, vec![
            (0x1000, 0x1020, "source/test.cpp"),
            (0x1020, 0x1040, "auto_00_00001020_text"),
        ]);
    }

    #[test]
    fn gcc_sections_keep_thunks_with_their_linkonce_target() {
        let mut data = vec![0; 0x60];
        data[0x20..0x28].copy_from_slice(&[0x38, 0x63, 0xff, 0xf8, 0x48, 0, 0, 12]);
        data[0x28..0x30].copy_from_slice(&[0x38, 0x84, 0xff, 0xf8, 0x48, 0, 0, 4]);
        let funcs = [
            (".main", 0x1000, 0x20, false),
            ("._ZThn8_N4Test4weakEv", 0x1020, 8, true),
            ("._ZThn16_N4Test4weakEv", 0x1028, 8, true),
            ("._ZN4Test4weakEv", 0x1030, 0x10, true),
            ("._ZN4Test5otherEv", 0x1040, 0x10, true),
        ];
        let symbols = funcs
            .into_iter()
            .map(|(name, address, size, weak)| ObjSymbol {
                name: name.into(),
                address,
                size,
                size_known: true,
                section: Some(0),
                kind: ObjSymbolKind::Function,
                flags: ObjSymbolFlagSet(if weak {
                    ObjSymbolFlags::Weak.into()
                } else {
                    ObjSymbolFlags::none()
                }),
                ..Default::default()
            })
            .collect();
        let obj = ObjInfo::new(
            ObjKind::Executable,
            ObjArchitecture::PowerPc64,
            "synthetic".into(),
            symbols,
            vec![section(".text", ObjSectionKind::Code, 0x1000, data)],
        );
        let pieces = compiler_text_sections(&obj, vec![Piece {
            original_section: 0,
            start: 0x1000,
            end: 0x1060,
            unit: "source/test.cpp".into(),
            align: 4,
            name: ".text".into(),
        }]);
        assert_eq!(
            pieces.iter().map(|p| (p.start, p.end, p.name.as_str())).collect::<Vec<_>>(),
            vec![
                (0x1000, 0x1020, ".text"),
                (0x1020, 0x1040, ".gnu.linkonce.t._ZN4Test4weakEv"),
                (0x1040, 0x1060, ".gnu.linkonce.t._ZN4Test5otherEv"),
            ]
        );
    }

    #[test]
    fn relocates_cross_unit_branches_and_individual_tocs() {
        let obj = ObjInfo::new(
            ObjKind::Executable,
            ObjArchitecture::PowerPc64,
            "test".into(),
            Vec::new(),
            vec![
                section(
                    ".text",
                    ObjSectionKind::Code,
                    0x1000,
                    [0x8062fff0_u32, 0x48000008, 0xe862fff0, 0x60000000]
                        .into_iter()
                        .flat_map(u32::to_be_bytes)
                        .collect(),
                ),
                section(".got", ObjSectionKind::Data, 0x2000, vec![0; 0x40]),
                section(".opd", ObjSectionKind::Data, 0x3000, vec![0; 16]),
            ],
        );
        let pieces = [
            Piece {
                original_section: 0,
                start: 0x1000,
                end: 0x1008,
                unit: "one.o".into(),
                align: 4,
                name: ".text".into(),
            },
            Piece {
                original_section: 0,
                start: 0x1008,
                end: 0x1010,
                unit: "two.o".into(),
                align: 4,
                name: ".text".into(),
            },
            Piece {
                original_section: 1,
                start: 0x2000,
                end: 0x2040,
                unit: "got.o".into(),
                align: 4,
                name: ".got".into(),
            },
            Piece {
                original_section: 2,
                start: 0x3000,
                end: 0x3010,
                unit: "opd.o".into(),
                align: 4,
                name: ".opd".into(),
            },
        ];
        let descriptors = [Descriptor { address: 0x3000, code: 0x1000, toc: 0x2010 }, Descriptor {
            address: 0x3008,
            code: 0x1008,
            toc: 0x2020,
        }];
        let (relocs, targets) = reconstruct_relocations(&obj, &pieces, &descriptors);
        assert_eq!(relocs[0].len(), 2);
        assert_eq!((relocs[0][0].offset, relocs[0][0].target, relocs[0][0].addend), (2, 0x2000, 0));
        assert_eq!(relocs[0][0].r_type, elf::R_PPC64_TOC16);
        assert_eq!(relocs[0][1].r_type, elf::R_PPC64_REL24);
        assert_eq!(relocs[0][1].target, 0x100c);
        assert_eq!(relocs[1][0].r_type, elf::R_PPC64_TOC16_DS);
        assert_eq!((relocs[1][0].target, relocs[1][0].addend), (0x2010, 0));
        assert_eq!(relocs[3].len(), 4);
        assert!(targets.contains(&0x2010));
        assert!(targets.contains(&0x100c));
    }

    #[test]
    fn relocates_lis_addi_and_lis_ori_address_pairs() {
        let data_base = 0x1234fff0;
        let obj = ObjInfo::new(
            ObjKind::Executable,
            ObjArchitecture::PowerPc64,
            "test".into(),
            vec![ObjSymbol {
                name: "known_data".into(),
                address: data_base,
                section: Some(1),
                kind: ObjSymbolKind::Object,
                ..Default::default()
            }],
            vec![
                section(
                    ".text",
                    ObjSectionKind::Code,
                    0x1000,
                    [0x3c601235_u32, 0x3863fff0, 0x3c801234, 0x6084fff0]
                        .into_iter()
                        .flat_map(u32::to_be_bytes)
                        .collect(),
                ),
                section(".data", ObjSectionKind::Data, data_base, vec![0; 8]),
            ],
        );
        let pieces = [
            Piece {
                original_section: 0,
                start: 0x1000,
                end: 0x1010,
                unit: "code.o".into(),
                align: 4,
                name: ".text".into(),
            },
            Piece {
                original_section: 1,
                start: data_base,
                end: data_base + 8,
                unit: "data.o".into(),
                align: 4,
                name: ".data".into(),
            },
        ];
        let (relocs, targets) = reconstruct_relocations(&obj, &pieces, &[]);
        assert_eq!(relocs[0].iter().map(|r| (r.offset, r.r_type)).collect::<Vec<_>>(), vec![
            (2, elf::R_PPC64_ADDR16_HA),
            (6, elf::R_PPC64_ADDR16_LO),
            (10, elf::R_PPC64_ADDR16_HI),
            (14, elf::R_PPC64_ADDR16_LO),
        ]);
        assert!(relocs[0].iter().all(|r| r.target == data_base && r.addend == 0));
        assert!(targets.contains(&data_base));
    }

    #[test]
    fn refuses_parent_paths_in_split_units() {
        assert!(output_name("source/game.o").is_ok());
        assert!(output_name("../other.o").is_err());
        assert!(output_name("/tmp/other.o").is_err());
    }
}
