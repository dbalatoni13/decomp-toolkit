//! Lightweight DWARF2 compilation-unit address ownership for PPU split generation.

use std::{borrow::Cow, collections::BTreeMap};

use anyhow::Result;
use gimli::{self, EndianSlice, RunTimeEndian};
use object::{Object, ObjectSection};

/// Address ranges belonging to a DWARF compilation unit. Unlike `read_dwarf2_info`,
/// this reads only CU headers and `.debug_aranges`, not the full DIE trees.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompilationUnitRange {
    pub source: String,
    pub start: u64,
    pub end: u64,
}

pub fn compilation_unit_ranges(obj_file: &object::File<'_>) -> Result<Vec<CompilationUnitRange>> {
    let Some(aranges_section) = obj_file.section_by_name(".debug_aranges") else {
        return Ok(Vec::new());
    };
    if obj_file.section_by_name(".debug_info").is_none() {
        return Ok(Vec::new());
    }
    let sections = gimli::DwarfSections::load(|id| {
        Ok::<_, gimli::Error>(
            obj_file
                .section_by_name(id.name())
                .and_then(|section| section.uncompressed_data().ok())
                .unwrap_or(Cow::Borrowed(&[][..])),
        )
    })?;
    let endian = match obj_file.endianness() {
        object::Endianness::Little => RunTimeEndian::Little,
        object::Endianness::Big => RunTimeEndian::Big,
    };
    let dwarf = sections.borrow(|section| EndianSlice::new(section, endian));
    let mut names = BTreeMap::new();
    let mut units = dwarf.units();
    while let Some(header) = units.next()? {
        let Some(offset) = header.offset().as_debug_info_offset() else {
            continue;
        };
        let unit = dwarf.unit(header)?;
        let mut entries = unit.entries();
        let Some((_, root)) = entries.next_dfs()? else {
            continue;
        };
        let Some(value) = root.attr_value(gimli::DW_AT_name)? else {
            continue;
        };
        let mut source = dwarf.attr_string(&unit, value)?.to_string_lossy().into_owned();
        if !source.contains(['/', '\\']) {
            if let Some(dir) = root.attr_value(gimli::DW_AT_comp_dir)? {
                let dir = dwarf.attr_string(&unit, dir)?.to_string_lossy();
                source = format!("{dir}/{source}");
            }
        }
        names.insert(offset.0, source);
    }
    let data = aranges_section.uncompressed_data()?;
    let aranges = gimli::DebugAranges::new(&data, endian);
    let mut result = Vec::new();
    let mut headers = aranges.headers();
    while let Some(header) = headers.next()? {
        let Some(source) = names.get(&header.debug_info_offset().0) else {
            continue;
        };
        let mut entries = header.entries();
        while let Some(entry) = entries.next()? {
            let range = entry.range();
            if range.end > range.begin {
                result.push(CompilationUnitRange {
                    source: source.clone(),
                    start: range.begin,
                    end: range.end,
                });
            }
        }
    }
    Ok(result)
}
