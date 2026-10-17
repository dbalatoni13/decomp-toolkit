//! Lightweight DWARF2 compilation-unit address ownership for PPU split generation.

use std::{borrow::Cow, collections::BTreeMap};

use anyhow::{Context, Result};
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

/// Original linked addresses and their DWARF source lines. The PPU splitter
/// rebases these rows into each extracted unit's relocatable text section.
/// Each compilation unit may have an independent line program; reading only
/// the first would silently discard most source lines in large PS3 games.
pub fn line_numbers(obj_file: &object::File<'_>) -> Result<BTreeMap<u64, u32>> {
    if obj_file.section_by_name(".debug_line").is_none()
        || obj_file.section_by_name(".debug_info").is_none()
    {
        return Ok(BTreeMap::new());
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
    let dwarf = sections.borrow(|data| EndianSlice::new(data, endian));
    let mut lines = BTreeMap::new();
    let mut units = dwarf.units();
    loop {
        let header = match units.next() {
            Ok(Some(header)) => header,
            Ok(None) => break,
            Err(err) => {
                eprintln!("Warning: invalid PPU DWARF line-unit header: {err}");
                break;
            }
        };
        let unit_lines = (|| -> Result<BTreeMap<u64, u32>> {
            let unit = dwarf.unit(header).context("Reading original PPU DWARF compilation unit")?;
            let Some(program) = unit.line_program else { return Ok(BTreeMap::new()) };
            let mut rows = program.rows();
            let mut unit_lines = BTreeMap::new();
            while let Some((_header, row)) = rows.next_row()? {
                if !row.end_sequence()
                    && let Some(line) = row.line()
                    && let Ok(line) = u32::try_from(line.get())
                {
                    unit_lines.insert(row.address(), line);
                }
            }
            Ok(unit_lines)
        })();
        match unit_lines {
            Ok(rows) => lines.extend(rows),
            Err(err) => eprintln!("Warning: ignoring unusable PPU DWARF line unit: {err:#}"),
        }
    }
    Ok(lines)
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
    loop {
        let header = match units.next() {
            Ok(Some(header)) => header,
            Ok(None) => break,
            Err(err) => {
                eprintln!("Warning: invalid PPU DWARF compilation-unit header: {err}");
                break;
            }
        };
        let name = (|| -> Result<Option<(usize, String)>> {
            let Some(offset) = header.offset().as_debug_info_offset() else { return Ok(None) };
            let unit = dwarf.unit(header)?;
            let mut entries = unit.entries();
            let Some((_, root)) = entries.next_dfs()? else { return Ok(None) };
            let Some(value) = root.attr_value(gimli::DW_AT_name)? else { return Ok(None) };
            let mut source = dwarf.attr_string(&unit, value)?.to_string_lossy().into_owned();
            if !source.contains(['/', '\\'])
                && let Some(dir) = root.attr_value(gimli::DW_AT_comp_dir)?
            {
                source = format!("{}/{}", dwarf.attr_string(&unit, dir)?.to_string_lossy(), source);
            }
            Ok(Some((offset.0, source)))
        })();
        match name {
            Ok(Some((offset, source))) => {
                names.insert(offset, source);
            }
            Ok(None) => {}
            Err(err) => eprintln!("Warning: ignoring unusable PPU DWARF compilation unit: {err:#}"),
        }
    }
    let data = aranges_section.uncompressed_data()?;
    let aranges = gimli::DebugAranges::new(&data, endian);
    let mut result = Vec::new();
    let mut headers = aranges.headers();
    loop {
        let header = match headers.next() {
            Ok(Some(header)) => header,
            Ok(None) => break,
            Err(err) => {
                eprintln!("Warning: invalid PPU DWARF aranges header: {err}");
                break;
            }
        };
        let Some(source) = names.get(&header.debug_info_offset().0) else { continue };
        let mut entries = header.entries();
        loop {
            match entries.next() {
                Ok(Some(entry)) => {
                    let range = entry.range();
                    if range.end > range.begin {
                        result.push(CompilationUnitRange {
                            source: source.clone(),
                            start: range.begin,
                            end: range.end,
                        });
                    }
                }
                Ok(None) => break,
                Err(err) => {
                    eprintln!("Warning: ignoring malformed PPU DWARF aranges entry: {err}");
                    break;
                }
            }
        }
    }
    Ok(result)
}

/// Static-storage variable address and its owning DWARF compilation unit.
/// An address may be mentioned by multiple CUs; callers must resolve
/// conflicting ownership rather than arbitrarily taking the first DIE.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticVariable {
    pub source: String,
    pub address: u64,
    pub name: Option<String>,
}

pub fn static_variables(obj_file: &object::File<'_>) -> Result<Vec<StaticVariable>> {
    if obj_file.section_by_name(".debug_info").is_none() {
        return Ok(Vec::new());
    }
    let sections = gimli::DwarfSections::load(|id| {
        Ok::<_, gimli::Error>(
            obj_file
                .section_by_name(id.name())
                .and_then(|section| section.uncompressed_data().ok())
                .unwrap_or(Cow::Borrowed(&[])),
        )
    })?;
    let endian = match obj_file.endianness() {
        object::Endianness::Little => RunTimeEndian::Little,
        object::Endianness::Big => RunTimeEndian::Big,
    };
    let dwarf = sections.borrow(|data| EndianSlice::new(data, endian));
    let mut result = Vec::new();
    let mut units = dwarf.units();
    loop {
        let header = match units.next() {
            Ok(Some(header)) => header,
            Ok(None) => break,
            Err(err) => {
                eprintln!("Warning: invalid PPU DWARF variable-unit header: {err}");
                break;
            }
        };
        let variables = (|| -> Result<Vec<StaticVariable>> {
            let mut result = Vec::new();
            let unit = dwarf.unit(header)?;
            let mut entries = unit.entries();
            let Some((_, root)) = entries.next_dfs()? else { return Ok(result) };
            let Some(name) = root.attr_value(gimli::DW_AT_name)? else { return Ok(result) };
            let mut source = dwarf.attr_string(&unit, name)?.to_string_lossy().into_owned();
            if !source.contains(['/', '\\']) {
                if let Some(dir) = root.attr_value(gimli::DW_AT_comp_dir)? {
                    source =
                        format!("{}/{}", dwarf.attr_string(&unit, dir)?.to_string_lossy(), source);
                }
            }
            while let Some((_, die)) = entries.next_dfs()? {
                if die.tag() != gimli::DW_TAG_variable {
                    continue;
                }
                // Declarations without storage are not proof of CU ownership.
                if die
                    .attr_value(gimli::DW_AT_declaration)?
                    .and_then(|v| v.udata_value())
                    .is_some_and(|v| v != 0)
                {
                    continue;
                }
                let Some(gimli::AttributeValue::Exprloc(expr)) =
                    die.attr_value(gimli::DW_AT_location)?
                else {
                    continue;
                };
                let mut ops = expr.operations(unit.encoding());
                let Some(gimli::Operation::Address { address }) = ops.next()? else { continue };
                // Locations with more operations are not a plain static address.
                if ops.next()?.is_some() {
                    continue;
                }
                let name = die
                    .attr_value(gimli::DW_AT_linkage_name)?
                    .or(die.attr_value(gimli::DW_AT_MIPS_linkage_name)?)
                    .or(die.attr_value(gimli::DW_AT_name)?);
                let name = match name {
                    Some(value) => dwarf
                        .attr_string(&unit, value)
                        .ok()
                        .map(|name| name.to_string_lossy().into_owned()),
                    None => None,
                };
                result.push(StaticVariable { source: source.clone(), address, name });
            }
            Ok(result)
        })();
        match variables {
            Ok(variables) => result.extend(variables),
            Err(err) => eprintln!("Warning: ignoring unusable PPU DWARF variable unit: {err:#}"),
        }
    }
    Ok(result)
}
