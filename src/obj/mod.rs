pub mod signatures;
pub mod split;

use std::{
    cmp::min,
    collections::{btree_map, BTreeMap, HashMap},
    hash::{Hash, Hasher},
    ops::{Range, RangeBounds},
};

use anyhow::{anyhow, bail, ensure, Result};
use flagset::{flags, FlagSet};
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};

use crate::util::{comment::MWComment, nested::NestedVec, rel::RelReloc};

flags! {
    #[repr(u8)]
    #[derive(Deserialize_repr, Serialize_repr)]
    pub enum ObjSymbolFlags: u8 {
        Global,
        Local,
        Weak,
        Common,
        Hidden,
        ForceActive,
    }
}

#[derive(Debug, Copy, Clone, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ObjSymbolFlagSet(pub FlagSet<ObjSymbolFlags>);

impl ObjSymbolFlagSet {
    #[inline]
    pub fn is_local(&self) -> bool { self.0.contains(ObjSymbolFlags::Local) }

    #[inline]
    pub fn is_global(&self) -> bool { !self.is_local() }

    #[inline]
    pub fn is_common(&self) -> bool { self.0.contains(ObjSymbolFlags::Common) }

    #[inline]
    pub fn is_weak(&self) -> bool { self.0.contains(ObjSymbolFlags::Weak) }

    #[inline]
    pub fn is_hidden(&self) -> bool { self.0.contains(ObjSymbolFlags::Hidden) }

    #[inline]
    pub fn is_force_active(&self) -> bool { self.0.contains(ObjSymbolFlags::ForceActive) }

    #[inline]
    pub fn set_global(&mut self) {
        self.0 =
            (self.0 & !(ObjSymbolFlags::Local | ObjSymbolFlags::Weak)) | ObjSymbolFlags::Global;
    }
}

#[allow(clippy::derived_hash_with_manual_eq)]
impl Hash for ObjSymbolFlagSet {
    fn hash<H: Hasher>(&self, state: &mut H) { self.0.bits().hash(state) }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum ObjSectionKind {
    Code,
    Data,
    ReadOnlyData,
    Bss,
}

#[derive(Debug, Clone)]
pub struct ObjSection {
    pub name: String,
    pub kind: ObjSectionKind,
    pub address: u64,
    pub size: u64,
    pub data: Vec<u8>,
    pub align: u64,
    pub index: usize,
    /// REL files reference the original ELF section indices
    pub elf_index: usize,
    pub relocations: Vec<ObjReloc>,
    pub original_address: u64,
    pub file_offset: u64,
    pub section_known: bool,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, Default, Serialize, Deserialize)]
pub enum ObjSymbolKind {
    #[default]
    Unknown,
    Function,
    Object,
    Section,
}

#[derive(Debug, Copy, Clone, Default, PartialEq, Eq)]
pub enum ObjDataKind {
    #[default]
    Unknown,
    Byte,
    Byte2,
    Byte4,
    Byte8,
    Float,
    Double,
    String,
    String16,
    StringTable,
    String16Table,
}

#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct ObjSymbol {
    pub name: String,
    pub demangled_name: Option<String>,
    pub address: u64,
    pub section: Option<usize>,
    pub size: u64,
    pub size_known: bool,
    pub flags: ObjSymbolFlagSet,
    pub kind: ObjSymbolKind,
    pub align: Option<u32>,
    pub data_kind: ObjDataKind,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum ObjKind {
    /// Fully linked object
    Executable,
    /// Relocatable object
    Relocatable,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum ObjArchitecture {
    PowerPc,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ObjSplit {
    pub unit: String,
    pub end: u32,
    pub align: Option<u32>,
    pub common: bool,
}

type SymbolIndex = usize;

#[derive(Debug, Clone)]
pub struct ObjSymbols {
    symbols: Vec<ObjSymbol>,
    symbols_by_address: BTreeMap<u32, Vec<SymbolIndex>>,
    symbols_by_name: HashMap<String, Vec<SymbolIndex>>,
}

#[derive(Debug, Clone)]
pub struct ObjInfo {
    pub kind: ObjKind,
    pub architecture: ObjArchitecture,
    pub name: String,
    pub symbols: ObjSymbols,
    pub sections: Vec<ObjSection>,
    pub entry: u64,
    pub mw_comment: MWComment,

    // Linker generated
    pub sda2_base: Option<u32>,
    pub sda_base: Option<u32>,
    pub stack_address: Option<u32>,
    pub stack_end: Option<u32>,
    pub db_stack_addr: Option<u32>,
    pub arena_lo: Option<u32>,
    pub arena_hi: Option<u32>,

    // Extracted
    pub splits: BTreeMap<u32, Vec<ObjSplit>>,
    pub named_sections: BTreeMap<u32, String>,
    pub link_order: Vec<String>,
    pub blocked_ranges: BTreeMap<u32, u32>, // start -> end

    // From extab
    pub known_functions: BTreeMap<u32, u32>,

    // REL
    /// Module ID (0 for main)
    pub module_id: u32,
    pub unresolved_relocations: Vec<RelReloc>,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub enum ObjRelocKind {
    Absolute,
    PpcAddr16Hi,
    PpcAddr16Ha,
    PpcAddr16Lo,
    PpcRel24,
    PpcRel14,
    PpcEmbSda21,
}

#[derive(Debug, Clone)]
pub struct ObjReloc {
    pub kind: ObjRelocKind,
    pub address: u64,
    pub target_symbol: SymbolIndex,
    pub addend: i64,
}

impl ObjSymbols {
    pub fn new(symbols: Vec<ObjSymbol>) -> Self {
        let mut symbols_by_address = BTreeMap::<u32, Vec<SymbolIndex>>::new();
        let mut symbols_by_name = HashMap::<String, Vec<SymbolIndex>>::new();
        for (idx, symbol) in symbols.iter().enumerate() {
            symbols_by_address.nested_push(symbol.address as u32, idx);
            if !symbol.name.is_empty() {
                symbols_by_name.nested_push(symbol.name.clone(), idx);
            }
        }
        Self { symbols, symbols_by_address, symbols_by_name }
    }

    pub fn add(&mut self, in_symbol: ObjSymbol, replace: bool) -> Result<SymbolIndex> {
        let opt = self.at_address(in_symbol.address as u32).find(|(_, symbol)| {
            (symbol.kind == in_symbol.kind ||
                // Replace lbl_* with real symbols
                (symbol.kind == ObjSymbolKind::Unknown && symbol.name.starts_with("lbl_")))
                // Hack to avoid replacing different ABS symbols
                && (symbol.section.is_some() || symbol.name == in_symbol.name)
        });
        let target_symbol_idx = if let Some((symbol_idx, existing)) = opt {
            let size =
                if existing.size_known && in_symbol.size_known && existing.size != in_symbol.size {
                    log::warn!(
                        "Conflicting size for {}: was {:#X}, now {:#X}",
                        existing.name,
                        existing.size,
                        in_symbol.size
                    );
                    if replace {
                        in_symbol.size
                    } else {
                        existing.size
                    }
                } else if in_symbol.size_known {
                    in_symbol.size
                } else {
                    existing.size
                };
            if !replace {
                // Not replacing existing symbol, but update size
                if in_symbol.size_known && !existing.size_known {
                    self.replace(symbol_idx, ObjSymbol {
                        size: in_symbol.size,
                        size_known: true,
                        ..existing.clone()
                    })?;
                }
                return Ok(symbol_idx);
            }
            let new_symbol = ObjSymbol {
                name: in_symbol.name,
                demangled_name: in_symbol.demangled_name,
                address: in_symbol.address,
                section: in_symbol.section,
                size,
                size_known: existing.size_known || in_symbol.size != 0,
                flags: in_symbol.flags,
                kind: in_symbol.kind,
                align: in_symbol.align.or(existing.align),
                data_kind: match in_symbol.data_kind {
                    ObjDataKind::Unknown => existing.data_kind,
                    kind => kind,
                },
            };
            if existing != &new_symbol {
                log::debug!("Replacing {:?} with {:?}", existing, new_symbol);
                self.replace(symbol_idx, new_symbol)?;
            }
            symbol_idx
        } else {
            let target_symbol_idx = self.symbols.len();
            self.add_direct(ObjSymbol {
                name: in_symbol.name,
                demangled_name: in_symbol.demangled_name,
                address: in_symbol.address,
                section: in_symbol.section,
                size: in_symbol.size,
                size_known: in_symbol.size != 0,
                flags: in_symbol.flags,
                kind: in_symbol.kind,
                align: in_symbol.align,
                data_kind: in_symbol.data_kind,
            })?;
            target_symbol_idx
        };
        Ok(target_symbol_idx)
    }

    pub fn add_direct(&mut self, in_symbol: ObjSymbol) -> Result<SymbolIndex> {
        let symbol_idx = self.symbols.len();
        self.symbols_by_address.nested_push(in_symbol.address as u32, symbol_idx);
        if !in_symbol.name.is_empty() {
            self.symbols_by_name.nested_push(in_symbol.name.clone(), symbol_idx);
        }
        self.symbols.push(in_symbol);
        Ok(symbol_idx)
    }

    pub fn at(&self, symbol_idx: SymbolIndex) -> &ObjSymbol { &self.symbols[symbol_idx] }

    pub fn address_of(&self, symbol_idx: SymbolIndex) -> u64 { self.symbols[symbol_idx].address }

    pub fn iter(&self) -> impl DoubleEndedIterator<Item = &ObjSymbol> { self.symbols.iter() }

    pub fn count(&self) -> usize { self.symbols.len() }

    pub fn at_address(
        &self,
        addr: u32,
    ) -> impl DoubleEndedIterator<Item = (SymbolIndex, &ObjSymbol)> {
        self.symbols_by_address
            .get(&addr)
            .into_iter()
            .flatten()
            .map(move |&idx| (idx, &self.symbols[idx]))
    }

    pub fn kind_at_address(
        &self,
        addr: u32,
        kind: ObjSymbolKind,
    ) -> Result<Option<(SymbolIndex, &ObjSymbol)>> {
        let (count, result) = self
            .at_address(addr)
            .filter(|(_, sym)| sym.kind == kind)
            .fold((0, None), |(i, _), v| (i + 1, Some(v)));
        ensure!(count <= 1, "Multiple symbols of kind {:?} at address {:#010X}", kind, addr);
        Ok(result)
    }

    // Iterate over all in address ascending order, including ABS symbols
    pub fn iter_ordered(&self) -> impl DoubleEndedIterator<Item = (SymbolIndex, &ObjSymbol)> {
        self.symbols_by_address
            .iter()
            .flat_map(move |(_, v)| v.iter().map(move |u| (*u, &self.symbols[*u])))
    }

    // Iterate over range in address ascending order, excluding ABS symbols
    pub fn for_range<R>(
        &self,
        range: R,
    ) -> impl DoubleEndedIterator<Item = (SymbolIndex, &ObjSymbol)>
    where
        R: RangeBounds<u32>,
    {
        self.symbols_by_address
            .range(range)
            .flat_map(move |(_, v)| v.iter().map(move |u| (*u, &self.symbols[*u])))
            // Ignore ABS symbols
            .filter(move |(_, sym)| sym.section.is_some())
    }

    pub fn indexes_for_range<R>(
        &self,
        range: R,
    ) -> impl DoubleEndedIterator<Item = (u32, &[SymbolIndex])>
    where
        R: RangeBounds<u32>,
    {
        self.symbols_by_address.range(range).map(|(k, v)| (*k, v.as_ref()))
    }

    pub fn for_section(
        &self,
        section: &ObjSection,
    ) -> impl DoubleEndedIterator<Item = (SymbolIndex, &ObjSymbol)> {
        let section_index = section.index;
        self.for_range(section.address as u32..(section.address + section.size) as u32)
            // TODO required?
            .filter(move |(_, symbol)| symbol.section == Some(section_index))
    }

    pub fn for_name(
        &self,
        name: &str,
    ) -> impl DoubleEndedIterator<Item = (SymbolIndex, &ObjSymbol)> {
        self.symbols_by_name
            .get(name)
            .into_iter()
            .flat_map(move |v| v.iter().map(move |u| (*u, &self.symbols[*u])))
    }

    pub fn by_name(&self, name: &str) -> Result<Option<(SymbolIndex, &ObjSymbol)>> {
        let mut iter = self.for_name(name);
        let result = iter.next();
        if let Some((index, symbol)) = result {
            if let Some((other_index, other_symbol)) = iter.next() {
                bail!(
                    "Multiple symbols with name {}: {} {:?} {:#010X} and {} {:?} {:#010X}",
                    name,
                    index,
                    symbol.kind,
                    symbol.address,
                    other_index,
                    other_symbol.kind,
                    other_symbol.address
                );
            }
        }
        Ok(result)
    }

    pub fn by_kind(&self, kind: ObjSymbolKind) -> impl Iterator<Item = (SymbolIndex, &ObjSymbol)> {
        self.symbols.iter().enumerate().filter(move |(_, sym)| sym.kind == kind)
    }

    pub fn replace(&mut self, index: SymbolIndex, symbol: ObjSymbol) -> Result<()> {
        let symbol_ref = &mut self.symbols[index];
        ensure!(symbol_ref.address == symbol.address, "Can't modify address with replace_symbol");
        if symbol_ref.name != symbol.name {
            if !symbol_ref.name.is_empty() {
                self.symbols_by_name.nested_remove(&symbol_ref.name, &index);
            }
            if !symbol.name.is_empty() {
                self.symbols_by_name.nested_push(symbol.name.clone(), index);
            }
        }
        *symbol_ref = symbol;
        Ok(())
    }

    // Try to find a previous sized symbol that encompasses the target
    pub fn for_relocation(
        &self,
        target_addr: u32,
        reloc_kind: ObjRelocKind,
    ) -> Result<Option<(SymbolIndex, &ObjSymbol)>> {
        let mut result = None;
        for (_addr, symbol_idxs) in self.indexes_for_range(..=target_addr).rev() {
            let symbol_idx = if symbol_idxs.len() == 1 {
                symbol_idxs.first().cloned().unwrap()
            } else {
                let mut symbol_idxs = symbol_idxs.to_vec();
                symbol_idxs.sort_by_key(|&symbol_idx| {
                    let symbol = self.at(symbol_idx);
                    let mut rank = match symbol.kind {
                        ObjSymbolKind::Function | ObjSymbolKind::Object => match reloc_kind {
                            ObjRelocKind::PpcAddr16Hi
                            | ObjRelocKind::PpcAddr16Ha
                            | ObjRelocKind::PpcAddr16Lo => 1,
                            ObjRelocKind::Absolute
                            | ObjRelocKind::PpcRel24
                            | ObjRelocKind::PpcRel14
                            | ObjRelocKind::PpcEmbSda21 => 2,
                        },
                        // Label
                        ObjSymbolKind::Unknown => match reloc_kind {
                            ObjRelocKind::PpcAddr16Hi
                            | ObjRelocKind::PpcAddr16Ha
                            | ObjRelocKind::PpcAddr16Lo
                                if !symbol.name.starts_with("..") =>
                            {
                                3
                            }
                            _ => 1,
                        },
                        ObjSymbolKind::Section => -1,
                    };
                    if symbol.size > 0 {
                        rank += 1;
                    }
                    -rank
                });
                match symbol_idxs.first().cloned() {
                    Some(v) => v,
                    None => continue,
                }
            };
            let symbol = self.at(symbol_idx);
            if symbol.address == target_addr as u64 {
                result = Some((symbol_idx, symbol));
                break;
            }
            if symbol.size > 0 {
                if symbol.address + symbol.size > target_addr as u64 {
                    result = Some((symbol_idx, symbol));
                }
                break;
            }
        }
        Ok(result)
    }
}

impl ObjInfo {
    pub fn new(
        kind: ObjKind,
        architecture: ObjArchitecture,
        name: String,
        symbols: Vec<ObjSymbol>,
        sections: Vec<ObjSection>,
    ) -> Self {
        Self {
            kind,
            architecture,
            name,
            symbols: ObjSymbols::new(symbols),
            sections,
            entry: 0,
            mw_comment: Default::default(),
            sda2_base: None,
            sda_base: None,
            stack_address: None,
            stack_end: None,
            db_stack_addr: None,
            arena_lo: None,
            arena_hi: None,
            splits: Default::default(),
            named_sections: Default::default(),
            link_order: vec![],
            blocked_ranges: Default::default(),
            known_functions: Default::default(),
            module_id: 0,
            unresolved_relocations: vec![],
        }
    }

    pub fn add_symbol(&mut self, in_symbol: ObjSymbol, replace: bool) -> Result<SymbolIndex> {
        match in_symbol.name.as_str() {
            "_SDA_BASE_" => self.sda_base = Some(in_symbol.address as u32),
            "_SDA2_BASE_" => self.sda2_base = Some(in_symbol.address as u32),
            "_stack_addr" => self.stack_address = Some(in_symbol.address as u32),
            "_stack_end" => self.stack_end = Some(in_symbol.address as u32),
            "_db_stack_addr" => self.db_stack_addr = Some(in_symbol.address as u32),
            "__ArenaLo" => self.arena_lo = Some(in_symbol.address as u32),
            "__ArenaHi" => self.arena_hi = Some(in_symbol.address as u32),
            _ => {}
        }
        self.symbols.add(in_symbol, replace)
    }

    pub fn section_at(&self, addr: u32) -> Result<&ObjSection> {
        self.sections
            .iter()
            .find(|s| s.contains(addr))
            .ok_or_else(|| anyhow!("Failed to locate section @ {:#010X}", addr))
    }

    pub fn section_for(&self, range: Range<u32>) -> Result<&ObjSection> {
        self.sections.iter().find(|s| s.contains_range(range.clone())).ok_or_else(|| {
            anyhow!("Failed to locate section @ {:#010X}-{:#010X}", range.start, range.end)
        })
    }

    pub fn section_data(&self, start: u32, end: u32) -> Result<(&ObjSection, &[u8])> {
        let section = self.section_at(start)?;
        let data = if end == 0 {
            &section.data[(start as u64 - section.address) as usize..]
        } else {
            &section.data[(start as u64 - section.address) as usize
                ..min(section.data.len(), (end as u64 - section.address) as usize)]
        };
        Ok((section, data))
    }

    /// Locate an existing split for the given address.
    pub fn split_for(&self, address: u32) -> Option<(u32, &ObjSplit)> {
        match self.splits_for_range(..=address).last() {
            Some((addr, split)) if split.end == 0 || split.end > address => Some((addr, split)),
            _ => None,
        }
    }

    /// Locate existing splits within the given address range.
    pub fn splits_for_range<R>(&self, range: R) -> impl Iterator<Item = (u32, &ObjSplit)>
    where R: RangeBounds<u32> {
        self.splits.range(range).flat_map(|(addr, v)| v.iter().map(move |u| (*addr, u)))
    }

    pub fn add_split(&mut self, address: u32, split: ObjSplit) {
        log::debug!("Adding split @ {:#010X}: {:?}", address, split);
        // TODO merge with preceding split if possible
        self.splits.entry(address).or_default().push(split);
    }
}

impl ObjSection {
    pub fn build_relocation_map(&self) -> Result<BTreeMap<u32, usize>> {
        let mut relocations = BTreeMap::new();
        for (idx, reloc) in self.relocations.iter().enumerate() {
            let address = reloc.address as u32;
            match relocations.entry(address) {
                btree_map::Entry::Vacant(e) => {
                    e.insert(idx);
                }
                btree_map::Entry::Occupied(_) => bail!("Duplicate relocation @ {address:#010X}"),
            }
        }
        Ok(relocations)
    }

    pub fn build_relocation_map_cloned(&self) -> Result<BTreeMap<u32, ObjReloc>> {
        let mut relocations = BTreeMap::new();
        for reloc in self.relocations.iter().cloned() {
            let address = reloc.address as u32;
            match relocations.entry(address) {
                btree_map::Entry::Vacant(e) => {
                    e.insert(reloc);
                }
                btree_map::Entry::Occupied(_) => bail!("Duplicate relocation @ {address:#010X}"),
            }
        }
        Ok(relocations)
    }

    #[inline]
    pub fn contains(&self, addr: u32) -> bool {
        (self.address..self.address + self.size).contains(&(addr as u64))
    }

    #[inline]
    pub fn contains_range(&self, range: Range<u32>) -> bool {
        (range.start as u64) >= self.address && (range.end as u64) <= self.address + self.size
    }
}

pub fn section_kind_for_section(section_name: &str) -> Result<ObjSectionKind> {
    Ok(match section_name {
        ".init" | ".text" | ".dbgtext" | ".vmtext" => ObjSectionKind::Code,
        ".ctors" | ".dtors" | ".rodata" | ".sdata2" | "extab" | "extabindex" => {
            ObjSectionKind::ReadOnlyData
        }
        ".bss" | ".sbss" | ".sbss2" => ObjSectionKind::Bss,
        ".data" | ".sdata" => ObjSectionKind::Data,
        name => bail!("Unknown section {name}"),
    })
}
