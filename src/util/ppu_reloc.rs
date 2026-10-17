//! Reconstructs PPU relocations from linked ELF instructions and pointer tables.

use std::collections::{BTreeMap, BTreeSet};

use object::elf;

use crate::{
    obj::{ObjInfo, ObjSectionKind},
    util::ppu_split::Piece,
};

#[derive(Debug, Clone)]
pub(super) struct Descriptor {
    pub(super) address: u64,
    pub(super) code: u64,
    pub(super) toc: u64,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct RelocSpec {
    pub(super) offset: u64,
    pub(super) target: u64,
    pub(super) addend: i64,
    pub(super) r_type: u32,
}

pub(super) fn piece_at(
    starts: &BTreeMap<u64, usize>,
    pieces: &[Piece],
    address: u64,
) -> Option<usize> {
    let (_, &index) = starts.range(..=address).next_back()?;
    (address < pieces[index].end).then_some(index)
}

pub(super) fn reconstruct_relocations(
    obj: &ObjInfo,
    pieces: &[Piece],
    descriptors: &[Descriptor],
) -> (Vec<Vec<RelocSpec>>, BTreeSet<u64>) {
    let starts: BTreeMap<_, _> = pieces.iter().enumerate().map(|(i, p)| (p.start, i)).collect();
    let mut result = vec![Vec::new(); pieces.len()];
    let mut targets = BTreeSet::new();
    let mut function_tocs = BTreeMap::new();
    let mut known_addresses: BTreeSet<u64> = obj
        .symbols
        .iter()
        .filter(|(_, symbol)| symbol.section.is_some())
        .map(|(_, symbol)| symbol.address)
        .collect();
    for d in descriptors {
        function_tocs.entry(d.code).or_insert(d.toc);
        known_addresses.extend([d.address, d.code, d.toc]);
    }
    targets.insert(obj.entry.unwrap_or_default());
    for (index, p) in pieces.iter().enumerate() {
        let source = &obj.sections[p.original_section];
        if source.kind == ObjSectionKind::Bss {
            continue;
        }
        let mut record = |address: u64, target: u64, addend: i64, r_type: u32| {
            if piece_at(&starts, pieces, target).is_none() {
                return;
            }
            result[index].push(RelocSpec { offset: address - p.start, target, addend, r_type });
            targets.insert(target);
        };
        if source.name == ".opd" {
            for d in descriptors.iter().filter(|d| d.address >= p.start && d.address + 8 <= p.end) {
                record(d.address, d.code, 0, elf::R_PPC64_ADDR32);
                record(d.address + 4, d.toc, 0, elf::R_PPC64_ADDR32);
            }
        } else if matches!(
            source.name.as_str(),
            ".got"
                | ".toc"
                | ".toc1"
                | ".ctors"
                | ".dtors"
                | ".jcr"
                | ".data.rel.ro"
                | ".data"
                | ".rodata"
                | ".data.sceFStub"
        ) {
            for address in (p.start + (4 - p.start % 4) % 4..p.end.saturating_sub(3)).step_by(4) {
                let offset = (address - source.address) as usize;
                let target = u64::from(u32::from_be_bytes(
                    source.data[offset..offset + 4].try_into().unwrap(),
                ));
                if known_addresses.contains(&target) {
                    record(address, target, 0, elf::R_PPC64_ADDR32);
                }
            }
        }
        if source.kind != ObjSectionKind::Code {
            continue;
        }
        let mut consumed_low = BTreeSet::new();
        for address in (p.start..p.end.saturating_sub(3)).step_by(4) {
            if consumed_low.remove(&address) {
                continue;
            }
            let offset = (address - source.address) as usize;
            let ins = u32::from_be_bytes(source.data[offset..offset + 4].try_into().unwrap());
            let opcode = ins >> 26;
            if opcode == 15 && (ins >> 16) & 31 == 0 && address + 8 <= p.end {
                let next =
                    u32::from_be_bytes(source.data[offset + 4..offset + 8].try_into().unwrap());
                let reg = (ins >> 21) & 31;
                let matched = ((next >> 21) & 31) == reg && ((next >> 16) & 31) == reg;
                let target = match (next >> 26, matched) {
                    (14, true) => {
                        let hi = (ins as u16 as i16) as i64;
                        let lo = (next as u16 as i16) as i64;
                        hi.checked_mul(65536)
                            .and_then(|v| v.checked_add(lo))
                            .filter(|v| *v >= 0)
                            .map(|v| v as u64)
                    }
                    (24, true) => Some((u64::from(ins & 0xffff) << 16) | u64::from(next & 0xffff)),
                    _ => None,
                };
                if let Some(target) = target.filter(|t| known_addresses.contains(t)) {
                    let hi_type = if next >> 26 == 14 {
                        elf::R_PPC64_ADDR16_HA
                    } else {
                        elf::R_PPC64_ADDR16_HI
                    };
                    record(address + 2, target, 0, hi_type);
                    record(address + 6, target, 0, elf::R_PPC64_ADDR16_LO);
                    consumed_low.insert(address + 4);
                    continue;
                }
            }
            if opcode == 18 || opcode == 16 {
                let displacement = if opcode == 18 {
                    ((ins << 6) as i32 >> 6) as i64 & !3
                } else {
                    ((ins as u16 as i16) as i64) & !3
                };
                let dest =
                    if (ins & 2) != 0 { displacement } else { address as i64 + displacement };
                if dest < 0 {
                    continue;
                }
                let dest = dest as u64;
                if piece_at(&starts, pieces, dest) != Some(index) {
                    let r_type = match (opcode, ins & 2 != 0) {
                        (18, false) => elf::R_PPC64_REL24,
                        (16, false) => elf::R_PPC64_REL14,
                        (18, true) => elf::R_PPC64_ADDR24,
                        _ => elf::R_PPC64_ADDR14,
                    };
                    record(address, dest, 0, r_type);
                }
                continue;
            }
            let ra = (ins >> 16) & 31;
            if ra != 2 {
                continue;
            }
            let ds = opcode == 58 || opcode == 62;
            let dform = matches!(opcode, 14 | 32..=55);
            if !ds && !dform {
                continue;
            }
            let Some((_, &toc)) = function_tocs.range(..=address).next_back() else {
                continue;
            };
            let signed = (ins as u16 as i16) as i64;
            let displacement = if ds { signed & !3 } else { signed };
            let Some(target) = (toc as i64).checked_add(displacement) else {
                continue;
            };
            if target < 0 {
                continue;
            }
            let r_type = if ds { elf::R_PPC64_ADDR16_LO_DS } else { elf::R_PPC64_ADDR16_LO };
            record(address + 2, target as u64, -(toc as i64), r_type);
        }
    }
    (result, targets)
}
