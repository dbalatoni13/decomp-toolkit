//! Reconstructs PPU relocations from linked ELF instructions and pointer tables.

use std::collections::{BTreeMap, BTreeSet};

use object::elf;

use crate::ps3::{
    obj::{ObjInfo, ObjSectionKind, ObjSymbolKind},
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
    // Calls to a named function in the same output section still need a
    // relocation to identify their callee in objdiff. An unrelocated PPC64
    // `bl` only encodes a section-relative displacement, so it is shown as
    // `bl 0x484` instead of the called function. Restrict this to *actual*
    // function entrypoints: ordinary local branches must not be rewritten.
    let function_entries: BTreeSet<u64> = obj
        .symbols
        .iter()
        .filter(|(_, symbol)| {
            symbol.kind == ObjSymbolKind::Function
                && symbol.section.is_some_and(|i| obj.sections[i].kind == ObjSectionKind::Code)
        })
        .map(|(_, symbol)| symbol.address)
        .collect();
    // A linked .data/.rodata value may point into an object rather than at
    // its beginning. Keep only proven sized object extents as possible targets.
    let mut sized_data = BTreeMap::<u64, u64>::new();
    for (_, sym) in obj.symbols.iter() {
        if sym.kind == crate::ps3::obj::ObjSymbolKind::Object
            && sym.size_known
            && sym.size > 0
            && sym.section.is_some_and(|i| obj.sections[i].kind != ObjSectionKind::Code)
        {
            sized_data
                .entry(sym.address)
                .and_modify(|end| *end = (*end).max(sym.address + sym.size))
                .or_insert(sym.address + sym.size);
        }
    }
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
            // OPD descriptors are ordered by address. Scanning all of them
            // for every short source-owned OPD fragment is quadratic on
            // large PS3 executables (5039 has hundreds of thousands).
            let first = descriptors.partition_point(|d| d.address < p.start);
            for d in descriptors[first..].iter().take_while(|d| d.address + 8 <= p.end) {
                record(d.address, d.code, 0, elf::R_PPC64_ADDR32);
                // Always emit a placeholder relocation at the descriptor's
                // second word. The SDK assembler uses symbol-less type 107
                // there, even when the TOC base is outside every input
                // section (e.g. .toc starts at 0x30000, TOC = 0x38000).
                // `fix_sdk_opd_markers` makes this symbol-less after writing.
                record(d.address + 4, d.code, 0, elf::R_PPC64_ADDR32);
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
                let inside_named_data =
                    sized_data.range(..=target).next_back().is_some_and(|(_, &end)| target < end);
                if target != 0 && (known_addresses.contains(&target) || inside_named_data) {
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
                // Branches can only target executable code. Linked `.text`
                // also contains inline data and jump tables whose words can
                // coincidentally decode as `b`/`bl`. In particular, a word
                // resembling `bl` which resolves into `.bss` is not a valid
                // call and must not become a linker relocation.
                let Some(target_piece) = piece_at(&starts, pieces, dest) else {
                    continue;
                };
                if obj.sections[pieces[target_piece].original_section].kind != ObjSectionKind::Code
                {
                    continue;
                }
                // The runtime's `.init`/`.fini` code already uses its linked
                // executable TOC. Fabricating a cross-object call relocation
                // makes the SDK linker synthesize an additional TOC-switch
                // stub, overflowing the adjacent `.text` section. Retain the
                // original branch until the runtime's original relocation
                // provenance can be recovered.
                if (matches!(source.name.as_str(), ".init" | ".fini")
                    || matches!(
                        obj.sections[pieces[target_piece].original_section].name.as_str(),
                        ".init" | ".fini"
                    ))
                    && opcode == 18
                    && target_piece != index
                {
                    continue;
                }
                // Direct branches into `.sceStub.text` are already resolved
                // import-stub calls, not the original external symbol
                // references. Sony's elf64-ppc.c processes a REL24 to this
                // section by overwriting the following instruction with an
                // r2 restore, even where the linked original contains a nop.
                // Reconstructing such relocations would corrupt the executable;
                // preserve its existing branch displacement instead.
                if opcode == 18
                    && ins & 1 != 0
                    && obj.sections[pieces[target_piece].original_section].name == ".sceStub.text"
                {
                    continue;
                }
                let named_call = opcode == 18 && ins & 1 != 0 && function_entries.contains(&dest);
                if piece_at(&starts, pieces, dest) != Some(index) || named_call {
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
            // `addi r2,r2,imm` updates the TOC base itself, e.g. in an
            // already-linked cross-TOC call stub. It is NOT an access to a
            // symbol at `TOC + imm`; emitting TOC16 here can overflow and
            // replace the original linker-produced TOC-switch sequence.
            if opcode == 14 && (ins >> 21) & 31 == 2 {
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
            // Match the original PS3 GCC output: r2-relative accesses use a
            // TOC-relative relocation against the input `.toc` entry. The
            // original linker supplies the correct TOC base for each group.
            let r_type = if ds { elf::R_PPC64_TOC16_DS } else { elf::R_PPC64_TOC16 };
            record(address + 2, target as u64, 0, r_type);
        }
    }
    (result, targets)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ps3::obj::{ObjArchitecture, ObjKind, ObjSection, ObjSymbol, ObjSymbolKind};

    #[test]
    fn relocates_calls_to_named_functions_in_same_text_piece() {
        let mut code = vec![0; 0x30];
        code[0..4].copy_from_slice(&0x4800_0021_u32.to_be_bytes()); // bl other() at +0x20
        code[4..8].copy_from_slice(&0x419c_000c_u32.to_be_bytes()); // beq +0xc (local)
        code[8..12].copy_from_slice(&0x4800_0009_u32.to_be_bytes()); // bl +0x8 (not a function)
        let obj = ObjInfo::new(
            ObjKind::Executable,
            ObjArchitecture::PowerPc64,
            "test".into(),
            vec![
                ObjSymbol {
                    name: ".caller".into(),
                    address: 0x1000,
                    section: Some(0),
                    kind: ObjSymbolKind::Function,
                    size: 0x20,
                    size_known: true,
                    ..Default::default()
                },
                ObjSymbol {
                    name: ".callee".into(),
                    address: 0x1020,
                    section: Some(0),
                    kind: ObjSymbolKind::Function,
                    size: 0x10,
                    size_known: true,
                    ..Default::default()
                },
            ],
            vec![ObjSection {
                name: ".text".into(),
                kind: ObjSectionKind::Code,
                address: 0x1000,
                size: 0x30,
                data: code,
                align: 4,
                elf_index: 1,
                splits: Default::default(),
            }],
        );
        let pieces = [Piece {
            original_section: 0,
            start: 0x1000,
            end: 0x1030,
            unit: "both.o".into(),
            align: 4,
            name: ".text".into(),
        }];
        let (relocs, targets) = reconstruct_relocations(&obj, &pieces, &[]);
        assert_eq!(relocs[0].len(), 1);
        assert_eq!(relocs[0][0].offset, 0);
        assert_eq!(relocs[0][0].target, 0x1020);
        assert_eq!(relocs[0][0].r_type, elf::R_PPC64_REL24);
        assert!(targets.contains(&0x1020));
    }

    #[test]
    fn ignores_branch_shaped_words_that_point_into_non_executable_sections() {
        let mut code = vec![0; 8];
        code[..4].copy_from_slice(&0x4800_1001u32.to_be_bytes()); // `bl 0x2000` from 0x1000
        let obj = ObjInfo::new(
            ObjKind::Executable,
            ObjArchitecture::PowerPc64,
            "test".into(),
            vec![],
            vec![
                ObjSection {
                    name: ".text".into(),
                    kind: ObjSectionKind::Code,
                    address: 0x1000,
                    size: 8,
                    data: code,
                    align: 4,
                    elf_index: 1,
                    splits: Default::default(),
                },
                ObjSection {
                    name: ".bss".into(),
                    kind: ObjSectionKind::Bss,
                    address: 0x2000,
                    size: 8,
                    data: vec![],
                    align: 4,
                    elf_index: 2,
                    splits: Default::default(),
                },
            ],
        );
        let pieces = [
            Piece {
                original_section: 0,
                start: 0x1000,
                end: 0x1008,
                unit: "a".into(),
                align: 4,
                name: ".text".into(),
            },
            Piece {
                original_section: 1,
                start: 0x2000,
                end: 0x2008,
                unit: "b".into(),
                align: 4,
                name: ".bss".into(),
            },
        ];
        let (relocations, _) = reconstruct_relocations(&obj, &pieces, &[]);
        assert!(relocations.iter().all(Vec::is_empty));
    }

    #[test]
    fn preserves_already_resolved_import_stub_branches() {
        let mut code = vec![0; 16];
        code[0..4].copy_from_slice(&0x4800_1001u32.to_be_bytes()); // bl 0x2000
        code[4..8].copy_from_slice(&0x3860_0001u32.to_be_bytes()); // li r3,1: NOT a nop
        code[8..12].copy_from_slice(&0x4800_0ffdu32.to_be_bytes()); // bl 0x2004
        code[12..16].copy_from_slice(&0x6000_0000u32.to_be_bytes()); // nop: TOC restore slot
        let obj = ObjInfo::new(
            ObjKind::Executable,
            ObjArchitecture::PowerPc64,
            "stub-call-test".into(),
            vec![],
            vec![
                ObjSection {
                    name: ".text".into(),
                    kind: ObjSectionKind::Code,
                    address: 0x1000,
                    size: 16,
                    data: code,
                    align: 4,
                    elf_index: 1,
                    splits: Default::default(),
                },
                ObjSection {
                    name: ".sceStub.text".into(),
                    kind: ObjSectionKind::Code,
                    address: 0x2000,
                    size: 16,
                    data: vec![0; 16],
                    align: 4,
                    elf_index: 2,
                    splits: Default::default(),
                },
            ],
        );
        let pieces = [
            Piece {
                original_section: 0,
                start: 0x1000,
                end: 0x1010,
                unit: "caller".into(),
                align: 4,
                name: ".text".into(),
            },
            Piece {
                original_section: 1,
                start: 0x2000,
                end: 0x2010,
                unit: "import".into(),
                align: 4,
                name: ".sceStub.text".into(),
            },
        ];
        let (relocs, _) = reconstruct_relocations(&obj, &pieces, &[]);
        assert!(relocs.iter().all(Vec::is_empty));
    }

    #[test]
    fn does_not_mistake_toc_base_adjustment_for_toc_access() {
        let obj = ObjInfo::new(
            ObjKind::Executable,
            ObjArchitecture::PowerPc64,
            "test".into(),
            vec![ObjSymbol {
                name: "toc_slot".into(),
                address: 0xF138,
                section: Some(1),
                kind: ObjSymbolKind::Object,
                size: 4,
                size_known: true,
                ..Default::default()
            }],
            vec![
                ObjSection {
                    name: ".text".into(),
                    kind: ObjSectionKind::Code,
                    address: 0x1000,
                    size: 8,
                    data: [0x3842_F138u32.to_be_bytes(), 0x3862_F138u32.to_be_bytes()].concat(),
                    align: 4,
                    elf_index: 1,
                    splits: Default::default(),
                },
                ObjSection {
                    name: ".got".into(),
                    kind: ObjSectionKind::Data,
                    address: 0xF138,
                    size: 4,
                    data: vec![0; 4],
                    align: 4,
                    elf_index: 2,
                    splits: Default::default(),
                },
            ],
        );
        let pieces = [
            Piece {
                original_section: 0,
                start: 0x1000,
                end: 0x1008,
                unit: "code".into(),
                align: 4,
                name: ".text".into(),
            },
            Piece {
                original_section: 1,
                start: 0xF138,
                end: 0xF13C,
                unit: "toc".into(),
                align: 4,
                name: ".got".into(),
            },
        ];
        let descriptors = [Descriptor { address: 0x2000, code: 0x1000, toc: 0x10000 }];
        let (relocs, _) = reconstruct_relocations(&obj, &pieces, &descriptors);
        assert_eq!(relocs[0].len(), 1, "Only the r3 address computation is a TOC16 access");
        assert_eq!(relocs[0][0].offset, 6);
        assert_eq!(relocs[0][0].target, 0xF138);
        assert_eq!(relocs[0][0].r_type, elf::R_PPC64_TOC16);
    }

    #[test]
    fn retains_resolved_branches_between_runtime_and_text_sections() {
        let obj = ObjInfo::new(
            ObjKind::Executable,
            ObjArchitecture::PowerPc64,
            "runtime".into(),
            vec![],
            vec![
                ObjSection {
                    name: ".init".into(),
                    kind: ObjSectionKind::Code,
                    address: 0x1000,
                    size: 8,
                    data: [0x4800_1000u32.to_be_bytes(), [0; 4]].concat(),
                    align: 4,
                    elf_index: 1,
                    splits: Default::default(),
                },
                ObjSection {
                    name: ".text".into(),
                    kind: ObjSectionKind::Code,
                    address: 0x2000,
                    size: 8,
                    data: [0x4800_1001u32.to_be_bytes(), 0x6000_0000u32.to_be_bytes()].concat(),
                    align: 4,
                    elf_index: 2,
                    splits: Default::default(),
                },
                ObjSection {
                    name: ".fini".into(),
                    kind: ObjSectionKind::Code,
                    address: 0x3000,
                    size: 8,
                    data: [0x4bff_f001u32.to_be_bytes(), 0x6000_0000u32.to_be_bytes()].concat(),
                    align: 4,
                    elf_index: 3,
                    splits: Default::default(),
                },
            ],
        );
        let pieces = [
            Piece {
                original_section: 0,
                start: 0x1000,
                end: 0x1008,
                unit: "runtime-init".into(),
                align: 4,
                name: ".init".into(),
            },
            Piece {
                original_section: 1,
                start: 0x2000,
                end: 0x2008,
                unit: "code".into(),
                align: 4,
                name: ".text".into(),
            },
            Piece {
                original_section: 2,
                start: 0x3000,
                end: 0x3008,
                unit: "runtime-fini".into(),
                align: 4,
                name: ".fini".into(),
            },
        ];
        let (relocs, _) = reconstruct_relocations(&obj, &pieces, &[]);
        assert!(relocs.iter().all(Vec::is_empty));
    }
    #[test]
    fn data_pointer_into_sized_bss_object_is_relocated() {
        let obj = ObjInfo::new(
            ObjKind::Executable,
            ObjArchitecture::PowerPc64,
            "test".into(),
            vec![ObjSymbol {
                name: "gTable".into(),
                address: 0x3000,
                section: Some(1),
                size: 12,
                size_known: true,
                kind: ObjSymbolKind::Object,
                ..Default::default()
            }],
            vec![
                ObjSection {
                    name: ".data".into(),
                    kind: ObjSectionKind::Data,
                    address: 0x2000,
                    size: 4,
                    data: 0x3004u32.to_be_bytes().to_vec(),
                    align: 4,
                    elf_index: 1,
                    splits: Default::default(),
                },
                ObjSection {
                    name: ".bss".into(),
                    kind: ObjSectionKind::Bss,
                    address: 0x3000,
                    size: 16,
                    data: vec![],
                    align: 4,
                    elf_index: 2,
                    splits: Default::default(),
                },
            ],
        );
        let pieces = vec![
            Piece {
                original_section: 0,
                start: 0x2000,
                end: 0x2004,
                unit: "a".into(),
                align: 4,
                name: ".data".into(),
            },
            Piece {
                original_section: 1,
                start: 0x3000,
                end: 0x3010,
                unit: "b".into(),
                align: 4,
                name: ".bss".into(),
            },
        ];
        let (relocs, targets) = reconstruct_relocations(&obj, &pieces, &[]);
        assert!(targets.contains(&0x3004));
        assert_eq!(relocs[0].len(), 1);
        assert_eq!(relocs[0][0].target, 0x3004);
        assert_eq!(relocs[0][0].r_type, elf::R_PPC64_ADDR32);
    }
}
