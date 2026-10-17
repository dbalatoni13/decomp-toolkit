//! Recover relocation sites in an already-linked PPU function for signatures.
//! These are *inferred* relocations: linked PS3 ELFs have no original .rela.text.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::ps3::obj::ObjInfo;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SigRelocKind {
    #[serde(rename = "rel24", alias = "PpcRel24")]
    Rel24,
    #[serde(rename = "rel14", alias = "PpcRel14")]
    Rel14,
    #[serde(rename = "addr24", alias = "PpcAddr24")]
    Addr24,
    #[serde(rename = "addr14", alias = "PpcAddr14")]
    Addr14,
    #[serde(rename = "hi", alias = "PpcAddr16Hi")]
    Hi,
    #[serde(rename = "ha", alias = "PpcAddr16Ha")]
    Ha,
    #[serde(rename = "l", alias = "PpcAddr16Lo")]
    Lo,
    #[serde(rename = "lo_ds", alias = "PpcAddr16LoDs")]
    LoDs,
}

impl SigRelocKind {
    pub fn mask(self) -> u32 {
        match self {
            Self::Rel24 | Self::Addr24 => !0x03ff_fffc,
            Self::Rel14 | Self::Addr14 => !0x0000_fffc,
            Self::Hi | Self::Ha | Self::Lo => !0xffff,
            Self::LoDs => !0xfffc,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ResolvedReloc {
    pub offset: u32, // byte offset of relocation field (halfword at +2)
    pub kind: SigRelocKind,
    pub target: u64,
    pub addend: i32,
}

fn ins_at(data: &[u8], i: usize) -> u32 { u32::from_be_bytes(data[i..i + 4].try_into().unwrap()) }

pub fn recover_function_relocations(
    obj: &ObjInfo,
    code_address: u64,
    code: &[u8],
    toc: Option<u64>,
    known_addresses: &BTreeSet<u64>,
) -> Vec<ResolvedReloc> {
    let mut result = Vec::new();
    let valid_target = |target: u64| {
        obj.sections.iter().any(|(_, section)| {
            section.address <= target && target < section.address + section.size
        })
    };
    let mut consumed_low = false;
    for i in (0..code.len()).step_by(4) {
        if consumed_low {
            consumed_low = false;
            continue;
        }
        let ins = ins_at(code, i);
        let opcode = ins >> 26;
        let pc = code_address + i as u64;
        if opcode == 15 && (ins >> 16) & 31 == 0 && i + 8 <= code.len() {
            let next = ins_at(code, i + 4);
            let reg = (ins >> 21) & 31;
            let same_reg = ((next >> 21) & 31) == reg && ((next >> 16) & 31) == reg;
            let target = match (next >> 26, same_reg) {
                (14, true) => {
                    let hi = (ins as u16 as i16) as i64;
                    let lo = (next as u16 as i16) as i64;
                    hi.checked_mul(65536)
                        .and_then(|x| x.checked_add(lo))
                        .and_then(|x| u64::try_from(x).ok())
                }
                (24, true) => Some((u64::from(ins & 0xffff) << 16) | u64::from(next & 0xffff)),
                _ => None,
            };
            if let Some(target) =
                target.filter(|&t| known_addresses.contains(&t) && valid_target(t))
            {
                result.push(ResolvedReloc {
                    offset: i as u32 + 2,
                    kind: if next >> 26 == 14 { SigRelocKind::Ha } else { SigRelocKind::Hi },
                    target,
                    addend: 0,
                });
                result.push(ResolvedReloc {
                    offset: i as u32 + 6,
                    kind: SigRelocKind::Lo,
                    target,
                    addend: 0,
                });
                consumed_low = true;
                continue;
            }
        }
        if opcode == 18 || opcode == 16 {
            let displacement = if opcode == 18 {
                ((ins << 6) as i32 >> 6) as i64 & !3
            } else {
                ((ins as u16 as i16) as i64) & !3
            };
            let dest = if ins & 2 != 0 { displacement } else { pc as i64 + displacement };
            let Some(target) = u64::try_from(dest).ok() else { continue };
            if (code_address..code_address + code.len() as u64).contains(&target)
                || !valid_target(target)
            {
                continue;
            }
            let kind = match (opcode, ins & 2 != 0) {
                (18, false) => SigRelocKind::Rel24,
                (16, false) => SigRelocKind::Rel14,
                (18, true) => SigRelocKind::Addr24,
                _ => SigRelocKind::Addr14,
            };
            result.push(ResolvedReloc { offset: i as u32, kind, target, addend: 0 });
            continue;
        }
        let ra = (ins >> 16) & 31;
        if ra != 2 {
            continue;
        }
        let ds = opcode == 58 || opcode == 62;
        if !ds && !matches!(opcode, 14 | 32..=55) {
            continue;
        }
        let Some(toc) = toc else { continue };
        let signed = (ins as u16 as i16) as i64;
        let displacement = if ds { signed & !3 } else { signed };
        let Some(target) =
            (toc as i64).checked_add(displacement).and_then(|x| u64::try_from(x).ok())
        else {
            continue;
        };
        if !valid_target(target) {
            continue;
        }
        if let Ok(addend) = i32::try_from(-(toc as i64)) {
            result.push(ResolvedReloc {
                offset: i as u32 + 2,
                kind: if ds { SigRelocKind::LoDs } else { SigRelocKind::Lo },
                target,
                addend,
            });
        }
    }
    result
}

pub fn descriptor_tocs(opd: &crate::ps3::util::ppu::PpuOpd) -> BTreeMap<u64, u64> {
    let mut tocs = BTreeMap::new();
    for (_, (code, toc)) in opd.iter() {
        tocs.entry(u64::from(code)).or_insert(u64::from(toc));
    }
    tocs
}
