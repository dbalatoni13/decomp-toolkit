//! DTK-style, versioned PPC64 function signatures.
//!
//! As in the original decomp-toolkit, each signature consists of 32-bit
//! instruction words paired with matching masks. Different implementations of
//! a function are separate entries, not a fuzzy union of their instructions.
//! PPC64 PC-relative branch displacements are masked; all register operands,
//! absolute immediates and non-branch instructions stay significant.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    fs,
};

use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use object::{Architecture, Endianness, File, Object, ObjectSection, ObjectSymbol, SymbolKind};
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};
use typed_path::Utf8NativePath;

use crate::ps3::{
    obj::{ObjInfo, ObjSectionKind, ObjSymbol, ObjSymbolFlagSet, ObjSymbolFlags, ObjSymbolKind},
    util::{
        ppu::PpuOpd,
        ppu_split::{load, read_elf},
        signature_reloc::{SigRelocKind, descriptor_tocs, recover_function_relocations},
    },
};

/// A PPU extension of upstream DTK's signature schema. Relative branches and
/// PPC64 TOC-relative DS loads require PPC64-specific relocation kinds.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PpuOutReloc {
    pub offset: u32,
    pub kind: SigRelocKind,
    pub symbol: u32,
    pub addend: i32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FunctionSignature {
    pub symbol: u32,
    pub hash: String,
    pub signature: String,
    pub symbols: Vec<crate::util::signatures::OutSymbol>,
    pub relocations: Vec<PpuOutReloc>,
}

impl FunctionSignature {
    pub fn name(&self) -> &str { &self.symbols[self.symbol as usize].name }

    pub fn size(&self) -> u32 { self.symbols[self.symbol as usize].size }
}

#[derive(Clone, Debug)]
struct CompiledSignature {
    name: String,
    patterns: Vec<(u32, u32)>,
    signature: FunctionSignature,
}

#[derive(Default, Debug)]
pub struct MatchReport {
    pub examined: usize,
    pub matches: usize,
    pub ambiguous: usize,
    pub inserted: usize,
    pub renamed: usize,
}

pub struct MatchResult {
    pub added: Vec<ObjSymbol>,
    pub renames: Vec<(String, String)>,
    pub report: MatchReport,
}

/// For PPU ELFs these are implementation symbols, not PRX import stubs.
/// Only include well-defined SDK and compiler/runtime naming families.
fn family(name: &str) -> Option<&'static str> {
    let n = name.strip_prefix('.')?;
    if n.starts_with("cell") || n.starts_with("sce") || n.starts_with("sys_") {
        return Some("ps3-sdk");
    }
    const LIBC: &[&str] = &[
        "memcpy",
        "memmove",
        "memset",
        "memcmp",
        "memchr",
        "memccpy",
        "strlen",
        "strnlen",
        "strcpy",
        "strncpy",
        "strcmp",
        "strncmp",
        "strcasecmp",
        "strncasecmp",
        "strcat",
        "strncat",
        "strchr",
        "strrchr",
        "strstr",
        "strpbrk",
        "strcspn",
        "strspn",
        "strtok",
        "strdup",
        "strerror",
        "strtol",
        "strtoul",
        "strtod",
        "printf",
        "fprintf",
        "sprintf",
        "snprintf",
        "vprintf",
        "vsprintf",
        "vsnprintf",
        "scanf",
        "sscanf",
        "fopen",
        "fclose",
        "fread",
        "fwrite",
        "fseek",
        "ftell",
        "fflush",
        "malloc",
        "free",
        "calloc",
        "realloc",
        "abort",
        "exit",
        "atexit",
        "qsort",
        "bsearch",
        "powf",
        "expf",
        "logf",
        "sinf",
        "cosf",
        "tanf",
        "sqrtf",
        "floorf",
        "ceilf",
        "atan2f",
        "atanf",
    ];
    if LIBC.contains(&n)
        || n.starts_with("__cxa_")
        || n.starts_with("__gxx_")
        || n.starts_with("_Unwind_")
        || n.starts_with("_ZNSt")
        || n.starts_with("_ZSt")
        || n.starts_with("_ZNS")
        || n.starts_with("_Znwm")
        || n.starts_with("_Znam")
        || n.starts_with("_ZdlPv")
        || n.starts_with("_ZdaPv")
    {
        return Some("gcc-runtime");
    }
    None
}

/// Encode masked instruction words and relocation metadata. Like DTK,
/// relocation sites are masked according to their relocation *kind*, not
/// indiscriminately by instruction opcode.
fn encode_pattern(code: &[u8], relocs: &[PpuOutReloc]) -> (String, String) {
    let mut instructions: Vec<(u32, u32)> = code
        .chunks_exact(4)
        .map(|w| (u32::from_be_bytes(w.try_into().unwrap()), u32::MAX))
        .collect();
    for reloc in relocs {
        let index = (reloc.offset / 4) as usize;
        if let Some((word, mask)) = instructions.get_mut(index) {
            *mask &= reloc.kind.mask();
            *word &= *mask;
        }
    }
    let mut bytes = Vec::with_capacity(instructions.len() * 8);
    for (value, mask) in instructions {
        bytes.extend(value.to_be_bytes());
        bytes.extend(mask.to_be_bytes());
    }
    let hash = format!("{:x}", Sha1::digest(&bytes));
    (hash, STANDARD.encode(bytes))
}

fn compile(sig: &FunctionSignature) -> Result<CompiledSignature> {
    ensure!(sig.symbol as usize == 0 && !sig.symbols.is_empty(), "Invalid function index");
    let size = sig.size();
    ensure!(size >= 16 && size % 4 == 0, "Invalid signature size for {}", sig.name());
    let bytes = STANDARD.decode(&sig.signature).context("Invalid base64 signature")?;
    ensure!(bytes.len() == size as usize * 2, "Invalid signature length for {}", sig.name());
    ensure!(
        format!("{:x}", Sha1::digest(&bytes)) == sig.hash,
        "Signature hash mismatch for {}",
        sig.name()
    );
    let patterns: Vec<_> = bytes
        .chunks_exact(8)
        .map(|c| {
            (
                u32::from_be_bytes(c[0..4].try_into().unwrap()),
                u32::from_be_bytes(c[4..8].try_into().unwrap()),
            )
        })
        .collect();
    for reloc in &sig.relocations {
        ensure!((reloc.symbol as usize) < sig.symbols.len(), "Invalid relocation symbol index");
        ensure!(
            reloc.offset < size
                && reloc.offset % 4
                    == if matches!(
                        reloc.kind,
                        SigRelocKind::Ha | SigRelocKind::Hi | SigRelocKind::Lo | SigRelocKind::LoDs
                    ) {
                        2
                    } else {
                        0
                    },
            "Invalid relocation offset for {}",
            sig.name()
        );
        ensure!(
            patterns[reloc.offset as usize / 4].1 & !reloc.kind.mask() == 0,
            "Unmasked relocation in {}",
            sig.name()
        );
    }
    Ok(CompiledSignature { name: sig.name().to_owned(), patterns, signature: sig.clone() })
}

fn matches(pattern: &[(u32, u32)], code: &[u8]) -> bool {
    code.chunks_exact(4)
        .zip(pattern)
        .all(|(w, &(value, mask))| u32::from_be_bytes(w.try_into().unwrap()) & mask == value)
}

fn to_out_symbol(
    obj: &ObjInfo,
    named_symbols: &HashMap<u64, &ObjSymbol>,
    address: u64,
    fallback: &str,
    default_section: &str,
) -> crate::util::signatures::OutSymbol {
    use crate::obj::{ObjSymbolFlagSet, ObjSymbolFlags, ObjSymbolKind};
    let named = named_symbols.get(&address).copied();
    if let Some(sym) = named {
        let scope = if sym.flags.is_local() {
            ObjSymbolFlags::Local
        } else if sym.flags.is_weak() {
            ObjSymbolFlags::Weak
        } else {
            ObjSymbolFlags::Global
        };
        let section = sym.section.and_then(|i| obj.sections.get(i)).map(|s| s.name.clone());
        crate::util::signatures::OutSymbol {
            kind: if sym.kind == crate::ps3::obj::ObjSymbolKind::Function {
                ObjSymbolKind::Function
            } else if sym.kind == crate::ps3::obj::ObjSymbolKind::Unknown {
                ObjSymbolKind::Unknown
            } else {
                ObjSymbolKind::Object
            },
            name: sym.name.clone(),
            size: if sym.kind == crate::ps3::obj::ObjSymbolKind::Function {
                0
            } else {
                sym.size as u32
            },
            flags: ObjSymbolFlagSet(scope.into()),
            section,
        }
    } else {
        let section = obj
            .sections
            .iter()
            .find(|(_, s)| s.address <= address && address < s.address + s.size)
            .map(|(_, s)| s.name.clone())
            .unwrap_or_else(|| default_section.to_owned());
        crate::util::signatures::OutSymbol {
            kind: ObjSymbolKind::Unknown,
            name: fallback.to_owned(),
            size: 0,
            flags: ObjSymbolFlagSet(ObjSymbolFlags::Local.into()),
            section: Some(section),
        }
    }
}

fn build_signature(
    obj: &ObjInfo,
    named_symbols: &HashMap<u64, &ObjSymbol>,
    name: &str,
    addr: u64,
    code: &[u8],
    toc: Option<u64>,
    known: &BTreeSet<u64>,
) -> FunctionSignature {
    let first = to_out_symbol(obj, named_symbols, addr, name, ".text");
    let first = crate::util::signatures::OutSymbol {
        name: name.to_owned(),
        kind: crate::obj::ObjSymbolKind::Function,
        size: code.len() as u32,
        ..first
    };
    let mut symbols = vec![first];
    let mut symbol_ids = HashMap::<u64, u32>::new();
    symbol_ids.insert(addr, 0);
    let mut relocations = Vec::new();
    for reloc in recover_function_relocations(obj, addr, code, toc, known) {
        let symbol = if let Some(&id) = symbol_ids.get(&reloc.target) {
            id
        } else {
            let id = symbols.len() as u32;
            let fallback = format!("@{:04X}", reloc.offset);
            symbols.push(to_out_symbol(obj, named_symbols, reloc.target, &fallback, ".text"));
            symbol_ids.insert(reloc.target, id);
            id
        };
        relocations.push(PpuOutReloc {
            offset: reloc.offset,
            kind: reloc.kind,
            symbol,
            addend: reloc.addend,
        });
    }
    let (hash, signature) = encode_pattern(code, &relocations);
    FunctionSignature { symbol: 0, hash, signature, symbols, relocations }
}

/// Generate one DTK-style signature per actual function implementation;
/// linked PPU binaries require inferred relocations rather than original RELAs.
pub fn generate(inputs: &[&Utf8NativePath]) -> Result<Vec<FunctionSignature>> {
    ensure!(!inputs.is_empty(), "Provide at least one PS3 PPU ELF");
    let mut variants: BTreeMap<(String, String), FunctionSignature> = BTreeMap::new();
    for path in inputs {
        let bytes = read_elf(path)?;
        let elf = File::parse(bytes.as_slice())?;
        ensure!(
            elf.architecture() == Architecture::PowerPc64
                && elf.endianness() == Endianness::Big
                && elf.is_64(),
            "Expected big-endian PPU ELF64: {path}"
        );
        let obj = load(path)?;
        let opd = PpuOpd::parse(&elf)?;
        let mut named_symbols: HashMap<u64, &ObjSymbol> = HashMap::new();
        for (_, symbol) in obj.symbols.iter() {
            if symbol.section.is_none() {
                continue;
            }
            let best = named_symbols.entry(symbol.address).or_insert(symbol);
            if (symbol.kind == ObjSymbolKind::Function && best.kind != ObjSymbolKind::Function)
                || (!symbol.flags.is_local() && best.flags.is_local())
            {
                *best = symbol;
            }
        }
        let tocs = descriptor_tocs(&opd);
        let mut known: BTreeSet<u64> = obj
            .symbols
            .iter()
            .filter(|(_, s)| s.section.is_some())
            .map(|(_, s)| s.address)
            .collect();
        for (descriptor, (code, toc)) in opd.iter() {
            known.extend([descriptor, u64::from(code), u64::from(toc)]);
        }
        let text = elf.section_by_name(".text").context("Missing .text")?;
        let base = text.address();
        let data = text.data()?;
        for sym in elf.symbols() {
            if sym.section_index() != Some(text.index()) || sym.kind() != SymbolKind::Text {
                continue;
            }
            let name = sym.name()?;
            if family(name).is_none() {
                continue;
            }
            let size = sym.size();
            if !(16..=8192).contains(&size) || size % 4 != 0 {
                continue;
            }
            let Some(start) = sym.address().checked_sub(base).and_then(|n| usize::try_from(n).ok())
            else {
                continue;
            };
            let Some(code) = data.get(start..start.saturating_add(size as usize)) else {
                continue;
            };
            let signature = build_signature(
                &obj,
                &named_symbols,
                name,
                sym.address(),
                code,
                tocs.get(&sym.address()).copied(),
                &known,
            );
            let key = (name.to_owned(), signature.hash.clone());
            // If two linked versions produce the same masked bytes but have
            // different references, retain the more richly reconstructed one.
            match variants.entry(key) {
                std::collections::btree_map::Entry::Vacant(v) => {
                    v.insert(signature);
                }
                std::collections::btree_map::Entry::Occupied(mut v) => {
                    if signature.relocations.len() > v.get().relocations.len() {
                        v.insert(signature);
                    }
                }
            }
        }
    }
    let mut out: Vec<_> = variants.into_values().collect();
    out.sort_by(|a, b| {
        (family(a.name()), a.name(), &a.hash).cmp(&(family(b.name()), b.name(), &b.hash))
    });
    Ok(out)
}

pub fn save(path: &Utf8NativePath, signatures: &[FunctionSignature]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, serde_yaml::to_string(signatures)?)?;
    Ok(())
}

pub fn parse(yaml: &str) -> Result<Vec<FunctionSignature>> {
    let entries: Vec<FunctionSignature> = serde_yaml::from_str(yaml)?;
    for sig in &entries {
        compile(sig)?;
    }
    Ok(entries)
}

// build.rs embeds each per-function YAML file independently, as DTK did.
static BUNDLED_PPU_FILES: &[&str] = include!(concat!(env!("OUT_DIR"), "/ppu_signature_files.rs"));

pub fn bundled() -> Result<Vec<FunctionSignature>> {
    let mut variants = Vec::new();
    for contents in BUNDLED_PPU_FILES {
        variants.extend(parse(contents)?);
    }
    Ok(variants)
}

/// Keep one YAML file per function, with all compiler/SDK variants inside it,
/// analogous to `assets/signatures/memset.yml` in upstream DTK.
pub fn save_directory(dir: &Utf8NativePath, signatures: &[FunctionSignature]) -> Result<usize> {
    let mut by_name = BTreeMap::<&str, Vec<FunctionSignature>>::new();
    for sig in signatures {
        by_name.entry(sig.name()).or_default().push(sig.clone());
    }
    for (name, variants) in &by_name {
        let family = family(variants[0].name()).expect("Generated SDK/GCC function");
        let clean_name = name
            .trim_start_matches('.')
            .chars()
            .filter(|ch| ch.is_ascii_alphanumeric() || *ch == '_')
            .take(48)
            .collect::<String>();
        let digest = format!("{:x}", Sha1::digest(name.as_bytes()));
        let file_name = format!("{}__{}.yml", clean_name, &digest[..12]);
        save(&dir.join(family).join(file_name), variants)?;
    }
    Ok(by_name.len())
}

pub fn load_directory(dir: &Utf8NativePath) -> Result<Vec<FunctionSignature>> {
    let mut result = Vec::new();
    for family in ["gcc-runtime", "ps3-sdk"] {
        let subdir = dir.join(family);
        if !std::fs::metadata(&subdir).is_ok_and(|m| m.is_dir()) {
            continue;
        }
        let mut files = std::fs::read_dir(&subdir)?.collect::<std::io::Result<Vec<_>>>()?;
        files.sort_by_key(|entry| entry.file_name());
        for file in files {
            if file.path().extension().is_some_and(|ext| ext == "yml") {
                result.extend(parse(&std::fs::read_to_string(file.path())?)?);
            }
        }
    }
    Ok(result)
}

/// Match the relocation *relationships* as well as the masked bytes.
/// The linked ELF's original relocations are gone, so PPC64 instruction and
/// TOC decoding supplies the relocation targets. A conflicting original ELF
/// symbol at one of those targets disqualifies this variant.
fn verify_references(
    obj: &ObjInfo,
    by_address: &HashMap<u64, Vec<(u32, String, ObjSymbolKind)>>,
    known: &BTreeSet<u64>,
    toc: Option<u64>,
    address: u64,
    code: &[u8],
    signature: &FunctionSignature,
) -> Option<Vec<(u64, crate::util::signatures::OutSymbol)>> {
    if signature.relocations.is_empty() {
        return Some(Vec::new());
    }
    let actual = recover_function_relocations(obj, address, code, toc, known);
    let by_offset: HashMap<_, _> = actual.iter().map(|r| (r.offset, r)).collect();
    let mut references = BTreeMap::new();
    for relocation in &signature.relocations {
        let found = by_offset.get(&relocation.offset)?;
        if found.kind != relocation.kind {
            return None;
        }
        let expected = &signature.symbols[relocation.symbol as usize];
        if expected.name.starts_with('@') {
            continue;
        }
        if expected.name == signature.name() && found.target != address {
            return None;
        }
        let (_, target_section) = obj.sections.iter().find(|(_, section)| {
            section.address <= found.target && found.target < section.address + section.size
        })?;
        if let Some(section_name) = &expected.section
            && &target_section.name != section_name
        {
            return None;
        }
        if let Some(existing) = by_address.get(&found.target)
            && existing
                .iter()
                .any(|(_, name, _)| !name.starts_with("lbl_") && name != &expected.name)
        {
            return None;
        }
        if found.target != address
            && let Some(previous) = references.insert(found.target, expected.clone())
            && previous.name != expected.name
        {
            return None;
        }
    }
    Some(references.into_iter().collect())
}

/// Only code entries with no original function symbol or a DTK `lbl_*` are
/// eligible. Preexisting ELF names and human-edited labels are never replaced.
/// A signature must be the only *distinct name* matching the target, and
/// cannot simultaneously match another entrypoint under a different name.
/// Exact duplicate functions are therefore intentionally left unnamed.
pub fn identify(
    obj: &mut ObjInfo,
    signatures: &[FunctionSignature],
    descriptors: &PpuOpd,
) -> Result<MatchResult> {
    let mut report = MatchReport::default();
    let mut code_sections = Vec::new();
    for (index, sec) in obj.sections.iter() {
        if sec.kind == ObjSectionKind::Code {
            code_sections.push((index, sec));
        }
    }
    let mut by_address: HashMap<u64, Vec<(u32, String, ObjSymbolKind)>> = HashMap::new();
    let mut names = HashSet::new();
    for (_, sym) in obj.symbols.iter() {
        names.insert(sym.name.clone());
        if let Some(section) = sym.section {
            by_address.entry(sym.address).or_default().push((section, sym.name.clone(), sym.kind));
        }
    }
    let mut candidates = BTreeSet::new();
    let tocs = descriptor_tocs(descriptors);
    let mut known: BTreeSet<u64> = by_address.keys().copied().collect();
    for (descriptor, (code, toc)) in descriptors.iter() {
        known.extend([descriptor, u64::from(code), u64::from(toc)]);
    }
    for (_, (code, _toc)) in descriptors.iter() {
        candidates.insert(u64::from(code));
    }
    // Some stripped symbols are known from branch addresses without `.opd`.
    for (addr, symbols) in &by_address {
        if symbols.iter().any(|(_, name, _)| name.starts_with("lbl_")) {
            candidates.insert(*addr);
        }
    }
    // Different function names sometimes compile to the exact same masked
    // bytes (e.g. distinct C++ constructors/destructors). Such hashes are
    // never safe to use for automatic naming.
    let mut named_hashes = HashMap::<&str, HashSet<&str>>::new();
    for sig in signatures {
        named_hashes.entry(sig.hash.as_str()).or_default().insert(sig.name());
    }
    let mut by_size: HashMap<u32, Vec<CompiledSignature>> = HashMap::new();
    for sig in signatures {
        if named_hashes[&*sig.hash].len() != 1 {
            continue;
        }
        by_size.entry(sig.size()).or_default().push(compile(sig)?);
    }
    let mut established = HashMap::<u32, Vec<(u64, String, u32)>>::new();
    for (_, sym) in obj.symbols.iter() {
        let Some(section_index) = sym.section else {
            continue;
        };
        if sym.kind != ObjSymbolKind::Function
            || !sym.size_known
            || sym.size == 0
            || sym.size > u32::MAX as u64
            || sym.name.starts_with("lbl_")
            || !code_sections.iter().any(|(i, _)| *i == section_index)
        {
            continue;
        }
        established.entry(sym.size as u32).or_default().push((
            sym.address,
            sym.name.clone(),
            section_index,
        ));
    }
    type Proposal =
        (u64, u32, String, Option<String>, u32, Vec<(u64, crate::util::signatures::OutSymbol)>);
    let mut proposed = Vec::<Proposal>::new();
    for address in candidates {
        let Some((section_id, sec)) = code_sections
            .iter()
            .find(|(_, sec)| address >= sec.address && address < sec.address + sec.size)
        else {
            continue;
        };
        let old = by_address.get(&address).map(Vec::as_slice).unwrap_or(&[]);
        if old.iter().any(|(_, name, _)| !name.starts_with("lbl_") && !name.is_empty()) {
            continue;
        }
        let offset = (address - sec.address) as usize;
        report.examined += 1;
        let mut hits =
            BTreeMap::<String, (u32, Vec<(u64, crate::util::signatures::OutSymbol)>)>::new();
        for (&size, list) in &by_size {
            let Some(code) = sec.data.get(offset..offset.saturating_add(size as usize)) else {
                continue;
            };
            for variant in list {
                if matches(&variant.patterns, code)
                    && let Some(references) = verify_references(
                        obj,
                        &by_address,
                        &known,
                        tocs.get(&address).copied(),
                        address,
                        code,
                        &variant.signature,
                    )
                {
                    // Prefer the longest fully matching variant when more than
                    // one version of this same function matches a prefix.
                    let previous = hits.entry(variant.name.clone()).or_default();
                    if size > previous.0
                        || (size == previous.0 && references.len() > previous.1.len())
                    {
                        *previous = (size, references);
                    }
                }
            }
        }
        if hits.len() > 1 {
            report.ambiguous += 1;
            continue;
        }
        let Some((name, (size, references))) = hits.into_iter().next() else {
            continue;
        };
        report.matches += 1;
        let old_name =
            old.iter().find(|(_, name, _)| name.starts_with("lbl_")).map(|(_, n, _)| n.clone());
        proposed.push((address, *section_id, name, old_name, size, references));
    }
    // A standalone 16-byte implementation may match at multiple locations.
    // Only commit a name if it has a single candidate address in this ELF.
    let mut appearances = HashMap::<String, usize>::new();
    for (_, _, name, _, _, _) in &proposed {
        *appearances.entry(name.clone()).or_default() += 1;
    }
    let mut added = Vec::new();
    let mut renames = Vec::new();
    for (address, section, name, old_name, size, references) in proposed {
        if appearances[&name] != 1 || (names.contains(&name) && old_name.as_deref() != Some(&name))
        {
            continue;
        }
        // A matching body at an unrelated already-named function is a false
        // positive risk, even when our source signature database has no
        // collision. Preserve that original symbol instead of guessing.
        let variants = &by_size[&size];
        let contradicts_known = established.get(&size).is_some_and(|functions| {
            functions.iter().any(|&(other_addr, ref other_name, other_section)| {
                if other_name == &name {
                    return false;
                }
                let Some((_, src)) = code_sections.iter().find(|(i, _)| *i == other_section) else {
                    return false;
                };
                let offset = (other_addr - src.address) as usize;
                let Some(code) = src.data.get(offset..offset.saturating_add(size as usize)) else {
                    return false;
                };
                variants
                    .iter()
                    .any(|variant| variant.name == name && matches(&variant.patterns, code))
            })
        });
        if contradicts_known {
            report.ambiguous += 1;
            continue;
        }
        if let Some(old_name) = old_name {
            for sym in obj.symbols.iter_mut() {
                if sym.address == address && sym.section == Some(section) && sym.name == old_name {
                    sym.name = name.clone();
                    sym.kind = ObjSymbolKind::Function;
                    sym.size = u64::from(size);
                    sym.size_known = true;
                }
            }
            renames.push((old_name, name.clone()));
            report.renamed += 1;
        } else {
            let symbol = ObjSymbol {
                name: name.clone(),
                address,
                section: Some(section),
                kind: ObjSymbolKind::Function,
                size: u64::from(size),
                size_known: true,
                flags: ObjSymbolFlagSet(ObjSymbolFlags::Global.into()),
                ..Default::default()
            };
            obj.symbols.push(symbol.clone());
            added.push(symbol);
            report.inserted += 1;
        }
        names.insert(name);
        // A successfully recognized function can identify the functions and
        // data it references, just as DTK's original apply_signature does.
        // Never replace original ELF names or user-edited labels.
        for (target, expected) in references {
            if names.contains(&expected.name) || expected.name.starts_with('@') {
                continue;
            }
            let Some((target_section, target_kind, section_end)) = obj
                .sections
                .iter()
                .find(|(_, sec)| sec.address <= target && target < sec.address + sec.size)
                .map(|(i, sec)| (i, sec.kind, sec.address + sec.size))
            else {
                continue;
            };
            let existing = by_address.get(&target).map(Vec::as_slice).unwrap_or(&[]);
            if existing.iter().any(|(_, old_name, _)| !old_name.starts_with("lbl_")) {
                continue;
            }
            let kind = match expected.kind {
                crate::obj::ObjSymbolKind::Function if target_kind == ObjSectionKind::Code => {
                    ObjSymbolKind::Function
                }
                crate::obj::ObjSymbolKind::Object => ObjSymbolKind::Object,
                _ => ObjSymbolKind::Unknown,
            };
            let size = u64::from(expected.size).min(section_end - target);
            if let Some((_, old_name, _)) =
                existing.iter().find(|(_, old_name, _)| old_name.starts_with("lbl_"))
            {
                for sym in obj.symbols.iter_mut() {
                    if sym.address == target
                        && sym.section == Some(target_section)
                        && sym.name == *old_name
                    {
                        sym.name = expected.name.clone();
                        sym.kind = kind;
                        if size != 0 {
                            sym.size = size;
                            sym.size_known = true;
                        }
                    }
                }
                renames.push((old_name.clone(), expected.name.clone()));
                report.renamed += 1;
            } else {
                let symbol = ObjSymbol {
                    name: expected.name.clone(),
                    address: target,
                    section: Some(target_section),
                    kind,
                    size,
                    size_known: size > 0,
                    flags: ObjSymbolFlagSet(ObjSymbolFlags::Global.into()),
                    ..Default::default()
                };
                obj.symbols.push(symbol.clone());
                added.push(symbol);
                report.inserted += 1;
            }
            names.insert(expected.name);
        }
    }
    Ok(MatchResult { added, renames, report })
}

/// Replace only a generated `lbl_*` definition at the exact name boundary.
/// Never change a manual symbol name or any other part of symbols.txt.
pub fn rename_config_labels(path: &Utf8NativePath, renames: &[(String, String)]) -> Result<()> {
    if renames.is_empty() || fs::metadata(path).is_err() {
        return Ok(());
    }
    let contents = fs::read_to_string(path)?;
    let map: HashMap<&str, &str> = renames.iter().map(|(a, b)| (a.as_str(), b.as_str())).collect();
    let mut output = String::with_capacity(contents.len());
    for line in contents.lines() {
        let Some((head, tail)) = line.split_once(" = ") else {
            output.push_str(line);
            output.push('\n');
            continue;
        };
        output.push_str(map.get(head).copied().unwrap_or(head));
        output.push_str(" = ");
        output.push_str(tail);
        output.push('\n');
    }
    if output != contents {
        fs::write(path, output)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn sample_signature(name: &str, code: &[u8]) -> FunctionSignature {
        let (hash, signature) = encode_pattern(code, &[]);
        FunctionSignature {
            symbol: 0,
            hash,
            signature,
            relocations: vec![],
            symbols: vec![crate::util::signatures::OutSymbol {
                kind: crate::obj::ObjSymbolKind::Function,
                name: name.into(),
                size: code.len() as u32,
                flags: crate::obj::ObjSymbolFlagSet(crate::obj::ObjSymbolFlags::Global.into()),
                section: Some(".text".into()),
            }],
        }
    }
    #[test]
    fn masks_only_relocations_instead_of_all_branches() {
        let code = [
            0x48000005u32.to_be_bytes(),
            0x38600001u32.to_be_bytes(),
            0x4e800020u32.to_be_bytes(),
            0x48000004u32.to_be_bytes(),
        ]
        .concat();
        let mut sig = sample_signature(".cellTest", &code);
        assert_ne!(
            sig.signature,
            encode_pattern(&code, &[PpuOutReloc {
                offset: 0,
                kind: SigRelocKind::Rel24,
                symbol: 0,
                addend: 0
            }])
            .1
        );
        sig.relocations.push(PpuOutReloc {
            offset: 0,
            kind: SigRelocKind::Rel24,
            symbol: 0,
            addend: 0,
        });
        let (hash, pattern) = encode_pattern(&code, &sig.relocations);
        sig.hash = hash;
        sig.signature = pattern;
        assert!(compile(&sig).is_ok());
        let mut relocated = code.clone();
        relocated[..4].copy_from_slice(&0x48000305u32.to_be_bytes());
        assert!(matches(&compile(&sig).unwrap().patterns, &relocated));
        relocated[15] = 0x08;
        assert!(!matches(&compile(&sig).unwrap().patterns, &relocated));
    }
    #[test]
    fn signatures_roundtrip_and_reject_corruption() {
        let code = [0x94, 0x21, 0xff, 0x80, 0x48, 0, 0, 5, 0x38, 0x60, 0, 1, 0x4e, 0x80, 0, 0x20];
        let sig = sample_signature(".cellTest", &code);
        assert!(matches(&compile(&sig).unwrap().patterns, &code));
        let yaml = serde_yaml::to_string(&vec![sig.clone()]).unwrap();
        let parsed = parse(&yaml).unwrap();
        assert_eq!(parsed[0].name(), sig.name());
        assert!(yaml.contains("symbols:") && yaml.contains("relocations:"));
        assert!(!yaml.contains("sources:"));
        let mut invalid = sig;
        invalid.hash = "invalid".into();
        assert!(compile(&invalid).is_err());
    }
    #[test]
    fn distinguishes_runtime_from_game_functions() {
        assert_eq!(family(".cellGcmFlush"), Some("ps3-sdk"));
        assert_eq!(family(".__cxa_throw"), Some("gcc-runtime"));
        assert_eq!(family(".memcpy"), Some("gcc-runtime"));
        assert_eq!(family(".str_find_aux"), None);
        assert_eq!(family("._ZN3Sim8Activity6AttachEv"), None);
    }
    fn mock_opd(code_address: u32) -> PpuOpd {
        use object::{BinaryFormat, Endianness, File, ObjectSection, write::Object as WriteObject};
        let mut writer =
            WriteObject::new(BinaryFormat::Elf, Architecture::PowerPc64, Endianness::Big);
        let sec = writer.add_section(Vec::new(), b".opd".to_vec(), object::SectionKind::Data);
        writer.append_section_data(
            sec,
            &[code_address.to_be_bytes(), 0x2000u32.to_be_bytes()].concat(),
            8,
        );
        let mut bytes = writer.write().unwrap();
        let parsed = File::parse(bytes.as_slice()).unwrap();
        let index = parsed.section_by_name(".opd").unwrap().index().0;
        let header = u64::from_be_bytes(bytes[40..48].try_into().unwrap()) as usize;
        let size = u16::from_be_bytes(bytes[58..60].try_into().unwrap()) as usize;
        bytes[header + index * size + 16..header + index * size + 24]
            .copy_from_slice(&0x3000u64.to_be_bytes());
        PpuOpd::parse(&File::parse(bytes.as_slice()).unwrap()).unwrap()
    }

    #[test]
    fn identifies_and_renames_editable_lbl_but_rejects_ambiguous_signatures() {
        use crate::ps3::obj::{ObjArchitecture, ObjKind, ObjSection};
        let code = [0x94, 0x21, 0xff, 0x80, 0x48, 0, 0, 5, 0x38, 0x60, 0, 1, 0x4e, 0x80, 0, 0x20];
        let sig = sample_signature(".cellExample", &code);
        let create_obj = || {
            ObjInfo::new(
                ObjKind::Executable,
                ObjArchitecture::PowerPc64,
                "mock".into(),
                vec![ObjSymbol {
                    name: "lbl_00001000".into(),
                    address: 0x1000,
                    section: Some(0),
                    kind: ObjSymbolKind::Unknown,
                    flags: ObjSymbolFlagSet(ObjSymbolFlags::Global.into()),
                    ..Default::default()
                }],
                vec![ObjSection {
                    name: ".text".into(),
                    kind: ObjSectionKind::Code,
                    address: 0x1000,
                    size: 16,
                    data: code.to_vec(),
                    align: 4,
                    elf_index: 1,
                    splits: Default::default(),
                }],
            )
        };
        let mut obj = create_obj();
        let result = identify(&mut obj, std::slice::from_ref(&sig), &mock_opd(0x1000)).unwrap();
        assert_eq!(result.report.renamed, 1);
        assert_eq!(result.renames, vec![("lbl_00001000".into(), ".cellExample".into())]);
        assert!(
            obj.symbols
                .iter()
                .any(|(_, s)| s.name == ".cellExample" && s.kind == ObjSymbolKind::Function)
        );
        let mut ambiguous = create_obj();
        let mut colliding = sig.clone();
        colliding.symbols[0].name = ".cellUnrelated".into();
        let result = identify(&mut ambiguous, &[sig, colliding], &mock_opd(0x1000)).unwrap();
        assert_eq!(result.report.renamed, 0);
        assert!(ambiguous.symbols.iter().any(|(_, s)| s.name == "lbl_00001000"));
    }

    #[test]
    fn named_relocation_references_propagate_only_when_unambiguous() {
        use crate::ps3::obj::{ObjArchitecture, ObjKind, ObjSection};
        let code = [
            0x4800_1001u32.to_be_bytes(), // bl 0x2000 from 0x1000
            0x3860_0001u32.to_be_bytes(),
            0x4e80_0020u32.to_be_bytes(),
            0x6000_0000u32.to_be_bytes(),
        ]
        .concat();
        let mut sig = sample_signature(".cellCaller", &code);
        sig.symbols.push(crate::util::signatures::OutSymbol {
            kind: crate::obj::ObjSymbolKind::Function,
            name: ".cellCalled".into(),
            size: 0,
            flags: crate::obj::ObjSymbolFlagSet(crate::obj::ObjSymbolFlags::Global.into()),
            section: Some(".text".into()),
        });
        sig.relocations.push(PpuOutReloc {
            offset: 0,
            kind: SigRelocKind::Rel24,
            symbol: 1,
            addend: 0,
        });
        (sig.hash, sig.signature) = encode_pattern(&code, &sig.relocations);
        let create_obj = || {
            let mut data = vec![0u8; 0x1010];
            data[..code.len()].copy_from_slice(&code);
            ObjInfo::new(
                ObjKind::Executable,
                ObjArchitecture::PowerPc64,
                "mock".into(),
                vec![ObjSymbol {
                    name: "lbl_00001000".into(),
                    address: 0x1000,
                    section: Some(0),
                    flags: ObjSymbolFlagSet(ObjSymbolFlags::Global.into()),
                    ..Default::default()
                }],
                vec![ObjSection {
                    name: ".text".into(),
                    kind: ObjSectionKind::Code,
                    address: 0x1000,
                    size: data.len() as u64,
                    data,
                    align: 4,
                    elf_index: 1,
                    splits: Default::default(),
                }],
            )
        };
        let mut obj = create_obj();
        let result = identify(&mut obj, std::slice::from_ref(&sig), &mock_opd(0x1000)).unwrap();
        assert_eq!(result.report.renamed, 1);
        assert_eq!(result.report.inserted, 1);
        assert!(obj.symbols.iter().any(|(_, s)| {
            s.name == ".cellCalled" && s.address == 0x2000 && s.kind == ObjSymbolKind::Function
        }));

        let mut conflicting = create_obj();
        conflicting.symbols.push(ObjSymbol {
            name: "manually_named_function".into(),
            address: 0x2000,
            section: Some(0),
            flags: ObjSymbolFlagSet(ObjSymbolFlags::Global.into()),
            ..Default::default()
        });
        let result = identify(&mut conflicting, &[sig], &mock_opd(0x1000)).unwrap();
        assert_eq!(result.report.renamed + result.report.inserted, 0);
        assert!(conflicting.symbols.iter().any(|(_, s)| s.name == "lbl_00001000"));
    }

    #[test]
    fn bundled_signatures_have_versions_and_relocation_metadata() {
        let db = bundled().unwrap();
        assert!(
            db.iter().any(|s| family(s.name()) == Some("ps3-sdk") && s.name() == ".cellGcmFlush")
        );
        assert!(
            db.iter().any(|s| family(s.name()) == Some("gcc-runtime") && s.name() == ".memcpy")
        );
        // New SDK releases may supply additional matching function variants.
        assert!(db.iter().filter(|s| s.name() == ".cellGcmFlush").count() >= 2);
        assert!(db.iter().any(|s| !s.relocations.is_empty() && s.symbols.len() > 1));
    }
    #[test]
    #[ignore = "requires target/EBOOT.elf and target/HAWAII_PS3_INTERNAL_UNITY.elf fixtures"]
    fn recovers_stripped_sdk_function_from_both_toolchains_without_overwriting_names() {
        for path in [
            Utf8NativePath::new("target/EBOOT.elf"),
            Utf8NativePath::new("target/HAWAII_PS3_INTERNAL_UNITY.elf"),
        ] {
            let mut obj = crate::ps3::util::ppu_split::load(path).unwrap();
            let target = obj
                .symbols
                .iter()
                .find(|(_, s)| s.name == ".cellGcmFlush" && s.section.is_some())
                .map(|(_, s)| s.address)
                .unwrap();
            for sym in obj.symbols.iter_mut() {
                if sym.name == ".cellGcmFlush" && sym.address == target {
                    sym.name = format!("lbl_{target:08X}");
                    sym.kind = ObjSymbolKind::Unknown;
                }
            }
            let bytes = read_elf(path).unwrap();
            let elf = File::parse(bytes.as_slice()).unwrap();
            let result =
                identify(&mut obj, &bundled().unwrap(), &PpuOpd::parse(&elf).unwrap()).unwrap();
            assert!(
                result
                    .renames
                    .iter()
                    .any(|(old, new)| old == &format!("lbl_{target:08X}") && new == ".cellGcmFlush"),
                "failed to recover SDK name in {path}"
            );
            assert_eq!(
                obj.symbols
                    .iter()
                    .filter(|(_, s)| s.name == ".cellGcmFlush" && s.address == target)
                    .count(),
                1
            );
        }
    }
}
