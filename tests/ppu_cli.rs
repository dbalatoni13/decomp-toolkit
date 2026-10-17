//! Opt-in end-to-end tests for the large PS3 PPU ELF fixtures in `target/`.

use std::{
    env, fs, io,
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

use object::{
    Architecture, BinaryFormat, Endianness, Object, ObjectKind, ObjectSection, ObjectSymbol,
    RelocationFlags, RelocationTarget, SymbolScope, elf,
};

struct ScratchDir(PathBuf);

impl ScratchDir {
    fn new(label: &str) -> io::Result<Self> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        for attempt in 0..16 {
            let path = env::temp_dir()
                .join(format!("kevin-ppu-{label}-{}-{now}-{attempt}", std::process::id()));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(err) if err.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(err) => return Err(err),
            }
        }
        Err(io::Error::new(io::ErrorKind::AlreadyExists, "No unique scratch directory"))
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); }
}

fn run_kevin(subcommand: &str, input: &Path, output: &Path) {
    let result = Command::new(env!("CARGO_BIN_EXE_kevin"))
        .args(["elf", subcommand])
        .arg(input)
        .arg(output)
        .output()
        .expect("Failed to start kevin");
    assert!(
        result.status.success(),
        "kevin elf {} failed ({}):\nstdout:\n{}\nstderr:\n{}",
        subcommand,
        result.status,
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr),
    );
}

/// The original PS3 linker is the only supported linker for PPU output.
/// Provide absolute WIBO and PPU_LD environment paths to exercise it.
fn original_linker() -> Option<(PathBuf, PathBuf)> {
    let wibo = env::var_os("WIBO").map(PathBuf::from)?;
    let linker = env::var_os("PPU_LD").map(PathBuf::from)?;
    assert!(wibo.is_file(), "WIBO does not exist: {}", wibo.display());
    assert!(linker.is_file(), "PPU_LD does not exist: {}", linker.display());
    Some((wibo, linker))
}

fn verify_original_relocatable_link(wibo: &Path, linker: &Path, output_dir: &Path, order: &str) {
    let mut command = Command::new(wibo);
    command.current_dir(output_dir).arg(linker).args(["-r", "-o", "combined.o"]);
    for line in order.lines().filter(|line| !line.trim().is_empty()) {
        command.arg(line.split_whitespace().next().unwrap());
    }
    let result = command.output().expect("Failed to run original ppu-lv2-ld");
    assert!(
        result.status.success(),
        "ppu-lv2-ld -r failed:\n{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let output =
        fs::read(output_dir.join("combined.o")).expect("Missing original SDK linked object");
    let file = object::File::parse(output.as_slice()).expect("Invalid original SDK linked object");
    assert_eq!(file.kind(), ObjectKind::Relocatable);
    assert_eq!(file.architecture(), Architecture::PowerPc64);
}

fn test_fixture(
    fixture: &str,
    expected_toc_anchors: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let input = Path::new(env!("CARGO_MANIFEST_DIR")).join("target").join(fixture);
    assert!(input.is_file(), "Missing PS3 ELF fixture: {}", input.display());

    let scratch = ScratchDir::new(fixture)?;
    let split_dir = scratch.0.join("split");
    let config_dir = split_dir.join("config");
    run_kevin("split", &input, &split_dir);
    let splits = fs::read_to_string(config_dir.join("splits.txt"))?;
    let symbols_path = config_dir.join("symbols.txt");
    let symbols = fs::read_to_string(&symbols_path)?;
    assert!(
        symbols.lines().any(|line| line.starts_with("lbl_")),
        "Inferred relocation labels must be editable in symbols.txt"
    );
    if fixture == "EBOOT.elf" {
        // Test the intended DTK workflow: rename an inferred label, rerun
        // config, then use it as an external relocation in another object.
        let original = "lbl_009BBEF0 =";
        let renamed = "custom_data_anchor_009BBEF0 =";
        assert!(symbols.contains(original));
        let edited = symbols.replacen(original, renamed, 1);
        fs::write(&symbols_path, &edited)?;
        run_kevin("split", &input, &split_dir);
        assert_eq!(
            fs::read_to_string(&symbols_path)?,
            edited,
            "Regenerating config must preserve edited label names"
        );
    }
    assert!(!splits.contains("sections/text.o:"), "Unidentified code must use auto units");
    assert!(
        splits.lines().filter(|line| line.starts_with("auto_") && line.ends_with("_text:")).count()
            > 0,
        "Expected DTK-style auto text units for unattributed code"
    );
    for name in ["config.yml", "symbols.txt", "splits.txt"] {
        let path = config_dir.join(name);
        assert!(fs::metadata(&path)?.len() > 0, "Empty {name} for {fixture}");
    }

    let order = fs::read_to_string(split_dir.join("link_order.txt"))?;
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(split_dir.join("config.json"))?)?;
    let units = manifest["units"].as_array().expect("Missing DTK-compatible units array");
    assert_eq!(units.len(), order.lines().count(), "config.json must contain every unit");
    assert_eq!(manifest["module_id"], 0);
    assert_eq!(manifest["modules"], serde_json::json!([]));
    for (unit, line) in units.iter().zip(order.lines()) {
        let (rel, name) = line.split_once(" # ").expect("Missing unit name");
        assert_eq!(unit["name"], name);
        assert_eq!(unit["object"], split_dir.join(rel).to_string_lossy().as_ref());
        assert!(unit["autogenerated"].is_boolean());
    }
    let toc_bases = fs::read_to_string(split_dir.join("toc_bases.txt"))?;
    assert_eq!(
        toc_bases.lines().filter(|line| !line.trim().is_empty()).count(),
        expected_toc_anchors
    );

    let mut object_count = 0;
    let mut opd_relocations = 0;
    let mut generated_labels = 0;
    let mut toc16_users = 0;
    for line in order.lines().filter(|line| !line.trim().is_empty()) {
        let relative = line.split_whitespace().next().unwrap();
        let object_path = split_dir.join(relative);
        let bytes = fs::read(&object_path)?;
        let file = object::File::parse(bytes.as_slice())?;
        assert_eq!(file.format(), BinaryFormat::Elf, "{}", object_path.display());
        assert!(file.is_64(), "{}", object_path.display());
        assert_eq!(file.endianness(), Endianness::Big, "{}", object_path.display());
        assert_eq!(file.architecture(), Architecture::PowerPc64, "{}", object_path.display());
        assert_eq!(file.kind(), ObjectKind::Relocatable, "{}", object_path.display());
        if let Some(opd) = file.section_by_name(".opd") {
            opd_relocations += opd.relocations().count();
        }
        if file.sections().any(|section| {
            section.relocations().any(|(_, relocation)| {
                matches!(relocation.flags(), RelocationFlags::Elf { r_type }
                if matches!(r_type, elf::R_PPC64_TOC16 | elf::R_PPC64_TOC16_DS))
            })
        }) {
            toc16_users += 1;
            assert!(
                file.section_by_name(".toc").is_some(),
                "Missing .toc section for original compiler TOC16 relocations in {relative}"
            );
        }
        for symbol in file.symbols() {
            let name = symbol.name()?;
            assert!(!name.starts_with("__kevin_addr_"), "Legacy synthetic symbol in {relative}");
            if name.starts_with("lbl_") {
                generated_labels += 1;
            }
        }
        object_count += 1;
    }
    assert!(order.lines().any(|line| line.starts_with("obj/auto_")), "Missing auto objects");
    assert!(!order.contains("obj/sections/text.o"), "Legacy catch-all text object remains");
    assert!(object_count > 0, "No split objects generated for {fixture}");
    assert!(opd_relocations > 0, "No .opd relocations generated for {fixture}");
    assert!(toc16_users > 0, "No original compiler TOC16 relocations for {fixture}");
    assert!(generated_labels > 0, "Expected DTK-style lbl_ symbols for unnamed targets");
    let linker_script = fs::read_to_string(split_dir.join("link.ld"))?;
    assert!(linker_script.contains("ENTRY(") && !linker_script.contains("__kevin_addr_"));
    if fixture == "EBOOT.elf" {
        let source =
            "EAX-BUILD1-S04-PS3/Carbon/Branches/LeadPlat/Speed/Indep/SourceLists/zAI.cpp.o";
        let bytes = fs::read(split_dir.join("obj").join(source))?;
        let z_ai = object::File::parse(bytes.as_slice())?;
        for name in [".data", ".rodata", ".bss"] {
            let section = z_ai
                .section_by_name(name)
                .unwrap_or_else(|| panic!("Missing DWARF-owned {name} in zAI.cpp.o"));
            assert!(section.size() > 0, "Empty zAI.cpp.o {name}");
        }
        assert!(
            z_ai.section_by_name(".rela.data").is_some(),
            "Data pointers were not reconstructed as relocations"
        );
        let meaningful_got_reference = z_ai
            .sections()
            .flat_map(|section| section.relocations())
            .filter_map(|(_, reloc)| match reloc.target() {
                RelocationTarget::Symbol(index) => z_ai.symbol_by_index(index).ok(),
                _ => None,
            })
            .any(|sym| {
                sym.name().is_ok_and(|name| name.starts_with("__got_") && name.contains("_009A"))
            });
        assert!(
            meaningful_got_reference,
            "Expected GOT references to identify underlying data symbols"
        );
        for suffix in ["C1", "C2"] {
            let symbol_name = format!("._ZN16AITrafficManager{suffix}EN3Sim5ParamE");
            let constructor = z_ai
                .symbols()
                .find(|sym| sym.name().is_ok_and(|name| name == symbol_name))
                .expect("Missing AITrafficManager constructor in zAI.cpp.o");
            assert_eq!(constructor.scope(), SymbolScope::Dynamic);
            assert_eq!(constructor.size(), 1500);
        }
        let names = [
            "._ZThn64_N3Sim8Activity6AttachEPN3UTL3COM8IUnknownE",
            "._ZThn48_N3Sim8Activity6AttachEPN3UTL3COM8IUnknownE",
            "._ZN3Sim8Activity6AttachEPN3UTL3COM8IUnknownE",
        ];
        let target_sections: Vec<_> = names
            .iter()
            .map(|name| {
                let symbol = z_ai
                    .symbols()
                    .find(|sym| sym.name().is_ok_and(|n| n == *name))
                    .expect("Missing Sim::Activity::Attach method/thunk");
                symbol.section_index().expect("Method/thunk has no section")
            })
            .collect();
        assert!(target_sections.iter().all(|&ix| ix == target_sections[0]));
        let group = z_ai.section_by_index(target_sections[0])?;
        assert_eq!(group.name()?, ".gnu.linkonce.t._ZN3Sim8Activity6AttachEPN3UTL3COM8IUnknownE");
        assert_eq!(group.size(), 76);
        // A cross-object bl must refer to the real dot-prefixed PPC64 code
        // symbol, rather than a synthetic address label.
        let caller_path =
            split_dir.join("obj/packages/spch/3.20.05/source/library/cmn/spchcsis.cpp.o");
        let caller_bytes = fs::read(&caller_path)?;
        let caller = object::File::parse(caller_bytes.as_slice())?;
        // With per-CU TOC ownership, this label may now be *defined* in the
        // caller object rather than referenced as an undefined external.
        // What matters is that the actual relocation uses the editable name.
        assert!(
            caller.sections().flat_map(|section| section.relocations()).any(|(_, relocation)| {
                match relocation.target() {
                    RelocationTarget::Symbol(index) => caller
                        .symbol_by_index(index)
                        .is_ok_and(|sym| sym.name().ok() == Some("custom_data_anchor_009BBEF0")),
                    _ => false,
                }
            }),
            "The caller's TOC relocation did not use the renamed DTK label"
        );
        let call =
            caller.sections().flat_map(|section| section.relocations()).find_map(|(_, reloc)| {
                match reloc.target() {
                    RelocationTarget::Symbol(index) => caller
                        .symbol_by_index(index)
                        .ok()
                        .filter(|sym| sym.name().ok() == Some("._Z20SPCHDBG_abortmessagePcz"))
                        .map(|sym| (reloc.flags(), sym.is_undefined())),
                    _ => None,
                }
            });
        let (flags, undefined) =
            call.expect("Cross-object call to SPCHDBG_abortmessage lost its real name");
        assert!(matches!(flags, RelocationFlags::Elf { r_type } if r_type == elf::R_PPC64_REL24));
        assert!(undefined, "Expected a named undefined symbol in the caller");

        // Reconstructed external branch relocations must use the unresolved
        // GCC input operand (bl 0). Keeping a linked negative displacement
        // causes objdiff to report an invalid bl target for this function.
        let eax_source =
            "EAX-BUILD1-S04-PS3/Carbon/Branches/LeadPlat/Speed/Indep/SourceLists/zEAXSound.cpp.o";
        let eax_bytes = fs::read(split_dir.join("obj").join(eax_source))?;
        let eax = object::File::parse(eax_bytes.as_slice())?;
        let function = eax
            .symbols()
            .find(|symbol| {
                symbol.name().ok() == Some("._ZN14SndStrmWrapper12CreateStreamEiiPciPv")
                    && symbol.section_index().is_some()
            })
            .expect("Missing SndStrmWrapper::CreateStream");
        let section = eax.section_by_index(function.section_index().unwrap())?;
        let data = section.data()?;
        let branches = [
            (0x40, "lbl_00012F9C"),
            (0x60, "lbl_0001278C"),
            (0x78, "lbl_0001087C"),
            (0x80, "lbl_000140AC"),
        ];
        for (offset, name) in branches {
            let at = function.address() as usize + offset;
            assert_eq!(
                &data[at..at + 4],
                &0x4800_0001_u32.to_be_bytes(),
                "Invalid bl operand at CreateStream + {offset:#x}"
            );
            let relocation = section
                .relocations()
                .find(|(address, _)| *address == at as u64)
                .map(|(_, relocation)| relocation)
                .expect("Missing relocation for CreateStream bl");
            assert!(matches!(relocation.flags(), RelocationFlags::Elf { r_type }
                if r_type == elf::R_PPC64_REL24));
            let RelocationTarget::Symbol(index) = relocation.target() else {
                panic!("Expected a named relocation for CreateStream bl");
            };
            assert_eq!(eax.symbol_by_index(index)?.name()?, name);
        }
        let local_beq = function.address() as usize + 0x54;
        assert_eq!(
            &data[local_beq..local_beq + 4],
            &0x419c_0054_u32.to_be_bytes(),
            "The unrelocated local conditional branch should remain unchanged"
        );

        // Same-object calls still require REL24 relocations so that objdiff
        // displays the destination function rather than an unlabelled
        // section-relative address (or an invalid branch destination).
        for (caller, calls) in [
            (
                "._ZN14SndStrmWrapper12CreateStreamEiiPciPv",
                &[(0xb0, "._ZN18AudioMemoryManager10FreeMemoryEPv")][..],
            ),
            (
                "._ZN18EAXS_StreamChannel11InitChannelEiii9eSTRMTYPE",
                &[
                    (0x28, "._ZN14SndStrmWrapper6CreateEiii"),
                    (
                        0x54,
                        "._ZN18EAXS_StreamManager16AddStreamChannelEP18EAXS_StreamChannel9eSTRMTYPE",
                    ),
                ][..],
            ),
        ] {
            let method = eax
                .symbols()
                .find(|symbol| {
                    symbol.name().ok() == Some(caller) && symbol.section_index().is_some()
                })
                .unwrap_or_else(|| panic!("Missing caller {caller}"));
            let section = eax.section_by_index(method.section_index().unwrap())?;
            let data = section.data()?;
            for &(offset, callee) in calls {
                let at = method.address() + offset;
                assert_eq!(
                    &data[at as usize..at as usize + 4],
                    &0x4800_0001u32.to_be_bytes(),
                    "Call {caller}+{offset:#x} should be `bl 0`"
                );
                let relocation = section
                    .relocations()
                    .find(|(address, _)| *address == at)
                    .map(|(_, relocation)| relocation)
                    .unwrap_or_else(|| panic!("Missing call relocation {caller}+{offset:#x}"));
                assert!(matches!(relocation.flags(), RelocationFlags::Elf { r_type }
                    if r_type == elf::R_PPC64_REL24));
                let RelocationTarget::Symbol(index) = relocation.target() else {
                    panic!("Missing named callee at {caller}+{offset:#x}");
                };
                assert_eq!(eax.symbol_by_index(index)?.name()?, callee);
            }
        }

        let init = eax
            .symbols()
            .find(|symbol| {
                symbol.name().ok() == Some("._ZN18EAXS_StreamChannel11InitChannelEiii9eSTRMTYPE")
                    && symbol.section_index().is_some()
            })
            .unwrap();
        let init_section = eax.section_by_index(init.section_index().unwrap())?;
        let beq = init.address() as usize + 0x3c;
        assert_eq!(&init_section.data()?[beq..beq + 4], &0x419c_003cu32.to_be_bytes());
    }
    if let Some((wibo, linker)) = original_linker() {
        verify_original_relocatable_link(&wibo, &linker, &split_dir, &order);
    }
    println!("{fixture}: {object_count} ELF64 PPC64 objects, {opd_relocations} .opd relocations");
    Ok(())
}

#[test]
#[ignore = "requires large target/EBOOT.elf fixture"]
fn eboot_cli_split() -> Result<(), Box<dyn std::error::Error>> { test_fixture("EBOOT.elf", 2) }

#[test]
#[ignore = "requires target/ppu-compiler-probe/standalone.elf, WIBO and PPU_LD"]
fn original_ps3_linker_relinks_compiler_fixture_exactly() -> Result<(), Box<dyn std::error::Error>>
{
    let (wibo, linker) = original_linker().expect("Set WIBO and PPU_LD to the original PS3 tools");
    let input =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("target/ppu-compiler-probe/standalone.elf");
    assert!(input.is_file(), "Missing original GCC-linked fixture: {}", input.display());
    let scratch = ScratchDir::new("sdk-original-linker")?;
    let split = scratch.0.join("split");
    let config = split.join("config");
    run_kevin("split", &input, &split);
    let result = Command::new("bash")
        .arg("link.sh")
        .current_dir(&split)
        .env("WIBO", &wibo)
        .env("PPU_LD", &linker)
        .output()?;
    assert!(
        result.status.success(),
        "Original ppu-lv2-ld failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    run_kevin("verify", &config.join("config.yml"), &split.join("linked.elf"));
    Ok(())
}

#[test]
#[ignore = "requires target/ppu-compiler-probe/standalone.elf, llvm-objcopy-18, WIBO and PPU_LD"]
fn original_ps3_linker_relinks_stripped_compiler_fixture_exactly()
-> Result<(), Box<dyn std::error::Error>> {
    let (wibo, linker) = original_linker().expect("Set WIBO and PPU_LD to the original PS3 tools");
    let input =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("target/ppu-compiler-probe/standalone.elf");
    assert!(input.is_file(), "Missing original GCC-linked fixture: {}", input.display());
    let scratch = ScratchDir::new("sdk-stripped-original-linker")?;
    let stripped = scratch.0.join("stripped.elf");
    let strip =
        Command::new("llvm-objcopy-18").arg("--strip-all").arg(&input).arg(&stripped).output()?;
    assert!(
        strip.status.success(),
        "Failed to strip fixture: {}",
        String::from_utf8_lossy(&strip.stderr)
    );
    let bytes = fs::read(&stripped)?;
    let file = object::File::parse(bytes.as_slice())?;
    assert_eq!(file.symbols().count(), 0, "Fixture still contains symbols");

    let split = scratch.0.join("split");
    let config = split.join("config");
    run_kevin("split", &stripped, &split);
    let code = fs::read(split.join("obj/auto_00_00010000_text.o"))?;
    let reconstructed = object::File::parse(code.as_slice())?;
    assert_eq!(
        reconstructed
            .symbols()
            .filter(|symbol| {
                symbol.name().ok() == Some("lbl_00030014") && symbol.is_definition()
            })
            .count(),
        1,
        "The stripped entrypoint must have exactly one definition"
    );
    let result = Command::new("bash")
        .arg("link.sh")
        .current_dir(&split)
        .env("WIBO", wibo)
        .env("PPU_LD", linker)
        .output()?;
    assert!(
        result.status.success(),
        "Original ppu-lv2-ld failed:\n{}",
        String::from_utf8_lossy(&result.stderr)
    );
    run_kevin("verify", &config.join("config.yml"), &split.join("linked.elf"));
    Ok(())
}

#[test]
#[ignore = "requires large target/HAWAII_PS3_INTERNAL_UNITY.elf fixture"]
fn hawaii_cli_split() -> Result<(), Box<dyn std::error::Error>> {
    test_fixture("HAWAII_PS3_INTERNAL_UNITY.elf", 1)
}

#[test]
#[ignore = "requires target/EBOOT.elf fixture; optionally WIBO and PPU_LD"]
fn eboot_noncontiguous_unit_split() -> Result<(), Box<dyn std::error::Error>> {
    let input = Path::new(env!("CARGO_MANIFEST_DIR")).join("target/EBOOT.elf");
    let scratch = ScratchDir::new("eboot-disjoint")?;
    let split_dir = scratch.0.join("split");
    let config_dir = split_dir.join("config");
    run_kevin("split", &input, &split_dir);
    let split_path = config_dir.join("splits.txt");
    let existing = fs::read_to_string(&split_path)?;
    let source = "EAX-BUILD1-S04-PS3/Carbon/Branches/LeadPlat/Speed/Indep/SourceLists/zAI.cpp";
    assert!(existing.contains(&format!("{source}:")));
    assert!(
        !existing.contains("auto_01_000738BC_text:"),
        "A this-adjusting thunk must be attached to its source CU"
    );
    assert!(!existing.contains("D:\\EAX-BUILD1-S04-PS3"));
    let bytes = fs::read(split_dir.join(format!("obj/{source}.o")))?;
    let output = object::File::parse(bytes.as_slice())?;
    assert!(
        output
            .sections()
            .filter(|s| { s.name().is_ok_and(|name| name.starts_with(".gnu.linkonce.t.")) })
            .count()
            > 100
    );
    assert!(output.section_by_name(".text").is_some());
    assert!(output.sections().all(|s| { s.name().is_ok_and(|name| !name.contains(".kevin_")) }));
    let order = fs::read_to_string(split_dir.join("link_order.txt"))?;
    if let Some((wibo, linker)) = original_linker() {
        verify_original_relocatable_link(&wibo, &linker, &split_dir, &order);
    }
    Ok(())
}
