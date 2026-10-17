# kevin

> **Disclaimer:** This project is trash in its current state. It is virtually unusable, buggy, and not recommended for anyone to use or even reference.

A fork of [decomp-toolkit](https://github.com/encounter/decomp-toolkit) with PS3 PPU ELF support.

## Sections

- [Goals](#goals)
- [Background](#background)
- [Analyzer features](#analyzer-features)
- [Other approaches](docs/other_approaches.md)
- [Terminology](docs/terminology.md)
- [Commands](#commands)
  - [ar create](#ar-create)
  - [ar extract](#ar-extract)
  - [demangle](#demangle)
  - [disc info](#disc-info)
  - [disc extract](#disc-extract)
  - [disc convert](#disc-convert)
  - [disc verify](#disc-verify)
  - [dol info](#dol-info)
  - [dol split](#dol-split)
  - [dol diff](#dol-diff)
  - [dol apply](#dol-apply)
  - [dol config](#dol-config)
  - [dwarf dump](#dwarf-dump)
  - [elf disasm](#elf-disasm)
  - [elf fixup](#elf-fixup)
  - [elf info](#elf-info)
  - [elf split](#elf-split)
  - [elf verify](#elf-verify)
  - [elf sigs](#elf-sigs)
  - [elf2dol](#elf2dol)
  - [map](#map)
  - [rel info](#rel-info)
  - [rel merge](#rel-merge)
  - [rso info](#rso-info)
  - [rso make](#rso-make)
  - [shasum](#shasum)
  - [nlzss decompress](#nlzss-decompress)
  - [rarc list](#rarc-list)
  - [rarc extract](#rarc-extract)
  - [u8 list](#u8-list)
  - [u8 extract](#u8-extract)
  - [vfs ls](#vfs-ls)
  - [vfs cp](#vfs-cp)
  - [yay0 decompress](#yay0-decompress)
  - [yay0 compress](#yay0-compress)
  - [yaz0 decompress](#yaz0-decompress)
  - [yaz0 compress](#yaz0-compress)
  - [wad info](#wad-info)
  - [wad extract](#wad-extract)
  - [wad verify](#wad-verify)

## Goals

- Automate as much as possible, allowing developers to focus on matching code rather than months-long tedious setup.
- Provide highly **accurate** and performant analysis and tooling.
- Provide everything in a single portable binary. This simplifies project setup: a script can simply fetch the
  binary from GitHub.
- Replace common usages of msys2 and GNU assembler, eliminating the need to depend on devkitPro.
- Integrate well with other decompilation tooling like [objdiff](https://github.com/encounter/objdiff) and
  [decomp.me](https://decomp.me).

## Background

The goal of a matching decompilation project is to write C/C++ code that compiles back to the _exact_ same binary as
the original game. This often requires using the same compiler as the original game. (For GameCube and Wii,
[Metrowerks CodeWarrior](https://en.wikipedia.org/wiki/CodeWarrior))

When compiling C/C++ code, the compiler (in our case, `mwcceppc`) generates an object file (`.o`) for every source file.
This object file contains the compiled machine code, as well as information that the linker (`mwldeppc`) uses to
generate the final executable.

One way to verify that our code is a match is by taking any code that has been decompiled, and
linking it alongside portions of the original binary that have not been decompiled yet. First, we create relocatable
objects from the original binary:

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/diagram_dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="assets/diagram_light.svg">
  <img alt="Binary split diagram" src="assets/diagram.svg">
</picture>

(Heavily simplified)

Then, each object can be replaced by a decompiled version as matching code is written. If the linker still generates a
binary that is byte-for-byte identical to the original, then we know that the decompiled code is a match.

decomp-toolkit provides tooling for analyzing and splitting the original binary into relocatable objects, as well
as generating the linker script and other files needed to link the decompiled code.

## Analyzer features

**Function boundary analysis**  
Discovers function boundaries with high accuracy. Uses various heuristics to disambiguate tail calls from
inner-function control flow.

**Signature analysis**  
Identifies supported PS3 SDK and runtime functions using bundled signatures.

**Relocation analysis**  
Performs control-flow analysis and rebuilds relocations with high accuracy.  
With some manual tweaking (mainly in data), this should generate fully-shiftable objects.

**Section analysis**  
Automatically identifies DOL and REL sections based on information from signature and relocation analysis.

**Object analysis**  
Attempts to identify the type and size of data objects by analyzing usage.  
Also attempts to identify string literals, wide string literals, and string tables.

**Splitting**  
Generates split object files in memory based on user configuration.  
In order to support relinking with `mwldeppc.exe`, any **unsplit** `.ctors`, `.dtors`, `extab` and `extabindex` entries
are analyzed and automatically split along with their associated functions. This ensures that the linker will properly
generate these sections without any additional configuration.  
A topological sort is performed to determine the final link order of the split objects.

**Object file writing**  
Writes object files directly, with no assembler required. (Bye devkitPPC!)  
If desired, optionally writes GNU assembler-compatible files alongside the object files.

**Linker script generation**  
Generates `ldscript.lcf` for `mwldeppc.exe`.

## Commands

### ar create

Create a static library (.a) from the input objects.

```shell
$ kevin ar create out.a input_1.o input_2.o
# or
$ echo input_1.o >> rspfile
$ echo input_2.o >> rspfile
$ kevin ar create out.a @rspfile
```

### ar extract

Extracts the contents of static library (.a) files.

Accepts multiple files, glob patterns (e.g. `*.a`) and response files (e.g. `@rspfile`).

Options:
- `-o`, `--out <output-dir>`: Output directory. Defaults to the current directory.
- `-v`, `--verbose`: Verbose output.
- `-q`, `--quiet`: Suppresses all output except errors.

```shell
# Extracts to outdir
$ kevin ar extract lib.a -o outdir

# With multiple inputs, extracts to separate directories
# Extracts to outdir/lib1, outdir/lib2
$ kevin ar extract lib1.a lib2.a -o outdir
```

### demangle

Demangles CodeWarrior C++ symbols. A thin wrapper for [cwdemangle](https://github.com/encounter/cwdemangle).

```shell
$ dtk demangle 'BuildLight__9CGuiLightCFv'
CGuiLight::BuildLight() const
```

### disc info

_`disc` commands are wrappers around the [nod](https://github.com/encounter/nod-rs) library
and its `nodtool` command line tool._

Displays information about disc images.

To list the contents of a disc image, use [vfs ls](#vfs-ls).

Supported disc image formats:

- ISO (GCM)
- WIA / RVZ
- WBFS (+ NKit 2 lossless)
- CISO (+ NKit 2 lossless)
- NFS (Wii U VC)
- GCZ
- TGC

```shell
$ kevin disc info /path/to/game.iso
```

### disc extract

Extracts the contents of disc images to a directory.

See [disc info](#disc-info) for supported formats.

> [!NOTE]  
> [vfs cp](#vfs-cp) is more flexible and supports disc images.

```shell
$ kevin disc extract /path/to/game.iso [outdir]
```

By default, only the main **data** partition is extracted.  
Use the `-p`/`--partition` option to choose a different partition.  
(Options: `all`, `data`, `update`, `channel`, or a partition index)

### disc convert

Converts any supported disc image to raw ISO (GCM).

If the format is lossless, the output will be identical to the original disc image.

See [disc info](#disc-info) for supported formats.

```shell
$ kevin disc convert /path/to/game.wia /path/to/game.iso
```

### disc verify

Hashes the contents of a disc image and verifies it against a built-in [Redump](http://redump.org/) database.

See [disc info](#disc-info) for supported formats.

```shell
$ kevin disc verify /path/to/game.iso
```

### dol info

Analyzes a DOL file and outputs information section and symbol information.

See [vfs ls](#vfs-ls) for information on the VFS abstraction.

```shell
$ kevin dol info input.dol
# or, directly from a disc image
$ kevin dol info 'disc.rvz:sys/main.dol'
```

### dol split

> [!IMPORTANT]  
> **This command is intended to be used as part of a decompilation project's build system.**  
> For an example project structure and for documentation on the configuration, see
> [dtk-template](https://github.com/encounter/dtk-template).

Analyzes and splits a DOL file into relocatable objects based on user configuration.

```shell
$ kevin dol split config.yml target
```

### dol diff

Simple diff tool for issues in a linked ELF. (Yes, not DOL. It's misnamed.)  
Tries to find the most obvious difference causing a mismatch.

Pass in the project configuration file, and the path to the linked ELF file to compare against.

```shell
$ kevin dol diff config.yml build/main.elf
```

### dol apply

Applies updated symbols from a linked ELF to the project configuration. (Again, misnamed.)

Useful after matching a file. It will pull updated symbol information from the final result.

```shell
$ kevin dol apply config.yml build/main.elf
```

### dol config

Generates an initial project configuration file from a DOL (& RELs).

Pass in the DOL file, and any REL files that are linked with it.  
Or, for Wii games, pass in the `selfile.sel`. (Not RSOs)

```shell
$ kevin dol config main.dol rels/*.rel -o config.yml
```

### dwarf dump

Dumps DWARF 1.1 and DWARF 2 information from an ELF file.

```shell
$ kevin dwarf dump input.elf
# or, to include data that was stripped by MWLD
$ kevin dwarf dump input.elf --include-erased
```

### elf disasm

Disassemble an unstripped CodeWarrior ELF file. Attempts to automatically split objects and rebuild relocations
when possible.

```shell
$ kevin elf disasm input.elf out
```

### elf fixup

Fixes issues with GNU assembler-built objects to ensure compatibility with `mwldeppc.exe`.

- Strips empty sections
- Generates section symbols for all allocatable sections
- Where possible, replaces section-relative relocations with direct relocations.
- Adds an ` (asm)` suffix to the file symbol. (For matching progress calculation)

```shell
# input and output can be the same
$ kevin elf fixup file.o file.o
```

### elf info

Prints ELF section and symbol information.

```shell
$ kevin elf info input.elf
```

### elf split

Splits a PS3 PPU ELF into relocatable objects and editable configuration files.
When splitting from `config.yml`, Kevin also fills in a missing original ELF SHA-1 hash.

```shell
$ kevin elf split input.elf out/
# or use an existing configuration
$ kevin elf split config.yml out/
```

### elf verify

Compares a relinked PS3 executable's allocated sections and entrypoint against the original ELF.

```shell
$ kevin elf verify out/config/config.yml linked.elf
```

### elf sigs

Generates ELF function signatures. For PS3, omit `-s` to generate one YAML file per function.

```shell
$ kevin elf sigs -o signatures/ input.elf
```

### elf2dol

Creates a DOL file from the provided ELF file.

```shell
$ kevin elf2dol input.elf output.dol
# or, to ignore certain sections
$ kevin elf2dol input.elf output.dol --ignore debug_section1 --ignore debug_section2
```

### map

Processes CodeWarrior map files and provides information about symbols and TUs.

```shell
$ dtk map entries Game.MAP 'Unit.o'
# Outputs all symbols that are referenced by Unit.o
# This is useful for finding deduplicated weak functions,
# which only show on first use in the link map.

$ dtk map symbol Game.MAP 'Function__5ClassFv'
# Outputs reference information for Function__5ClassFv
# CodeWarrior link maps can get very deeply nested,
# so this is useful for emitting direct references
# in a readable format.
```

### rel info

Prints information about a REL file.

See [vfs ls](#vfs-ls) for information on the VFS abstraction.

```shell
$ kevin rel info input.rel
# or, directly from a disc image
$ kevin rel info 'disc.rvz:files/RELS.arc:amem/d_a_tag_so.rel'
```

### rel merge

Merges a DOL file and associated RELs into a single ELF file, suitable for analysis in your favorite
reverse engineering software.

```shell
$ kevin rel info main.dol rels/*.rel -o merged.elf
```

### rso info

> [!WARNING]  
> This command is not yet functional.

Prints information about an RSO file.

```shell
$ kevin rso info input.rso
```

### rso make

> [!WARNING]  
> This command does not yet support creating SEL files.

Creates an RSO file from a relocatable ELF file.

Options:
- `-o`, `--output <File>`: Output RSO file.
- `-m`, `--module-name <Name>`: Module name (or path). Default: input name
- `-e`, `--export <File>`: File containing exported symbol names. (Newline separated)

```shell
$ kevin rso make input.elf -o input.rso
```

### shasum

Calculate and verify SHA-1 hashes.

```shell
$ dtk shasum baserom.dol
949c5ed7368aef547e0b0db1c3678f466e2afbff  baserom.dol

$ dtk shasum -c baserom.sha1 
baserom.dol: OK
```

### nlzss decompress

Decompresses NLZSS-compressed files.

```shell
$ kevin nlzss decompress input.bin.lz -o output.bin
# or, for batch processing
$ kevin nlzss decompress rels/*.lz -o rels
```

### rarc list

> [!NOTE]  
> [vfs ls](#vfs-ls) is more flexible and supports RARC archives.  
> This command is now equivalent to `kevin vfs ls -r input.arc:`

Lists the contents of an RARC (older .arc) archive.

```shell
$ dtk rarc list input.arc
```

### rarc extract

> [!NOTE]  
> [vfs cp](#vfs-cp) is more flexible and supports RARC archives.  
> This command is now equivalent to `kevin vfs cp input.arc: output_dir`

Extracts the contents of an RARC (older .arc) archive.

```shell
$ dtk rarc extract input.arc -o output_dir
```

### u8 list

> [!NOTE]
> [vfs ls](#vfs-ls) is more flexible and supports U8 archives.  
> This command is now equivalent to `kevin vfs ls -r input.arc:`

Extracts the contents of a U8 (newer .arc) archive.

```shell
$ dtk u8 list input.arc
```

### u8 extract

> [!NOTE]
> [vfs cp](#vfs-cp) is more flexible and supports U8 archives.  
> This command is now equivalent to `kevin vfs cp input.arc: output_dir`

Extracts the contents of a U8 (newer .arc) archive.

```shell
$ dtk u8 extract input.arc -o output_dir
```

### vfs ls

decomp-toolkit has a powerful virtual filesystem (VFS) abstraction that allows you to work with a
variety of containers. All operations happen in memory with minimal overhead and no temporary files.

Supported containers:

- Disc images (see [disc info](#disc-info) for supported formats)
- RARC archives (older .arc)
- U8 archives (newer .arc)
- WAD files (Wii VC)

Supported compression formats are handled transparently:
- Yay0 (SZP) / Yaz0 (SZS)
- NLZSS (.lz) (Use `:nlzss` in the path)

`vfs ls` lists the contents of a container or directory.

Options:

- `-r`, `--recursive`: Recursively list contents.
- `-s`, `--short`: Only list file names.

Examples:

```shell
# List the contents of the `amem` directory inside `RELS.arc` in a disc image
$ kevin vfs ls 'disc.rvz:files/RELS.arc:amem'
# List the contents of `RELS.arc` recursively
$ kevin vfs ls -r 'disc.rvz:files/RELS.arc:'

# All commands that accept a file path can also accept a VFS path
$ kevin rel info 'disc.rvz:files/RELS.arc:amem/d_a_tag_so.rel'
# Example disc image within a disc image
$ kevin dol info 'disc.rvz:files/zz_demo.tgc:sys/main.dol'
````

### vfs cp

See [vfs ls](#vfs-ls) for information on the VFS abstraction.

`vfs cp` copies files and directories recursively to the host filesystem.

Options:

- `--no-decompress`: Do not decompress files when copying.
- `-q`, `--quiet`: Suppresses all output except errors.

Examples:

```shell
# Extract a file from a nested path in a disc image to the current directory
$ kevin vfs cp 'disc.rvz:files/RELS.arc:amem/d_a_tag_so.rel' .

# Directories are copied recursively, making it easy to extract entire archives
$ kevin vfs cp 'disc.rvz:files/RELS.arc:' rels
# Or, to disable automatic decompression
$ kevin vfs cp --no-decompress 'disc.rvz:files/RELS.arc:' rels
```

### yay0 decompress

Decompresses Yay0-compressed files.

```shell
$ kevin yay0 decompress input.bin.yay0 -o output.bin
# or, for batch processing
$ kevin yay0 decompress rels/*.yay0 -o rels
```

### yay0 compress

Compresses files using Yay0 compression.

```shell
$ kevin yay0 compress input.bin -o output.bin.yay0
# or, for batch processing
$ kevin yay0 compress rels/* -o rels
```

### yaz0 decompress

Decompresses Yaz0-compressed files.

```shell
$ kevin yaz0 decompress input.bin.yaz0 -o output.bin
# or, for batch processing
$ kevin yaz0 decompress rels/*.yaz0 -o rels
```

### yaz0 compress

Compresses files using Yaz0 compression.

```shell
$ kevin yaz0 compress input.bin -o output.bin.yaz0
# or, for batch processing
$ kevin yaz0 compress rels/* -o rels
```

### wad info

Prints information about a WAD file.

```shell
$ kevin wad info input.wad
```

### wad extract

> [!NOTE]
> [vfs cp](#vfs-cp) is more flexible and supports WAD files.  
> This command is now equivalent to `kevin vfs cp input.wad: output_dir`

Extracts the contents of a WAD file.

```shell
$ kevin wad extract input.wad -o output_dir
```

### wad verify

Verifies the contents of a WAD file.

```shell
$ kevin wad verify input.wad
```
