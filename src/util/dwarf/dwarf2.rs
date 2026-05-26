use std::{borrow::Cow, collections::BTreeMap};

use anyhow::{Context, Result, anyhow, bail};
use gimli::{
    self, AttributeValue as GimliAttributeValue, Dwarf, EndianSlice, Reader, ReaderOffset,
    RunTimeEndian, Unit,
};
use object::{Object, ObjectSection};

use crate::util::{
    dwarf::{
        Attribute, AttributeKind, AttributeValue, DeclCoord, DwarfInfo, Endian, Producer, Tag,
        TagKind,
    },
    reader::FromBytes,
};

pub fn read_dwarf2_info(obj_file: &object::File<'_>) -> Result<DwarfInfo> {
    let dwarf_sections = gimli::DwarfSections::load(|id| {
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
    let e = match obj_file.endianness() {
        object::Endianness::Little => Endian::Little,
        object::Endianness::Big => Endian::Big,
    };
    let dwarf = dwarf_sections.borrow(|section| EndianSlice::new(section, endian));

    let mut info = DwarfInfo {
        e,
        tags: BTreeMap::new(),
        producer: Producer::OTHER,
        member_functions: Default::default(),
    };

    let mut units = dwarf.units();
    while let Some(header) = units.next()? {
        let unit = dwarf.unit(header)?;
        let decl_files = build_decl_files(&unit)?;
        let mut builder = UnitBuilder {
            dwarf: &dwarf,
            unit: &unit,
            info: &mut info,
            namespace_stack: Vec::new(),
            decl_files,
            children: BTreeMap::new(),
            roots: Vec::new(),
        };
        let mut tree = unit.entries_tree(None)?;
        let root = tree.root()?;
        builder.visit(root, None)?;
        builder.apply_siblings();
    }

    Ok(info)
}

pub fn read_dwarf2_elf(elf: &[u8]) -> Result<DwarfInfo> {
    let view = ElfSectionView::parse(elf)?;
    let dwarf_sections = gimli::DwarfSections::load(|id| {
        Ok::<_, gimli::Error>(Cow::Borrowed(view.section(id.name()).unwrap_or(&[])))
    })?;
    let dwarf = dwarf_sections.borrow(|section| EndianSlice::new(section, view.runtime_endian));

    let mut info = DwarfInfo {
        e: view.endian,
        tags: BTreeMap::new(),
        producer: Producer::OTHER,
        member_functions: Default::default(),
    };

    let mut units = dwarf.units();
    while let Some(header) = units.next()? {
        let unit = dwarf.unit(header)?;
        let decl_files = build_decl_files(&unit)?;
        let mut builder = UnitBuilder {
            dwarf: &dwarf,
            unit: &unit,
            info: &mut info,
            namespace_stack: Vec::new(),
            decl_files,
            children: BTreeMap::new(),
            roots: Vec::new(),
        };
        let mut tree = unit.entries_tree(None)?;
        let root = tree.root()?;
        builder.visit(root, None)?;
        builder.apply_siblings();
    }

    Ok(info)
}

struct ElfSectionView<'a> {
    endian: Endian,
    runtime_endian: RunTimeEndian,
    sections: BTreeMap<String, &'a [u8]>,
}

impl<'a> ElfSectionView<'a> {
    fn parse(data: &'a [u8]) -> Result<Self> {
        if data.len() < 0x40 || &data[..4] != b"\x7FELF" {
            bail!("Unsupported fallback ELF input");
        }
        let is_64 = match data[4] {
            1 => false,
            2 => true,
            other => bail!("Unsupported ELF class {other}"),
        };
        let (endian, runtime_endian) = match data[5] {
            1 => (Endian::Little, RunTimeEndian::Little),
            2 => (Endian::Big, RunTimeEndian::Big),
            other => bail!("Unsupported ELF endianness {other}"),
        };

        let (shoff, shentsize, shnum, shstrndx) = if is_64 {
            (
                read_u64(data, 0x28, endian)? as usize,
                read_u16(data, 0x3A, endian)? as usize,
                read_u16(data, 0x3C, endian)? as usize,
                read_u16(data, 0x3E, endian)? as usize,
            )
        } else {
            (
                read_u32(data, 0x20, endian)? as usize,
                read_u16(data, 0x2E, endian)? as usize,
                read_u16(data, 0x30, endian)? as usize,
                read_u16(data, 0x32, endian)? as usize,
            )
        };

        let mut headers = Vec::with_capacity(shnum);
        for idx in 0..shnum {
            let base = shoff + idx * shentsize;
            ensure_range(data, base, shentsize)?;
            let (name_off, offset, size) = if is_64 {
                (
                    read_u32(data, base, endian)? as usize,
                    read_u64(data, base + 0x18, endian)? as usize,
                    read_u64(data, base + 0x20, endian)? as usize,
                )
            } else {
                (
                    read_u32(data, base, endian)? as usize,
                    read_u32(data, base + 0x10, endian)? as usize,
                    read_u32(data, base + 0x14, endian)? as usize,
                )
            };
            headers.push((name_off, offset, size));
        }

        let (_, shstr_offset, shstr_size) =
            *headers.get(shstrndx).ok_or_else(|| anyhow!("Invalid shstrtab index"))?;
        ensure_range(data, shstr_offset, shstr_size)?;
        let shstrtab = &data[shstr_offset..shstr_offset + shstr_size];

        let mut sections = BTreeMap::new();
        for (name_off, offset, size) in headers {
            let name = read_c_string(shstrtab, name_off)?.to_string();
            if name.is_empty() {
                continue;
            }
            if offset == 0 && size == 0 {
                sections.insert(name, &[][..]);
                continue;
            }
            ensure_range(data, offset, size)?;
            sections.insert(name, &data[offset..offset + size]);
        }

        Ok(Self { endian, runtime_endian, sections })
    }

    fn section(&self, name: &str) -> Option<&'a [u8]> { self.sections.get(name).copied() }
}

struct UnitBuilder<'a, 'input> {
    dwarf: &'a Dwarf<EndianSlice<'input, RunTimeEndian>>,
    unit: &'a Unit<EndianSlice<'input, RunTimeEndian>>,
    info: &'a mut DwarfInfo,
    namespace_stack: Vec<String>,
    decl_files: Vec<String>,
    children: BTreeMap<u32, Vec<u32>>,
    roots: Vec<u32>,
}

impl<'a, 'input> UnitBuilder<'a, 'input> {
    fn visit(
        &mut self,
        node: gimli::EntriesTreeNode<'_, '_, '_, EndianSlice<'input, RunTimeEndian>>,
        parent: Option<u32>,
    ) -> Result<()> {
        let entry = node.entry();
        let tag = entry.tag();

        if tag == gimli::DW_TAG_namespace {
            let namespace = self.entry_name(entry)?.unwrap_or_default();
            if !namespace.is_empty() {
                self.namespace_stack.push(namespace);
            }
            let mut children = node.children();
            while let Some(child) = children.next()? {
                self.visit(child, parent)?;
            }
            if !self.namespace_stack.is_empty() {
                self.namespace_stack.pop();
            }
            return Ok(());
        }

        if tag == gimli::DW_TAG_imported_module || tag == gimli::DW_TAG_imported_declaration {
            return Ok(());
        }

        let key = self.key_for_entry(entry)?;
        let mut kind = map_tag_kind(tag)?;
        if kind == TagKind::GlobalVariable {
            if let Some(parent_key) = parent {
                if let Some(parent_tag) = self.info.tags.get(&parent_key) {
                    if matches!(
                        parent_tag.kind,
                        TagKind::GlobalSubroutine
                            | TagKind::Subroutine
                            | TagKind::InlinedSubroutine
                            | TagKind::LexicalBlock
                    ) {
                        kind = TagKind::LocalVariable;
                    }
                }
            }
        }
        let attrs = self.translate_attrs(entry)?;
        let decl = self.translate_decl(entry)?;
        self.info.tags.insert(
            key,
            Tag {
                key,
                kind,
                is_erased: false,
                is_erased_root: false,
                data_endian: self.info.e,
                attributes: attrs,
                decl,
                child_keys: Vec::new(),
            },
        );
        if let Some(parent) = parent {
            self.children.entry(parent).or_default().push(key);
            if let Some(parent_tag) = self.info.tags.get_mut(&parent) {
                parent_tag.child_keys.push(key);
            }
        } else {
            self.roots.push(key);
        }

        let mut children = node.children();
        while let Some(child) = children.next()? {
            self.visit(child, Some(key))?;
        }
        Ok(())
    }

    fn apply_siblings(&mut self) {
        for keys in self.children.values() {
            for pair in keys.windows(2) {
                if let [current, next] = pair {
                    if let Some(tag) = self.info.tags.get_mut(current) {
                        tag.attributes.push(Attribute {
                            kind: AttributeKind::Sibling,
                            value: AttributeValue::Reference(*next),
                        });
                    }
                }
            }
        }
        for pair in self.roots.windows(2) {
            if let [current, next] = pair {
                if let Some(tag) = self.info.tags.get_mut(current) {
                    tag.attributes.push(Attribute {
                        kind: AttributeKind::Sibling,
                        value: AttributeValue::Reference(*next),
                    });
                }
            }
        }
    }

    fn key_for_entry(
        &self,
        entry: &gimli::DebuggingInformationEntry<
            '_,
            '_,
            EndianSlice<'input, RunTimeEndian>,
            usize,
        >,
    ) -> Result<u32> {
        let offset = entry
            .offset()
            .to_debug_info_offset(&self.unit.header)
            .ok_or_else(|| anyhow!("Failed to convert unit-relative offset to .debug_info"))?;
        u32::try_from(offset.0).context("DWARF offset exceeds u32 range")
    }

    fn translate_attrs(
        &self,
        entry: &gimli::DebuggingInformationEntry<
            '_,
            '_,
            EndianSlice<'input, RunTimeEndian>,
            usize,
        >,
    ) -> Result<Vec<Attribute>> {
        let mut out = Vec::new();
        let mut attrs = entry.attrs();
        while let Some(attr) = attrs.next()? {
            let name = attr.name();
            let value = attr.value();
            match name {
                gimli::DW_AT_name => out.push(Attribute {
                    kind: AttributeKind::Name,
                    value: AttributeValue::String(self.translate_name(value)?),
                }),
                gimli::DW_AT_producer => out.push(Attribute {
                    kind: AttributeKind::Producer,
                    value: AttributeValue::String(self.attr_string(value)?),
                }),
                gimli::DW_AT_comp_dir => out.push(Attribute {
                    kind: AttributeKind::CompDir,
                    value: AttributeValue::String(self.attr_string(value)?),
                }),
                gimli::DW_AT_language => out.push(Attribute {
                    kind: AttributeKind::Language,
                    value: AttributeValue::Data4(as_u32(value)?),
                }),
                gimli::DW_AT_stmt_list => out.push(Attribute {
                    kind: AttributeKind::StmtList,
                    value: AttributeValue::Data4(as_u32(value)?),
                }),
                gimli::DW_AT_low_pc => out.push(Attribute {
                    kind: AttributeKind::LowPc,
                    value: AttributeValue::Address(as_u32(value)?),
                }),
                gimli::DW_AT_high_pc => out.push(Attribute {
                    kind: AttributeKind::HighPc,
                    value: AttributeValue::Address(as_u32(value)?),
                }),
                gimli::DW_AT_byte_size => out.push(Attribute {
                    kind: AttributeKind::ByteSize,
                    value: AttributeValue::Data4(as_u32(value)?),
                }),
                gimli::DW_AT_bit_size => out.push(Attribute {
                    kind: AttributeKind::BitSize,
                    value: AttributeValue::Data4(as_u32(value)?),
                }),
                gimli::DW_AT_bit_offset => out.push(Attribute {
                    kind: AttributeKind::BitOffset,
                    value: AttributeValue::Data2(u16::try_from(as_u64(value)?)?),
                }),
                gimli::DW_AT_type => out.push(Attribute {
                    kind: AttributeKind::DwAtType,
                    value: AttributeValue::Reference(self.debug_info_ref(value)?),
                }),
                gimli::DW_AT_specification | gimli::DW_AT_abstract_origin => out.push(Attribute {
                    kind: AttributeKind::Specification,
                    value: AttributeValue::Reference(self.debug_info_ref(value)?),
                }),
                gimli::DW_AT_containing_type => out.push(Attribute {
                    kind: AttributeKind::ContainingType,
                    value: AttributeValue::Reference(self.debug_info_ref(value)?),
                }),
                gimli::DW_AT_MIPS_linkage_name | gimli::DW_AT_linkage_name => {
                    out.push(Attribute {
                        kind: AttributeKind::MwMangled,
                        value: AttributeValue::String(self.attr_string(value)?),
                    })
                }
                gimli::DW_AT_prototyped => out.push(Attribute {
                    kind: AttributeKind::Prototyped,
                    value: AttributeValue::Flag(as_flag(value)?),
                }),
                gimli::DW_AT_inline => {
                    if as_u64(value)? != 0 {
                        out.push(Attribute {
                            kind: AttributeKind::Inline,
                            value: AttributeValue::Flag(true),
                        });
                    }
                }
                gimli::DW_AT_virtuality => {
                    if as_u64(value)? != 0 {
                        out.push(Attribute {
                            kind: AttributeKind::Virtual,
                            value: AttributeValue::Flag(true),
                        });
                    }
                }
                gimli::DW_AT_accessibility => {
                    let kind = match as_u64(value)? {
                        1 => AttributeKind::Public,
                        2 => AttributeKind::Protected,
                        3 => AttributeKind::Private,
                        other => bail!("Unhandled DW_AT_accessibility value {other}"),
                    };
                    out.push(Attribute { kind, value: AttributeValue::Flag(true) });
                }
                gimli::DW_AT_location => {
                    if let Some(location) = self.translate_location(value)? {
                        out.push(Attribute { kind: AttributeKind::Location, value: location });
                    }
                }
                gimli::DW_AT_data_member_location => {
                    out.push(Attribute {
                        kind: AttributeKind::Location,
                        value: self.translate_data_member_location(value)?,
                    });
                }
                gimli::DW_AT_upper_bound => out.push(Attribute {
                    kind: AttributeKind::DwUpperBound,
                    value: translate_scalar(value)?,
                }),
                gimli::DW_AT_lower_bound => out.push(Attribute {
                    kind: AttributeKind::DwLowerBound,
                    value: translate_scalar(value)?,
                }),
                gimli::DW_AT_count => out.push(Attribute {
                    kind: AttributeKind::DwCount,
                    value: translate_scalar(value)?,
                }),
                gimli::DW_AT_const_value => out.push(Attribute {
                    kind: AttributeKind::DwConstValue,
                    value: translate_scalar(value)?,
                }),
                gimli::DW_AT_encoding => out.push(Attribute {
                    kind: AttributeKind::DwEncoding,
                    value: AttributeValue::Udata(as_u64(value)?),
                }),
                gimli::DW_AT_external
                | gimli::DW_AT_declaration
                | gimli::DW_AT_artificial
                | gimli::DW_AT_call_file
                | gimli::DW_AT_call_line
                | gimli::DW_AT_sibling
                | gimli::DW_AT_frame_base => {}
                _ => {}
            }
        }
        Ok(out)
    }

    fn translate_decl(
        &self,
        entry: &gimli::DebuggingInformationEntry<
            '_,
            '_,
            EndianSlice<'input, RunTimeEndian>,
            usize,
        >,
    ) -> Result<Option<DeclCoord>> {
        let file = match entry.attr_value(gimli::DW_AT_decl_file)? {
            Some(value) => {
                let index = usize::try_from(as_u64(value)?)?;
                self.decl_files.get(index.wrapping_sub(1)).cloned()
            }
            None => None,
        };
        let line = match entry.attr_value(gimli::DW_AT_decl_line)? {
            Some(value) => Some(u32::try_from(as_u64(value)?)?),
            None => None,
        };
        Ok(match (file, line) {
            (Some(file), Some(line)) => Some(DeclCoord { file, line }),
            _ => None,
        })
    }

    fn entry_name(
        &self,
        entry: &gimli::DebuggingInformationEntry<
            '_,
            '_,
            EndianSlice<'input, RunTimeEndian>,
            usize,
        >,
    ) -> Result<Option<String>> {
        match entry.attr_value(gimli::DW_AT_name)? {
            Some(value) => Ok(Some(self.attr_string(value)?)),
            None => Ok(None),
        }
    }

    fn translate_name(
        &self,
        value: GimliAttributeValue<EndianSlice<'input, RunTimeEndian>>,
    ) -> Result<String> {
        let name = self.attr_string(value)?;
        if self.namespace_stack.is_empty() {
            Ok(name)
        } else {
            Ok(format!("{}::{}", self.namespace_stack.join("::"), name))
        }
    }

    fn attr_string(
        &self,
        value: GimliAttributeValue<EndianSlice<'input, RunTimeEndian>>,
    ) -> Result<String> {
        let reader = self.dwarf.attr_string(self.unit, value)?;
        Ok(reader.to_string_lossy().into_owned())
    }

    fn debug_info_ref(
        &self,
        value: GimliAttributeValue<EndianSlice<'input, RunTimeEndian>>,
    ) -> Result<u32> {
        let offset = match value {
            GimliAttributeValue::UnitRef(offset) => offset
                .to_debug_info_offset(&self.unit.header)
                .ok_or_else(|| anyhow!("Failed to convert unit ref to debug_info offset"))?,
            GimliAttributeValue::DebugInfoRef(offset) => offset,
            other => bail!("Expected DIE reference, got {other:?}"),
        };
        u32::try_from(offset.0).context("DWARF reference exceeds u32 range")
    }

    fn translate_location(
        &self,
        value: GimliAttributeValue<EndianSlice<'input, RunTimeEndian>>,
    ) -> Result<Option<AttributeValue>> {
        match value {
            GimliAttributeValue::Exprloc(expr) => {
                Ok(Some(AttributeValue::Block(expr.0.to_slice()?.into_owned())))
            }
            other => {
                if let Some(mut locations) = self.dwarf.attr_locations(self.unit, other)? {
                    if let Some(location) = locations.next()? {
                        return Ok(Some(AttributeValue::Block(
                            location.data.0.to_slice()?.into_owned(),
                        )));
                    }
                }
                Ok(None)
            }
        }
    }

    fn translate_data_member_location(
        &self,
        value: GimliAttributeValue<EndianSlice<'input, RunTimeEndian>>,
    ) -> Result<AttributeValue> {
        match value {
            GimliAttributeValue::Exprloc(expr) => {
                Ok(AttributeValue::Block(expr.0.to_slice()?.into_owned()))
            }
            GimliAttributeValue::Udata(offset) => {
                let mut block = vec![0x23];
                push_uleb128(&mut block, offset);
                Ok(AttributeValue::Block(block))
            }
            other => bail!("Unhandled data member location {other:?}"),
        }
    }
}

fn build_decl_files(unit: &Unit<EndianSlice<'_, RunTimeEndian>>) -> Result<Vec<String>> {
    let Some(program) = unit.line_program.clone() else {
        return Ok(Vec::new());
    };
    let header = program.header();
    let mut files = Vec::with_capacity(header.file_names().len());
    for file in header.file_names() {
        let path = file.path_name();
        let path = attr_value_string(path)?;
        let full = if is_absolute_path(&path) {
            normalize_path(path)
        } else if let Some(dir) = file.directory(header) {
            let dir = attr_value_string(dir)?;
            if dir.is_empty() {
                normalize_path(path)
            } else {
                normalize_path(format!("{dir}/{path}"))
            }
        } else {
            normalize_path(path)
        };
        files.push(full);
    }
    Ok(files)
}

fn attr_value_string<R: Reader>(value: gimli::AttributeValue<R>) -> Result<String> {
    match value {
        gimli::AttributeValue::String(reader) => Ok(reader.to_string_lossy()?.into_owned()),
        other => bail!("Expected string attribute value, got {other:?}"),
    }
}

fn normalize_path(path: String) -> String { path.replace('\\', "/").replace("/./", "/") }

fn is_absolute_path(path: &str) -> bool {
    path.starts_with('/') || path.starts_with('\\') || path.get(1..3) == Some(":/")
}

fn map_tag_kind(tag: gimli::DwTag) -> Result<TagKind> {
    Ok(match tag {
        gimli::DW_TAG_array_type => TagKind::ArrayType,
        gimli::DW_TAG_class_type => TagKind::ClassType,
        gimli::DW_TAG_compile_unit => TagKind::CompileUnit,
        gimli::DW_TAG_enumeration_type => TagKind::EnumerationType,
        gimli::DW_TAG_enumerator => TagKind::DwEnumerator,
        gimli::DW_TAG_formal_parameter => TagKind::FormalParameter,
        gimli::DW_TAG_inheritance => TagKind::Inheritance,
        gimli::DW_TAG_inlined_subroutine => TagKind::InlinedSubroutine,
        gimli::DW_TAG_label => TagKind::Label,
        gimli::DW_TAG_lexical_block => TagKind::LexicalBlock,
        gimli::DW_TAG_member => TagKind::Member,
        gimli::DW_TAG_pointer_type => TagKind::DwPointerType,
        gimli::DW_TAG_reference_type => TagKind::DwReferenceType,
        gimli::DW_TAG_structure_type => TagKind::StructureType,
        gimli::DW_TAG_subprogram => TagKind::GlobalSubroutine,
        gimli::DW_TAG_subrange_type => TagKind::DwSubrangeType,
        gimli::DW_TAG_subroutine_type => TagKind::SubroutineType,
        gimli::DW_TAG_typedef => TagKind::Typedef,
        gimli::DW_TAG_union_type => TagKind::UnionType,
        gimli::DW_TAG_unspecified_parameters => TagKind::UnspecifiedParameters,
        gimli::DW_TAG_variable => TagKind::GlobalVariable,
        gimli::DW_TAG_base_type => TagKind::DwBaseType,
        gimli::DW_TAG_const_type => TagKind::DwConstType,
        gimli::DW_TAG_volatile_type => TagKind::DwVolatileType,
        other => bail!("Unhandled DWARF 2 tag {other:?}"),
    })
}

fn translate_scalar<R: Reader>(value: gimli::AttributeValue<R>) -> Result<AttributeValue> {
    Ok(match value {
        gimli::AttributeValue::Data1(v) => AttributeValue::Udata(u64::from(v)),
        gimli::AttributeValue::Data2(v) => AttributeValue::Udata(u64::from(v)),
        gimli::AttributeValue::Data4(v) => AttributeValue::Udata(u64::from(v)),
        gimli::AttributeValue::Data8(v) => AttributeValue::Udata(v),
        gimli::AttributeValue::Udata(v) => AttributeValue::Udata(v),
        gimli::AttributeValue::Sdata(v) => AttributeValue::Sdata(v),
        gimli::AttributeValue::DebugStrRef(v) => AttributeValue::Udata(v.0.into_u64()),
        gimli::AttributeValue::String(reader) => {
            AttributeValue::String(reader.to_string_lossy()?.into_owned())
        }
        gimli::AttributeValue::Block(reader) => {
            let bytes = reader.to_slice()?;
            match bytes.len() {
                1 => AttributeValue::Udata(u64::from(bytes[0])),
                2 => AttributeValue::Udata(u64::from(u16::from_bytes(bytes[..2].try_into()?, Endian::Big))),
                4 => AttributeValue::Udata(u64::from(u32::from_bytes(bytes[..4].try_into()?, Endian::Big))),
                8 => AttributeValue::Udata(u64::from_bytes(bytes[..8].try_into()?, Endian::Big)),
                _ => bail!("Unhandled block scalar length {}", bytes.len()),
            }
        }
        other => bail!("Unhandled scalar attribute value {other:?}"),
    })
}

fn as_u64<R: Reader>(value: gimli::AttributeValue<R>) -> Result<u64> {
    Ok(match value {
        gimli::AttributeValue::Addr(v) => v,
        gimli::AttributeValue::Data1(v) => u64::from(v),
        gimli::AttributeValue::Data2(v) => u64::from(v),
        gimli::AttributeValue::Data4(v) => u64::from(v),
        gimli::AttributeValue::Data8(v) => v,
        gimli::AttributeValue::Udata(v) => v,
        gimli::AttributeValue::Flag(v) => u64::from(v),
        gimli::AttributeValue::DebugLineRef(v) => v.0.into_u64(),
        gimli::AttributeValue::Encoding(v) => u64::from(v.0),
        gimli::AttributeValue::Accessibility(v) => u64::from(v.0),
        gimli::AttributeValue::Inline(v) => u64::from(v.0),
        gimli::AttributeValue::Virtuality(v) => u64::from(v.0),
        gimli::AttributeValue::Language(v) => u64::from(v.0),
        gimli::AttributeValue::FileIndex(v) => v,
        other => bail!("Expected unsigned scalar, got {other:?}"),
    })
}

fn as_u32<R: Reader>(value: gimli::AttributeValue<R>) -> Result<u32> {
    u32::try_from(as_u64(value)?).context("Attribute value exceeds u32 range")
}

fn as_flag<R: Reader>(value: gimli::AttributeValue<R>) -> Result<bool> {
    Ok(match value {
        gimli::AttributeValue::Flag(v) => v,
        other => as_u64(other)? != 0,
    })
}

fn push_uleb128(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let mut byte = (value & 0x7F) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
}

fn ensure_range(data: &[u8], offset: usize, size: usize) -> Result<()> {
    let end = offset.checked_add(size).ok_or_else(|| anyhow!("Section range overflow"))?;
    if end > data.len() {
        bail!("Section range out of bounds");
    }
    Ok(())
}

fn read_u16(data: &[u8], offset: usize, endian: Endian) -> Result<u16> {
    ensure_range(data, offset, 2)?;
    Ok(u16::from_bytes(data[offset..offset + 2].try_into()?, endian))
}

fn read_u32(data: &[u8], offset: usize, endian: Endian) -> Result<u32> {
    ensure_range(data, offset, 4)?;
    Ok(u32::from_bytes(data[offset..offset + 4].try_into()?, endian))
}

fn read_u64(data: &[u8], offset: usize, endian: Endian) -> Result<u64> {
    ensure_range(data, offset, 8)?;
    Ok(u64::from_bytes(data[offset..offset + 8].try_into()?, endian))
}

fn read_c_string(data: &[u8], offset: usize) -> Result<&str> {
    let end = data[offset..]
        .iter()
        .position(|&b| b == 0)
        .map(|idx| offset + idx)
        .ok_or_else(|| anyhow!("Unterminated string"))?;
    std::str::from_utf8(&data[offset..end]).context("Invalid UTF-8 in ELF string table")
}
