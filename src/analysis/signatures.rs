//! GC/Wii's bundled signatures were removed. Retain the analysis hooks and
//! section-based constructor/destructor labels for DOL/REL workflows.

use anyhow::Result;

use crate::obj::{ObjInfo, ObjSymbol, ObjSymbolFlagSet, ObjSymbolFlags};

/// No built-in DOL/REL signatures are bundled with Kevin.
pub fn apply_signatures(_obj: &mut ObjInfo) -> Result<()> {
    Ok(())
}

/// No post-CFA DOL/REL signatures are bundled with Kevin.
pub fn apply_signatures_post(_obj: &mut ObjInfo) -> Result<()> {
    Ok(())
}

/// Create _ctors and _dtors symbols if missing
pub fn update_ctors_dtors(obj: &mut ObjInfo) -> Result<()> {
    if obj.symbols.by_name("_ctors")?.is_none() {
        if let Some((section_index, section)) = obj.sections.by_name(".ctors")? {
            obj.symbols.add_direct(ObjSymbol {
                name: "_ctors".to_string(),
                address: section.address,
                section: Some(section_index),
                size_known: true,
                flags: ObjSymbolFlagSet(ObjSymbolFlags::Global.into()),
                ..Default::default()
            })?;
        }
    }
    if obj.symbols.by_name("_dtors")?.is_none() {
        if let Some((section_index, section)) = obj.sections.by_name(".dtors")? {
            obj.symbols.add_direct(ObjSymbol {
                name: "_dtors".to_string(),
                address: section.address,
                section: Some(section_index),
                size_known: true,
                flags: ObjSymbolFlagSet(ObjSymbolFlags::Global.into()),
                ..Default::default()
            })?;
        }
    }
    Ok(())
}
