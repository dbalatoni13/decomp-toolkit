//! PPU linker layout and project-selected object inputs, kept separate from
//! the reference object writer. This mirrors DTK's `config.json` build contract:
//! build tooling selects a replacement object by unit name, never by overwriting
//! the reconstructed reference object.

use std::collections::BTreeMap;

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkLayout {
    pub entry: String,
    pub toc: Option<u64>,
    pub sections: Vec<LinkSection>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkSection {
    pub name: String,
    pub address: u64,
    pub inputs: Vec<LinkInput>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkInput {
    pub unit: String,
    pub section: String,
}

impl LinkLayout {
    pub fn script(&self, objects: &BTreeMap<String, String>) -> Result<String> {
        let mut script = format!("ENTRY({})\nSECTIONS {{\n", self.entry);
        if let Some(toc) = self.toc {
            script.push_str(&format!("  PROVIDE(.TOC. = {toc:#X});\n"));
        }
        for section in &self.sections {
            script.push_str(&format!("  {} {:#X} : {{\n", section.name, section.address));
            for input in &section.inputs {
                let path = objects.get(&input.unit).with_context(|| {
                    format!("No selected input for compilation unit '{}'", input.unit)
                })?;
                ensure!(
                    !path.contains(['\n', '\r', '"']) && !input.section.contains(['\n', '\r', ')']),
                    "Invalid linker input path or section name"
                );
                script.push_str(&format!("    \"{path}\"({})\n", input.section));
            }
            script.push_str("  }\n");
        }
        script.push_str("}\n");
        Ok(script)
    }
}
