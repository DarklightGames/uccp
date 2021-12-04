use pest::{Parser};
use pest_derive::Parser;
use pest::error::Error;
use std::path::{Path};

#[derive(Parser)]
#[grammar = "ini.pest"]
struct ConfigParser;

pub struct Section {
    pub name: String,
    pub properties: Vec<Property>
}

impl Section {
    pub fn values(&self, key: &str) -> Vec<String> {
        self.properties.iter()
            .filter(|p| p.key == key)
            .map(|p| p.value.clone())
            .collect()
    }
}

pub struct Property {
    pub key: String,
    pub value: String,
}

pub struct ConfigFile {
    sections: Vec<Box<Section>>,
}

impl ConfigFile {
    pub fn section(&self, name: &str) -> Option<&Box<Section>> {
        self.sections.iter().find(|section| section.name.as_str() == name)
    }
}

pub fn parse_config(path: &Path) -> Result<ConfigFile, Error<Rule>> {
    let contents = std::fs::read_to_string(path).unwrap().to_string();
    let config = ConfigParser::parse(Rule::ini, contents.as_str())?.next().unwrap();
    let mut sections = vec![];
    let mut section: Option<Box<Section>> = None;
    for line in config.into_inner() {
        match line.as_rule() {
            Rule::section => {
                if let Some(section) = section {
                    sections.push(section);
                }
                section = Some(Box::new(Section { name: line.as_str().to_string(), properties: vec![] }));
            }
            Rule::property => {
                let mut inner_iter = line.into_inner().into_iter();
                let property = Property {
                    key: inner_iter.next().unwrap().as_str().to_string(),
                    value: inner_iter.next().unwrap().as_str().to_string()
                };
                match &mut section {
                    None => {} // TODO: add to the "global" properties
                    Some(section) => {
                        section.properties.push(property)
                    }
                }
            }
            _ => {}
        }
    }
    if let Some(section) = section {
        sections.push(section);
    }
    Ok(ConfigFile { sections })
}
