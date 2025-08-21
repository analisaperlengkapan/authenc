use fluent_bundle::{FluentBundle, FluentResource, FluentArgs};
use unic_langid::LanguageIdentifier;
use std::collections::HashMap;
use std::fs;

pub struct I18n {
    ftl_map: HashMap<String, String>,
}

impl I18n {
    pub fn new(locales: &[&str], path: &str) -> Self {
        let mut ftl_map = HashMap::new();
        for &locale in locales {
            let ftl_path = format!("{}/{}.ftl", path, locale);
            let source = fs::read_to_string(&ftl_path).expect("Failed to read FTL file");
            ftl_map.insert(locale.to_string(), source);
        }
        I18n { ftl_map }
    }

    pub fn t(&self, locale: &str, key: &str, args: Option<&FluentArgs>) -> String {
        let ftl = self.ftl_map.get(locale).or_else(|| self.ftl_map.get("en-US"));
        if let Some(ftl) = ftl {
            let langid: LanguageIdentifier = locale.parse().unwrap_or_else(|_| "en-US".parse().unwrap());
            let res = FluentResource::try_new(ftl.clone()).expect("Failed to parse FTL");
            let mut bundle = FluentBundle::new(vec![langid]);
            bundle.add_resource(res).expect("Failed to add FTL resource");
            if let Some(msg) = bundle.get_message(key) {
                if let Some(pattern) = msg.value() {
                    let mut errors = vec![];
                    let value = bundle.format_pattern(pattern, args, &mut errors);
                    return value.to_string();
                }
            }
        }
        key.to_string()
    }
}
