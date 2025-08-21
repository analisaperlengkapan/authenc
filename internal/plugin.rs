use libloading::{Library, Symbol};
use std::path::Path;

pub struct PluginManager {
    plugins: Vec<Library>,
}

impl PluginManager {
    pub fn new() -> Self {
        PluginManager { plugins: Vec::new() }
    }

    pub fn load_plugin<P: AsRef<std::ffi::OsStr>>(&mut self, path: P) {
        unsafe {
            if let Ok(lib) = Library::new(path) {
                self.plugins.push(lib);
            }
        }
    }

    // Example: Call a function named `plugin_entry` in all loaded plugins
    pub fn call_plugin_entries(&self) {
        for lib in &self.plugins {
            unsafe {
                let func: Result<Symbol<unsafe extern fn()>, _> = lib.get(b"plugin_entry");
                if let Ok(entry) = func {
                    entry();
                }
            }
        }
    }
}
