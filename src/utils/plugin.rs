use libloading::{Library, Symbol};

pub struct PluginManager {
    plugins: Vec<Library>,
}

impl PluginManager {
    pub fn new() -> Self {
        PluginManager {
            plugins: Vec::new(),
        }
    }

    pub fn load_plugin<P: AsRef<std::ffi::OsStr>>(&mut self, path: P) -> Result<(), String> {
        unsafe {
            let lib = Library::new(path)
                .map_err(|e| format!("Failed to load plugin: {}", e))?;
            self.plugins.push(lib);
            Ok(())
        }
    }

    // Example: Call a function named `plugin_entry` in all loaded plugins
    pub fn call_plugin_entries(&self) -> Result<(), String> {
        for lib in &self.plugins {
            unsafe {
                let func: Result<Symbol<unsafe extern "C" fn()>, _> = lib.get(b"plugin_entry");
                if let Ok(entry) = func {
                    entry();
                } else {
                    log::warn!("Plugin does not have 'plugin_entry' function");
                }
            }
        }
        Ok(())
    }
}
