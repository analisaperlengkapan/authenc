use authenc_ui::App;
use leptos::prelude::*;

pub fn main() {
    console_error_panic_hook::set_once();
    mount_to_body(|| view! { <App/> })
}
