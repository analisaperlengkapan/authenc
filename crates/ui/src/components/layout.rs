use leptos::*;
use leptos_router::*;
use crate::components::sidebar::Sidebar;
use crate::components::header::Header;

#[component]
pub fn Layout() -> impl IntoView {
    view! {
        <div class="layout" style="display: flex; height: 100vh;">
            <Sidebar/>
            <div class="main-content" style="flex: 1; display: flex; flex-direction: column;">
                <Header/>
                <div class="page-content" style="padding: 20px; flex: 1; overflow-y: auto;">
                    <Outlet/>
                </div>
            </div>
        </div>
    }
}
