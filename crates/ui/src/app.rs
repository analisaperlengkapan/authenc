use leptos::*;
use leptos_router::*;
use crate::components::layout::Layout;
use crate::pages::{home::Home, users::Users, realms::Realms};

#[component]
pub fn App() -> impl IntoView {
    view! {
        <Router>
            <Routes>
                <Route path="/admin/console" view=Layout>
                    <Route path="" view=Home/>
                    <Route path="users" view=Users/>
                    <Route path="realms" view=Realms/>
                </Route>
                // Redirect root to admin console for now if accessed directly via SPA router
                <Route path="/" view=|| view! { <Redirect path="/admin/console"/> }/>
            </Routes>
        </Router>
    }
}
