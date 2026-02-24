use leptos::*;
use leptos_router::*;
use crate::components::layout::Layout;
use crate::pages::{
    home::Home,
    users::Users,
    realms::Realms,
    clients::Clients,
    roles::Roles,
    forgot_password::ForgotPassword,
    reset_password::ResetPassword,
    account::{profile::Profile, security::Security}
};

#[component]
pub fn App() -> impl IntoView {
    view! {
        <Router>
            <Routes>
                <Route path="/admin/console" view=Layout>
                    <Route path="" view=Home/>
                    <Route path="users" view=Users/>
                    <Route path="realms" view=Realms/>
                    <Route path="clients" view=Clients/>
                    <Route path="roles" view=Roles/>
                </Route>

                <Route path="/account" view=Layout>
                    <Route path="profile" view=Profile/>
                    <Route path="security" view=Security/>
                </Route>

                // Public auth routes
                <Route path="/forgot-password" view=ForgotPassword/>
                <Route path="/reset-password" view=ResetPassword/>

                // Redirect root to admin console for now if accessed directly via SPA router
                <Route path="/" view=|| view! { <Redirect path="/admin/console"/> }/>
            </Routes>
        </Router>
    }
}
