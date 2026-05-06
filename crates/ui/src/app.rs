use leptos::*;
use leptos_router::*;
use crate::components::layout::Layout;
use crate::pages::{
    home::Home,
    login::Login,
    users::Users,
    realms::Realms,
    clients::Clients,
    roles::Roles,
    groups::Groups,
    audit::Audit,
    identity_providers::IdentityProviders,
    organizations::Organizations,
    security::SecurityDashboard,
    authorization::Authorization,
    forgot_password::ForgotPassword,
    reset_password::ResetPassword,
    verify_email::VerifyEmail,
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
                    <Route path="groups" view=Groups/>
                    <Route path="realms" view=Realms/>
                    <Route path="clients" view=Clients/>
                    <Route path="roles" view=Roles/>
                    <Route path="identity-providers" view=IdentityProviders/>
                    <Route path="organizations" view=Organizations/>
                    <Route path="security" view=SecurityDashboard/>
                    <Route path="authorization" view=Authorization/>
                    <Route path="audit" view=Audit/>
                </Route>

                <Route path="/account" view=Layout>
                    <Route path="profile" view=Profile/>
                    <Route path="security" view=Security/>
                </Route>

                // Public auth routes
                <Route path="/login" view=Login/>
                <Route path="/forgot-password" view=ForgotPassword/>
                <Route path="/reset-password" view=ResetPassword/>
                <Route path="/verify-email" view=VerifyEmail/>

                // Redirect root based on auth status
                <Route path="/" view=|| {
                    let has_token = if let Ok(Some(storage)) = gloo_utils::window().local_storage() {
                        storage.get_item("authenc_token").ok().flatten().is_some()
                    } else {
                        false
                    };
                    if has_token {
                        view! { <Redirect path="/admin/console"/> }
                    } else {
                        view! { <Redirect path="/login"/> }
                    }
                }/>
            </Routes>
        </Router>
    }
}
