use leptos::*;
use leptos_router::*;

#[component]
pub fn Sidebar() -> impl IntoView {
    view! {
        <aside class="sidebar" style="width: 250px; background: #2c3e50; color: white; display: flex; flex-direction: column;">
            <div class="logo" style="padding: 20px; font-size: 1.5rem; font-weight: bold; border-bottom: 1px solid #34495e;">
                "Authenc"
            </div>
            <nav style="flex: 1; padding: 10px;">
                <ul style="list-style: none; padding: 0; margin: 0;">
                    <li style="margin-bottom: 5px;">
                        <A href="/admin/console" class="nav-link" active_class="active">
                            <i class="fas fa-tachometer-alt" style="margin-right: 10px; width: 20px;"></i>
                            "Dashboard"
                        </A>
                    </li>
                    <li style="margin-bottom: 5px;">
                        <A href="/admin/console/users" class="nav-link" active_class="active">
                            <i class="fas fa-users" style="margin-right: 10px; width: 20px;"></i>
                            "Users"
                        </A>
                    </li>
                    <li style="margin-bottom: 5px;">
                        <A href="/admin/console/realms" class="nav-link" active_class="active">
                            <i class="fas fa-globe" style="margin-right: 10px; width: 20px;"></i>
                            "Realms"
                        </A>
                    </li>
                    <li style="margin-bottom: 5px;">
                        <A href="/admin/console/clients" class="nav-link" active_class="active">
                            <i class="fas fa-desktop" style="margin-right: 10px; width: 20px;"></i>
                            "Clients"
                        </A>
                    </li>
                    <li style="margin-bottom: 5px;">
                        <A href="/admin/console/roles" class="nav-link" active_class="active">
                            <i class="fas fa-id-badge" style="margin-right: 10px; width: 20px;"></i>
                            "Roles"
                        </A>
                    </li>
                </ul>
            </nav>
            <style>
                ".nav-link {
                    display: flex;
                    align-items: center;
                    padding: 10px 15px;
                    color: #bdc3c7;
                    text-decoration: none;
                    border-radius: 4px;
                    transition: all 0.2s;
                }
                .nav-link:hover {
                    background: #34495e;
                    color: white;
                }
                .nav-link.active {
                    background: #007bff;
                    color: white;
                }"
            </style>
        </aside>
    }
}
