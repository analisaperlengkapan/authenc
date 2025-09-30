//! Admin Console UI using Leptos
//!
//! Provides a web-based admin interface for managing users, roles, realms, etc.

use axum::{extract::State, http::StatusCode, response::Html, Router};
use std::sync::Arc;

use crate::app::AppState;
use crate::database::Database;
use crate::handlers::api::auth_bearer::AuthBearer;
use crate::services::admin::{AdminManager, AdminService};
use crate::services::stores::user_store::UserStoreTrait;

/// Create admin console routes
pub fn create_admin_console_routes(
    state: Arc<crate::app::AppState>,
    db_state: Arc<Database>,
) -> Router<Arc<Database>> {
    Router::new()
        .route("/", axum::routing::get(dashboard))
        .route("/users", axum::routing::get(users_page))
        .route("/roles", axum::routing::get(roles_page))
        .route("/realms", axum::routing::get(realms_page))
        .route("/clients", axum::routing::get(clients_page))
        .with_state((state, db_state))
}

/// Dashboard handler
async fn dashboard(
    State((_app_state, db_state)): State<(Arc<AppState>, Arc<Database>)>,
    _auth: AuthBearer,
) -> Result<Html<String>, StatusCode> {
    let admin_manager = AdminManager::new(db_state.clone());

    // Fetch system stats from admin manager
    let stats = match admin_manager.get_system_stats().await {
        Ok(stats) => stats,
        Err(_) => return Err(StatusCode::INTERNAL_SERVER_ERROR),
    };

    let html = format!(
        r#"
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="utf-8"/>
        <meta name="viewport" content="width=device-width, initial-scale=1"/>
        <title>Authenc Admin Console</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }}
            .header {{ background: #2c3e50; color: white; padding: 20px; border-bottom: 1px solid #dee2e6; }}
            .nav {{ margin-top: 20px; background: white; padding: 10px; border-radius: 5px; }}
            .nav ul {{ list-style: none; padding: 0; margin: 0; }}
            .nav li {{ display: inline; margin-right: 20px; }}
            .nav a {{ text-decoration: none; color: #007bff; font-weight: bold; }}
            .nav a:hover {{ text-decoration: underline; }}
            .content {{ margin-top: 20px; }}
            .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-top: 20px; }}
            .stat-card {{ background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
            .stat-card h3 {{ margin-top: 0; color: #2c3e50; }}
            .stat-value {{ font-size: 2em; font-weight: bold; color: #007bff; }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>Authenc Admin Console</h1>
        </div>
        <nav class="nav">
            <ul>
                <li><a href="/admin/console/">Dashboard</a></li>
                <li><a href="/admin/console/users">Users</a></li>
                <li><a href="/admin/console/roles">Roles</a></li>
                <li><a href="/admin/console/realms">Realms</a></li>
                <li><a href="/admin/console/clients">Clients</a></li>
            </ul>
        </nav>
        <div class="content">
            <h2>Dashboard</h2>
            <div class="stats-grid">
                <div class="stat-card">
                    <h3>Total Users</h3>
                    <div class="stat-value">{}</div>
                </div>
                <div class="stat-card">
                    <h3>Active Sessions</h3>
                    <div class="stat-value">{}</div>
                </div>
                <div class="stat-card">
                    <h3>Total Realms</h3>
                    <div class="stat-value">{}</div>
                </div>
                <div class="stat-card">
                    <h3>Security Events (24h)</h3>
                    <div class="stat-value">{}</div>
                </div>
            </div>
        </div>
    </body>
    </html>
    "#,
        stats.total_users, stats.active_sessions, stats.total_realms, stats.security_events_today
    );

    Ok(Html(html))
}

/// Users page handler
async fn users_page(
    State((app_state, _db_state)): State<(Arc<AppState>, Arc<Database>)>,
    _auth: AuthBearer,
) -> Result<Html<String>, StatusCode> {
    // Fetch users from user store
    let users = match app_state.user_store.get_all().await {
        Ok(users) => users,
        Err(_) => return Err(StatusCode::INTERNAL_SERVER_ERROR),
    };

    let mut users_html = String::new();
    for user in users {
        users_html.push_str(&format!(r#"
        <tr>
            <td>{}</td>
            <td>{}</td>
            <td>{}</td>
            <td>{}</td>
            <td>
                <button onclick="editUser('{}')">Edit</button>
                <button onclick="deleteUser('{}')" style="background: #dc3545; color: white;">Delete</button>
            </td>
        </tr>
        "#, user.username, user.email,
           user.first_name.unwrap_or_else(|| "N/A".to_string()),
           if user.enabled { "Enabled" } else { "Disabled" },
           user.id, user.id));
    }

    let html = format!(
        r#"
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="utf-8"/>
        <meta name="viewport" content="width=device-width, initial-scale=1"/>
        <title>Users - Authenc Admin Console</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }}
            .header {{ background: #2c3e50; color: white; padding: 20px; border-bottom: 1px solid #dee2e6; }}
            .nav {{ margin-top: 20px; background: white; padding: 10px; border-radius: 5px; }}
            .nav ul {{ list-style: none; padding: 0; margin: 0; }}
            .nav li {{ display: inline; margin-right: 20px; }}
            .nav a {{ text-decoration: none; color: #007bff; font-weight: bold; }}
            .nav a:hover {{ text-decoration: underline; }}
            .content {{ margin-top: 20px; }}
            table {{ width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
            th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #dee2e6; }}
            th {{ background: #f8f9fa; font-weight: bold; }}
            button {{ padding: 6px 12px; border: none; border-radius: 4px; cursor: pointer; }}
            button:hover {{ opacity: 0.8; }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>Authenc Admin Console</h1>
        </div>
        <nav class="nav">
            <ul>
                <li><a href="/admin/console/">Dashboard</a></li>
                <li><a href="/admin/console/users">Users</a></li>
                <li><a href="/admin/console/roles">Roles</a></li>
                <li><a href="/admin/console/realms">Realms</a></li>
                <li><a href="/admin/console/clients">Clients</a></li>
            </ul>
        </nav>
        <div class="content">
            <h2>Users Management</h2>
            <button onclick="createUser()" style="background: #28a745; color: white; margin-bottom: 20px;">Create New User</button>
            <table>
                <thead>
                    <tr>
                        <th>Username</th>
                        <th>Email</th>
                        <th>Name</th>
                        <th>Status</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    {}
                </tbody>
            </table>
        </div>
        <script>
            function createUser() {{
                alert('Create user functionality not implemented yet');
            }}
            function editUser(id) {{
                alert('Edit user ' + id + ' not implemented yet');
            }}
            function deleteUser(id) {{
                if (confirm('Are you sure you want to delete this user?')) {{
                    alert('Delete user ' + id + ' not implemented yet');
                }}
            }}
        </script>
    </body>
    </html>
    "#,
        users_html
    );

    Ok(Html(html))
}

/// Roles page handler
async fn roles_page(
    State((app_state, _db_state)): State<(Arc<AppState>, Arc<Database>)>,
    _auth: AuthBearer,
) -> Result<Html<String>, StatusCode> {
    // Fetch roles from role store
    let roles = app_state.role_store.get_all();

    let mut roles_html = String::new();
    for role in roles {
        roles_html.push_str(&format!(r#"
        <tr>
            <td>{}</td>
            <td>{}</td>
            <td>{}</td>
            <td>
                <button onclick="editRole('{}')">Edit</button>
                <button onclick="deleteRole('{}')" style="background: #dc3545; color: white;">Delete</button>
            </td>
        </tr>
        "#, role.name, role.description.unwrap_or_else(|| "N/A".to_string()),
           role.realm_id.map(|id| id.to_string()).unwrap_or_else(|| "Global".to_string()),
           role.id, role.id));
    }

    let html = format!(
        r#"
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="utf-8"/>
        <meta name="viewport" content="width=device-width, initial-scale=1"/>
        <title>Roles - Authenc Admin Console</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }}
            .header {{ background: #2c3e50; color: white; padding: 20px; border-bottom: 1px solid #dee2e6; }}
            .nav {{ margin-top: 20px; background: white; padding: 10px; border-radius: 5px; }}
            .nav ul {{ list-style: none; padding: 0; margin: 0; }}
            .nav li {{ display: inline; margin-right: 20px; }}
            .nav a {{ text-decoration: none; color: #007bff; font-weight: bold; }}
            .nav a:hover {{ text-decoration: underline; }}
            .content {{ margin-top: 20px; }}
            table {{ width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
            th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #dee2e6; }}
            th {{ background: #f8f9fa; font-weight: bold; }}
            button {{ padding: 6px 12px; border: none; border-radius: 4px; cursor: pointer; }}
            button:hover {{ opacity: 0.8; }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>Authenc Admin Console</h1>
        </div>
        <nav class="nav">
            <ul>
                <li><a href="/admin/console/">Dashboard</a></li>
                <li><a href="/admin/console/users">Users</a></li>
                <li><a href="/admin/console/roles">Roles</a></li>
                <li><a href="/admin/console/realms">Realms</a></li>
                <li><a href="/admin/console/clients">Clients</a></li>
            </ul>
        </nav>
        <div class="content">
            <h2>Roles Management</h2>
            <button onclick="createRole()" style="background: #28a745; color: white; margin-bottom: 20px;">Create New Role</button>
            <table>
                <thead>
                    <tr>
                        <th>Role Name</th>
                        <th>Description</th>
                        <th>Realm</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    {}
                </tbody>
            </table>
        </div>
        <script>
            function createRole() {{
                alert('Create role functionality not implemented yet');
            }}
            function editRole(id) {{
                alert('Edit role ' + id + ' not implemented yet');
            }}
            function deleteRole(id) {{
                if (confirm('Are you sure you want to delete this role?')) {{
                    alert('Delete role ' + id + ' not implemented yet');
                }}
            }}
        </script>
    </body>
    </html>
    "#,
        roles_html
    );

    Ok(Html(html))
}

/// Realms page handler
async fn realms_page(
    State((app_state, _db_state)): State<(Arc<AppState>, Arc<Database>)>,
    _auth: AuthBearer,
) -> Result<Html<String>, StatusCode> {
    // Fetch realms from realm store
    let realms = app_state.realm_store.get_all();

    let mut realms_html = String::new();
    for realm in realms {
        realms_html.push_str(&format!(r#"
        <tr>
            <td>{}</td>
            <td>{}</td>
            <td>{}</td>
            <td>
                <button onclick="editRealm('{}')">Edit</button>
                <button onclick="deleteRealm('{}')" style="background: #dc3545; color: white;">Delete</button>
            </td>
        </tr>
        "#, realm.name, realm.display_name.unwrap_or_else(|| "N/A".to_string()),
           if realm.enabled { "Enabled" } else { "Disabled" },
           realm.id, realm.id));
    }

    let html = format!(
        r#"
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="utf-8"/>
        <meta name="viewport" content="width=device-width, initial-scale=1"/>
        <title>Realms - Authenc Admin Console</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }}
            .header {{ background: #2c3e50; color: white; padding: 20px; border-bottom: 1px solid #dee2e6; }}
            .nav {{ margin-top: 20px; background: white; padding: 10px; border-radius: 5px; }}
            .nav ul {{ list-style: none; padding: 0; margin: 0; }}
            .nav li {{ display: inline; margin-right: 20px; }}
            .nav a {{ text-decoration: none; color: #007bff; font-weight: bold; }}
            .nav a:hover {{ text-decoration: underline; }}
            .content {{ margin-top: 20px; }}
            table {{ width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
            th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #dee2e6; }}
            th {{ background: #f8f9fa; font-weight: bold; }}
            button {{ padding: 6px 12px; border: none; border-radius: 4px; cursor: pointer; }}
            button:hover {{ opacity: 0.8; }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>Authenc Admin Console</h1>
        </div>
        <nav class="nav">
            <ul>
                <li><a href="/admin/console/">Dashboard</a></li>
                <li><a href="/admin/console/users">Users</a></li>
                <li><a href="/admin/console/roles">Roles</a></li>
                <li><a href="/admin/console/realms">Realms</a></li>
                <li><a href="/admin/console/clients">Clients</a></li>
            </ul>
        </nav>
        <div class="content">
            <h2>Realms Management</h2>
            <button onclick="createRealm()" style="background: #28a745; color: white; margin-bottom: 20px;">Create New Realm</button>
            <table>
                <thead>
                    <tr>
                        <th>Realm Name</th>
                        <th>Display Name</th>
                        <th>Status</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    {}
                </tbody>
            </table>
        </div>
        <script>
            function createRealm() {{
                alert('Create realm functionality not implemented yet');
            }}
            function editRealm(id) {{
                alert('Edit realm ' + id + ' not implemented yet');
            }}
            function deleteRealm(id) {{
                if (confirm('Are you sure you want to delete this realm?')) {{
                    alert('Delete realm ' + id + ' not implemented yet');
                }}
            }}
        </script>
    </body>
    </html>
    "#,
        realms_html
    );

    Ok(Html(html))
}

/// Clients page handler
async fn clients_page(
    State((app_state, _db_state)): State<(Arc<AppState>, Arc<Database>)>,
    _auth: AuthBearer,
) -> Result<Html<String>, StatusCode> {
    // Fetch clients from OIDC client store
    let clients = match app_state.oidc_client_store.all().await {
        Ok(clients) => clients,
        Err(_) => return Err(StatusCode::INTERNAL_SERVER_ERROR),
    };

    let mut clients_html = String::new();
    for client in clients {
        clients_html.push_str(&format!(r#"
        <tr>
            <td>{}</td>
            <td>{}</td>
            <td>{}</td>
            <td>
                <button onclick="editClient('{}')">Edit</button>
                <button onclick="deleteClient('{}')" style="background: #dc3545; color: white;">Delete</button>
            </td>
        </tr>
        "#, client.client_id, client.name, if client.enabled { "Enabled" } else { "Disabled" },
           client.id, client.id));
    }

    let html = format!(
        r#"
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="utf-8"/>
        <meta name="viewport" content="width=device-width, initial-scale=1"/>
        <title>Clients - Authenc Admin Console</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }}
            .header {{ background: #2c3e50; color: white; padding: 20px; border-bottom: 1px solid #dee2e6; }}
            .nav {{ margin-top: 20px; background: white; padding: 10px; border-radius: 5px; }}
            .nav ul {{ list-style: none; padding: 0; margin: 0; }}
            .nav li {{ display: inline; margin-right: 20px; }}
            .nav a {{ text-decoration: none; color: #007bff; font-weight: bold; }}
            .nav a:hover {{ text-decoration: underline; }}
            .content {{ margin-top: 20px; }}
            table {{ width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
            th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #dee2e6; }}
            th {{ background: #f8f9fa; font-weight: bold; }}
            button {{ padding: 6px 12px; border: none; border-radius: 4px; cursor: pointer; }}
            button:hover {{ opacity: 0.8; }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>Authenc Admin Console</h1>
        </div>
        <nav class="nav">
            <ul>
                <li><a href="/admin/console/">Dashboard</a></li>
                <li><a href="/admin/console/users">Users</a></li>
                <li><a href="/admin/console/roles">Roles</a></li>
                <li><a href="/admin/console/realms">Realms</a></li>
                <li><a href="/admin/console/clients">Clients</a></li>
            </ul>
        </nav>
        <div class="content">
            <h2>Clients Management</h2>
            <button onclick="createClient()" style="background: #28a745; color: white; margin-bottom: 20px;">Create New Client</button>
            <table>
                <thead>
                    <tr>
                        <th>Client ID</th>
                        <th>Name</th>
                        <th>Status</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    {}
                </tbody>
            </table>
        </div>
        <script>
            function createClient() {{
                alert('Create client functionality not implemented yet');
            }}
            function editClient(id) {{
                alert('Edit client ' + id + ' not implemented yet');
            }}
            function deleteClient(id) {{
                if (confirm('Are you sure you want to delete this client?')) {{
                    alert('Delete client ' + id + ' not implemented yet');
                }}
            }}
        </script>
    </body>
    </html>
    "#,
        clients_html
    );

    Ok(Html(html))
}
