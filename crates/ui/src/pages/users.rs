use leptos::*;
use crate::models::UserResponse;
use crate::api_client::authenticated_request;

fn get_realm_id() -> String {
    if let Ok(Some(storage)) = gloo_utils::window().local_storage() {
        if let Ok(Some(id)) = storage.get_item("authenc_selected_realm_id") {
            return id;
        }
    }
    // Fallback to default/master realm ID
    "550e8400-e29b-41d4-a716-446655440000".to_string()
}

#[component]
pub fn Users() -> impl IntoView {
    let (error_message, set_error_message) = create_signal::<Option<String>>(None);

    let users_resource = create_resource(
        || (),
        move |_| async move {
            set_error_message.set(None);
            let realm_id = get_realm_id();
            let url = format!("/api/v1/auth/realms/{}/users", realm_id);

            match authenticated_request("GET", &url, None::<&()>).await {
                Ok(response) => {
                    if response.ok() {
                        response.json::<Vec<UserResponse>>().await.map_err(|e| e.to_string())
                    } else {
                        let msg = format!("Failed to fetch users: {}", response.status());
                        set_error_message.set(Some(msg.clone()));
                        Err(msg)
                    }
                }
                Err(e) => {
                    set_error_message.set(Some(e.clone()));
                    Err(e)
                }
            }
        }
    );

    view! {
        <div class="users-page">
            <div class="header-actions" style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
                <h2 style="margin: 0;">"Users"</h2>
                <button style="background: #28a745; color: white; border: none; padding: 10px 20px; border-radius: 4px; cursor: pointer; font-weight: bold;">
                    <i class="fas fa-plus" style="margin-right: 5px;"></i> "Create User"
                </button>
            </div>

            {move || error_message.get().map(|msg| view! {
                <div style="color: #721c24; background-color: #f8d7da; border-color: #f5c6cb; padding: .75rem 1.25rem; margin-bottom: 1rem; border: 1px solid transparent; border-radius: .25rem;">
                    {msg}
                </div>
            })}

            <div class="table-container" style="background: white; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); overflow: hidden;">
                <Suspense fallback=move || view! { <div style="padding: 20px; text-align: center;">"Loading users..."</div> }>
                {move || {
                    users_resource.get().map(|res| {
                        match res {
                            Ok(users) => {
                                if users.is_empty() {
                                    view! {
                                        <div style="padding: 20px; text-align: center; color: #6c757d;">
                                            "No users found in this realm."
                                        </div>
                                    }.into_view()
                                } else {
                                    view! {
                                        <table style="width: 100%; border-collapse: collapse;">
                                            <thead>
                                                <tr style="background: #f8f9fa; border-bottom: 1px solid #dee2e6;">
                                                    <th style="padding: 15px; text-align: left; font-weight: 600; color: #495057;">"Username"</th>
                                                    <th style="padding: 15px; text-align: left; font-weight: 600; color: #495057;">"Email"</th>
                                                    <th style="padding: 15px; text-align: left; font-weight: 600; color: #495057;">"Status"</th>
                                                    <th style="padding: 15px; text-align: left; font-weight: 600; color: #495057;">"Actions"</th>
                                                </tr>
                                            </thead>
                                            <tbody>
                                                {users.into_iter().map(|user| {
                                                    view! {
                                                        <tr style="border-bottom: 1px solid #dee2e6;">
                                                            <td style="padding: 15px;">{user.username}</td>
                                                            <td style="padding: 15px;">{user.email}</td>
                                                            <td style="padding: 15px;">
                                                                <span style={if user.enabled {
                                                                    "background: #d4edda; color: #155724; padding: 5px 10px; border-radius: 20px; font-size: 0.85em; font-weight: 500;"
                                                                } else {
                                                                    "background: #f8d7da; color: #721c24; padding: 5px 10px; border-radius: 20px; font-size: 0.85em; font-weight: 500;"
                                                                }}>
                                                                    {if user.enabled { "Enabled" } else { "Disabled" }}
                                                                </span>
                                                            </td>
                                                            <td style="padding: 15px;">
                                                                <button style="margin-right: 8px; padding: 6px 12px; border: 1px solid #dee2e6; background: white; border-radius: 4px; cursor: pointer; color: #495057;">
                                                                    <i class="fas fa-edit"></i> " Edit"
                                                                </button>
                                                                <button style="padding: 6px 12px; border: 1px solid #dc3545; background: white; border-radius: 4px; cursor: pointer; color: #dc3545;">
                                                                    <i class="fas fa-trash"></i>
                                                                </button>
                                                            </td>
                                                        </tr>
                                                    }
                                                }).collect_view()}
                                            </tbody>
                                        </table>
                                    }.into_view()
                                }
                            },
                            Err(_) => view! {
                                <div style="padding: 20px; text-align: center; color: #dc3545;">
                                    "Error loading users."
                                </div>
                            }.into_view()
                        }
                    })
                }}
                </Suspense>
            </div>
        </div>
    }
}
