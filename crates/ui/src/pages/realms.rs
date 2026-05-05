use leptos::*;
use serde::{Deserialize, Serialize};
use crate::api_client::authenticated_request;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RealmResponse {
    pub id: Uuid,
    pub name: String,
    pub display_name: Option<String>,
    pub description: Option<String>,
    pub enabled: bool,
    pub created_at: String,
    pub updated_at: String,
}

fn switch_realm(realm_id: Uuid) {
    if let Ok(Some(storage)) = gloo_utils::window().local_storage() {
        let _ = storage.set_item("authenc_selected_realm_id", &realm_id.to_string());
        // Reload page to refresh all components with the new realm context
        let _ = gloo_utils::window().location().reload();
    }
}

#[component]
pub fn Realms() -> impl IntoView {
    let (error_message, set_error_message) = create_signal::<Option<String>>(None);

    let realms_resource = create_resource(
        || (),
        move |_| async move {
            set_error_message.set(None);
            match authenticated_request("GET", "/api/v1/auth/realms", None::<&()>).await {
                Ok(response) => {
                    if response.ok() {
                        response.json::<Vec<RealmResponse>>().await.map_err(|e| e.to_string())
                    } else {
                        let msg = format!("Failed to fetch realms: {}", response.status());
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
        <div class="realms-page">
            <div class="header-actions" style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
                <h2 style="margin: 0;">"Realms"</h2>
                <button style="background: #28a745; color: white; border: none; padding: 10px 20px; border-radius: 4px; cursor: pointer; font-weight: bold;">
                    <i class="fas fa-plus" style="margin-right: 5px;"></i> "Create Realm"
                </button>
            </div>

            {move || error_message.get().map(|msg| view! {
                <div style="color: #721c24; background-color: #f8d7da; border-color: #f5c6cb; padding: .75rem 1.25rem; margin-bottom: 1rem; border: 1px solid transparent; border-radius: .25rem;">
                    {msg}
                </div>
            })}

            <div class="realm-grid" style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px;">
                <Suspense fallback=move || view! { <div style="padding: 20px; text-align: center;">"Loading realms..."</div> }>
                {move || {
                    realms_resource.get().map(|res| {
                        match res {
                            Ok(realms) => {
                                if realms.is_empty() {
                                    view! {
                                        <div style="grid-column: 1/-1; padding: 40px; text-align: center; background: white; border-radius: 8px;">
                                            "No realms found. Create one to get started."
                                        </div>
                                    }.into_view()
                                } else {
                                    realms.into_iter().map(|realm| {
                                        let id = realm.id;
                                        let is_master = realm.name == "master";
                                        view! {
                                            <div class="realm-card" style=format!(
                                                "background: white; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); padding: 20px; border-top: 4px solid {};",
                                                if is_master { "#007bff" } else { "#6c757d" }
                                            )>
                                                <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 15px;">
                                                    <h3 style="margin: 0; font-size: 1.2rem;">{realm.display_name.unwrap_or(realm.name)}</h3>
                                                    <span style={if realm.enabled {
                                                        "background: #d4edda; color: #155724; padding: 2px 8px; border-radius: 4px; font-size: 0.8em;"
                                                    } else {
                                                        "background: #f8d7da; color: #721c24; padding: 2px 8px; border-radius: 4px; font-size: 0.8em;"
                                                    }}>
                                                        {if realm.enabled { "Enabled" } else { "Disabled" }}
                                                    </span>
                                                </div>
                                                <p style="color: #6c757d; margin-bottom: 20px; min-height: 3em;">
                                                    {realm.description.unwrap_or_else(|| "No description provided.".to_string())}
                                                </p>
                                                <div class="actions" style="border-top: 1px solid #eee; padding-top: 15px; display: flex; justify-content: flex-end;">
                                                    <button
                                                        on:click=move |_| switch_realm(id)
                                                        style="padding: 6px 12px; border: 1px solid #007bff; background: white; color: #007bff; border-radius: 4px; cursor: pointer;"
                                                    >
                                                        "Manage"
                                                    </button>
                                                </div>
                                            </div>
                                        }
                                    }).collect_view()
                                }
                            },
                            Err(_) => view! {
                                <div style="grid-column: 1/-1; padding: 20px; text-align: center; color: #dc3545; background: white; border-radius: 8px;">
                                    "Error loading realms."
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
