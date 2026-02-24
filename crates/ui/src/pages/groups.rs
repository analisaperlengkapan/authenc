use leptos::*;
use crate::models::Group;
use crate::api_client::authenticated_request;

#[component]
pub fn Groups() -> impl IntoView {
    // Resource to fetch groups
    let groups_resource = create_resource(
        || (),
        |_| async move {
            // TODO: Get realm ID from context or URL
            // For now, we'll try to fetch from a hardcoded UUID or fail gracefully
            // This is a placeholder UUID for the master realm if it were deterministic, but it's not.
            // In a real app, we'd have the realm ID in the app state.
            let realm_id = "550e8400-e29b-41d4-a716-446655440000";
            let url = format!("/api/v1/auth/realms/{}/groups", realm_id);

            match authenticated_request("GET", &url, None::<&()>).await {
                Ok(resp) => {
                    if resp.ok() {
                        resp.json::<Vec<Group>>().await.map_err(|e| e.to_string())
                    } else {
                        Err(format!("Error fetching groups: {}", resp.status()))
                    }
                }
                Err(e) => Err(e),
            }
        },
    );

    view! {
        <div class="groups-page">
            <div class="header-actions" style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
                <h2 style="margin: 0;">"Groups"</h2>
                <button style="background: #28a745; color: white; border: none; padding: 10px 20px; border-radius: 4px; cursor: pointer; font-weight: bold;">
                    <i class="fas fa-plus" style="margin-right: 5px;"></i> "Create Group"
                </button>
            </div>

            <div class="table-container" style="background: white; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); overflow: hidden;">
                <table style="width: 100%; border-collapse: collapse;">
                    <thead>
                        <tr style="background: #f8f9fa; border-bottom: 1px solid #dee2e6;">
                            <th style="padding: 15px; text-align: left; font-weight: 600; color: #495057;">"Name"</th>
                            <th style="padding: 15px; text-align: left; font-weight: 600; color: #495057;">"Path"</th>
                            <th style="padding: 15px; text-align: left; font-weight: 600; color: #495057;">"Description"</th>
                            <th style="padding: 15px; text-align: left; font-weight: 600; color: #495057;">"Members"</th>
                            <th style="padding: 15px; text-align: left; font-weight: 600; color: #495057;">"Actions"</th>
                        </tr>
                    </thead>
                    <tbody>
                        <Suspense fallback=move || view! { <tr><td colspan="5" style="padding: 15px; text-align: center;">"Loading groups..."</td></tr> }>
                            {move || {
                                groups_resource.get().map(|result| match result {
                                    Ok(groups) => {
                                        if groups.is_empty() {
                                            view! { <tr><td colspan="5" style="padding: 15px; text-align: center; color: #6c757d;">"No groups found"</td></tr> }.into_view()
                                        } else {
                                            groups.into_iter().map(|group| view! {
                                                <tr style="border-bottom: 1px solid #dee2e6;">
                                                    <td style="padding: 15px;">{group.name}</td>
                                                    <td style="padding: 15px;">{group.path}</td>
                                                    <td style="padding: 15px;">{group.description.unwrap_or_default()}</td>
                                                    <td style="padding: 15px;">
                                                        <span style="background: #e9ecef; color: #495057; padding: 5px 10px; border-radius: 20px; font-size: 0.85em; font-weight: 500;">
                                                            {group.member_count} " members"
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
                                            }).collect_view()
                                        }
                                    }
                                    Err(e) => view! { <tr><td colspan="5" style="padding: 15px; text-align: center; color: #dc3545;">"Error loading groups: " {e}</td></tr> }.into_view()
                                })
                            }}
                        </Suspense>
                    </tbody>
                </table>
            </div>
        </div>
    }
}
