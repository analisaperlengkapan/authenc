use leptos::*;
use crate::models::AuditLogResponse;
use crate::api_client::authenticated_request;
use crate::utils::get_realm_id;

#[component]
pub fn Audit() -> impl IntoView {
    // State for errors
    let (error_message, set_error_message) = create_signal::<Option<String>>(None);

    // Resource to fetch audit logs
    let audit_logs = create_resource(
        || (),
        move |_| async move {
            set_error_message.set(None); // Clear previous errors

            let realm_id = get_realm_id();
            let url = format!("/api/v1/auth/realms/{}/audit", realm_id);

            // Fetch from the API
            match authenticated_request("GET", &url, None::<&()>).await {
                Ok(response) => {
                    if response.ok() {
                        let result: Result<AuditLogResponse, _> = response.json().await;
                        result.map(|res| res.logs).map_err(|e| {
                            let msg = format!("Failed to parse response: {}", e);
                            set_error_message.set(Some(msg.clone()));
                            msg
                        }).unwrap_or_default()
                    } else {
                        let msg = format!("Failed to fetch audit logs: {}", response.status());
                        set_error_message.set(Some(msg));
                        vec![]
                    }
                },
                Err(e) => {
                    let msg = format!("Network error: {}", e);
                    set_error_message.set(Some(msg));
                    vec![]
                },
            }
        },
    );

    view! {
        <div class="audit-page">
            <div class="header-actions" style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
                <h2 style="margin: 0;">"Audit Logs"</h2>
                <div class="actions">
                    <button
                        style="background: #007bff; color: white; border: none; padding: 10px 20px; border-radius: 4px; cursor: pointer; font-weight: bold;"
                        on:click=move |_| audit_logs.refetch()
                    >
                        <i class="fas fa-sync" style="margin-right: 5px;"></i> "Refresh"
                    </button>
                </div>
            </div>

            // Error Message Display
            {move || error_message.get().map(|msg| view! {
                <div style="color: #721c24; background-color: #f8d7da; border-color: #f5c6cb; padding: .75rem 1.25rem; margin-bottom: 1rem; border: 1px solid transparent; border-radius: .25rem;">
                    {msg}
                </div>
            })}

            <div class="table-container" style="background: white; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); overflow: hidden;">
                <Suspense fallback=move || view! { <div style="padding: 20px; text-align: center;">"Loading audit logs..."</div> }>
                    {move || {
                        let logs = audit_logs.get().unwrap_or_default();

                        if logs.is_empty() {
                            view! {
                                <div style="padding: 20px; text-align: center; color: #6c757d;">
                                    "No audit logs found."
                                </div>
                            }.into_view()
                        } else {
                            view! {
                                <table style="width: 100%; border-collapse: collapse;">
                                    <thead>
                                        <tr style="background: #f8f9fa; border-bottom: 1px solid #dee2e6;">
                                            <th style="padding: 15px; text-align: left; font-weight: 600; color: #495057;">"Time"</th>
                                            <th style="padding: 15px; text-align: left; font-weight: 600; color: #495057;">"Event"</th>
                                            <th style="padding: 15px; text-align: left; font-weight: 600; color: #495057;">"User"</th>
                                            <th style="padding: 15px; text-align: left; font-weight: 600; color: #495057;">"Client"</th>
                                            <th style="padding: 15px; text-align: left; font-weight: 600; color: #495057;">"Status"</th>
                                            <th style="padding: 15px; text-align: left; font-weight: 600; color: #495057;">"Details"</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {logs.into_iter().map(|log| {
                                            view! {
                                                <tr style="border-bottom: 1px solid #dee2e6;">
                                                    <td style="padding: 15px; white-space: nowrap;">{log.timestamp}</td>
                                                    <td style="padding: 15px;">{log.event}</td>
                                                    <td style="padding: 15px;">{log.user_id.unwrap_or_else(|| "-".to_string())}</td>
                                                    <td style="padding: 15px;">{log.client_id.unwrap_or_else(|| "-".to_string())}</td>
                                                    <td style="padding: 15px;">
                                                        <span style={
                                                            if log.status == "success" {
                                                                "background: #d4edda; color: #155724; padding: 5px 10px; border-radius: 20px; font-size: 0.85em; font-weight: 500;"
                                                            } else {
                                                                "background: #f8d7da; color: #721c24; padding: 5px 10px; border-radius: 20px; font-size: 0.85em; font-weight: 500;"
                                                            }
                                                        }>
                                                            {log.status}
                                                        </span>
                                                    </td>
                                                    <td style="padding: 15px; max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title={log.detail.clone().unwrap_or_default()}>
                                                        {log.detail.unwrap_or_default()}
                                                    </td>
                                                </tr>
                                            }
                                        }).collect_view()}
                                    </tbody>
                                </table>
                            }.into_view()
                        }
                    }}
                </Suspense>
            </div>
        </div>
    }
}
