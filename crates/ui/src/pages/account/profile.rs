use leptos::prelude::*;
use crate::api_client::authenticated_request;
use crate::models::UserResponse;

#[component]
pub fn Profile() -> impl IntoView {
    let user_resource = LocalResource::new(|_| async move {
            let resp = authenticated_request("GET", "/api/v1/auth/account", None::<&()>).await;
            match resp {
                Ok(response) => {
                    if response.ok() {
                        response.json::<UserResponse>().await.ok()
                    } else {
                        None
                    }
                }
                Err(_) => None,
            }
        },
    );

    view! {
        <div class="profile-page">
            <h2 style="margin-bottom: 20px;">"My Profile"</h2>
            <div class="card" style="background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                <Suspense fallback=move || view! { <p>"Loading profile..."</p> }>
                    {move || {
                        user_resource.get().map(|data| {
                            match data {
                                Some(user) => view! {
                                    <div class="profile-details">
                                        <div class="detail-row" style="margin-bottom: 15px;">
                                            <strong style="display: block; color: #6c757d; margin-bottom: 5px;">"Username"</strong>
                                            <div style="font-size: 1.1em;">{user.username}</div>
                                        </div>
                                        <div class="detail-row" style="margin-bottom: 15px;">
                                            <strong style="display: block; color: #6c757d; margin-bottom: 5px;">"Email"</strong>
                                            <div style="font-size: 1.1em;">
                                                {user.email}
                                                <span style="margin-left: 10px; font-size: 0.8em; padding: 2px 6px; border-radius: 4px; background: #e9ecef;">
                                                    {if user.email_verified { "Verified" } else { "Unverified" }}
                                                </span>
                                            </div>
                                        </div>
                                        <div class="detail-row" style="margin-bottom: 15px;">
                                            <strong style="display: block; color: #6c757d; margin-bottom: 5px;">"Full Name"</strong>
                                            <div style="font-size: 1.1em;">
                                                {format!("{} {}", user.first_name.unwrap_or_default(), user.last_name.unwrap_or_default())}
                                            </div>
                                        </div>
                                        <div class="detail-row" style="margin-bottom: 15px;">
                                            <strong style="display: block; color: #6c757d; margin-bottom: 5px;">"Account Status"</strong>
                                            <div style="font-size: 1.1em;">
                                                {if user.enabled {
                                                    view! { <span style="color: green;">"Active"</span> }
                                                } else {
                                                    view! { <span style="color: red;">"Disabled"</span> }
                                                }}
                                            </div>
                                        </div>
                                    </div>
                                }.into_any(),
                                None => view! { <p style="color: red;">"Failed to load profile. Please verify your login."</p> }.into_any()
                            }
                        })
                    }}
                </Suspense>
            </div>
        </div>
    }
}
