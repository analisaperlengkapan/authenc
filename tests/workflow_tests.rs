use axum::{
    Router,
    extract::{Json, Path, Query, State},
    http::StatusCode,
    routing::{delete, get, post, put},
};
use axum_test::TestServer;
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

// Advanced Workflow Tests
// Testing complex user workflows, multi-step processes, and business logic scenarios

#[derive(Clone)]
struct WorkflowState {
    users: Arc<Mutex<HashMap<String, serde_json::Value>>>,
    workflows: Arc<Mutex<HashMap<String, serde_json::Value>>>,
    workflow_steps: Arc<Mutex<HashMap<String, Vec<serde_json::Value>>>>,
    approvals: Arc<Mutex<HashMap<String, Vec<serde_json::Value>>>>,
    notifications: Arc<Mutex<Vec<serde_json::Value>>>,
    audit_trail: Arc<Mutex<Vec<serde_json::Value>>>,
}

impl WorkflowState {
    fn new() -> Self {
        Self {
            users: Arc::new(Mutex::new(HashMap::new())),
            workflows: Arc::new(Mutex::new(HashMap::new())),
            workflow_steps: Arc::new(Mutex::new(HashMap::new())),
            approvals: Arc::new(Mutex::new(HashMap::new())),
            notifications: Arc::new(Mutex::new(Vec::new())),
            audit_trail: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

#[tokio::test]
async fn test_user_onboarding_workflow() {
    let state = WorkflowState::new();

    let app = Router::new()
        .route("/workflow/onboarding/start", post(move |State(state): State<WorkflowState>, Json(onboarding_data): Json<serde_json::Value>| async move {
            let mut users = state.users.lock().await;
            let mut workflows = state.workflows.lock().await;
            let mut workflow_steps = state.workflow_steps.lock().await;
            let mut notifications = state.notifications.lock().await;
            let mut audit_trail = state.audit_trail.lock().await;

            let user_id = format!("user_{}", users.len() + 1);
            let workflow_id = format!("onboarding_{}", user_id);

            // Create user
            users.insert(user_id.clone(), json!({
                "id": user_id,
                "email": onboarding_data["email"],
                "status": "onboarding",
                "onboarding_step": 1,
                "created_at": "2024-12-01T10:00:00Z"
            }));

            // Create onboarding workflow
            workflows.insert(workflow_id.clone(), json!({
                "id": workflow_id,
                "user_id": user_id,
                "type": "onboarding",
                "status": "in_progress",
                "current_step": 1,
                "total_steps": 5,
                "created_at": "2024-12-01T10:00:00Z"
            }));

            // Initialize workflow steps
            workflow_steps.insert(workflow_id.clone(), vec![
                json!({"step": 1, "name": "email_verification", "status": "pending", "required": true}),
                json!({"step": 2, "name": "profile_setup", "status": "pending", "required": true}),
                json!({"step": 3, "name": "security_setup", "status": "pending", "required": true}),
                json!({"step": 4, "name": "preferences", "status": "pending", "required": false}),
                json!({"step": 5, "name": "completion", "status": "pending", "required": true}),
            ]);

            // Send welcome notification
            notifications.push(json!({
                "type": "onboarding_started",
                "user_id": user_id,
                "message": "Welcome! Let's get you set up.",
                "timestamp": "2024-12-01T10:00:00Z"
            }));

            // Audit trail
            audit_trail.push(json!({
                "event": "onboarding_workflow_started",
                "user_id": user_id,
                "workflow_id": workflow_id,
                "timestamp": "2024-12-01T10:00:00Z"
            }));

            Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                "workflow_id": workflow_id,
                "user_id": user_id,
                "message": "Onboarding workflow started",
                "next_step": "email_verification"
            })))
        }))
        .route("/workflow/onboarding/{workflow_id}/step/{step_number}", post(move |State(state): State<WorkflowState>, Path((workflow_id, step_number)): Path<(String, u32)>, Json(step_data): Json<serde_json::Value>| async move {
            let workflows = state.workflows.lock().await;
            let mut workflow_steps = state.workflow_steps.lock().await;
            let mut users = state.users.lock().await;
            let mut notifications = state.notifications.lock().await;
            let mut audit_trail = state.audit_trail.lock().await;

            if let Some(workflow) = workflows.get(&workflow_id) {
                if let Some(steps) = workflow_steps.get_mut(&workflow_id) {
                    if step_number <= steps.len() as u32 {
                        let step_index = (step_number - 1) as usize;
                        steps[step_index]["status"] = json!("completed");

                        // Update user onboarding step
                        let user_id = workflow["user_id"].as_str().unwrap();
                        if let Some(user) = users.get_mut(user_id) {
                            user["onboarding_step"] = json!(step_number);
                        }

                        // Check if workflow is complete
                        let all_required_complete = steps.iter()
                            .filter(|s| s["required"] == true)
                            .all(|s| s["status"] == "completed");

                        if all_required_complete && step_number == steps.len() as u32 {
                            // Complete onboarding
                            if let Some(user) = users.get_mut(user_id) {
                                user["status"] = json!("active");
                            }

                            notifications.push(json!({
                                "type": "onboarding_completed",
                                "user_id": user_id,
                                "message": "Congratulations! Your account is now active.",
                                "timestamp": "2024-12-01T10:30:00Z"
                            }));

                            audit_trail.push(json!({
                                "event": "onboarding_workflow_completed",
                                "user_id": user_id,
                                "workflow_id": workflow_id,
                                "timestamp": "2024-12-01T10:30:00Z"
                            }));
                        } else {
                            // Send next step notification
                            let next_step = if step_number < steps.len() as u32 {
                                steps[step_number as usize]["name"].as_str().unwrap()
                            } else {
                                "completion"
                            };

                            notifications.push(json!({
                                "type": "onboarding_next_step",
                                "user_id": user_id,
                                "message": format!("Great! Next step: {}", next_step),
                                "timestamp": "2024-12-01T10:15:00Z"
                            }));
                        }

                        audit_trail.push(json!({
                            "event": "onboarding_step_completed",
                            "user_id": user_id,
                            "workflow_id": workflow_id,
                            "step_number": step_number,
                            "step_name": steps[step_index]["name"],
                            "timestamp": "2024-12-01T10:15:00Z"
                        }));

                        Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                            "workflow_id": workflow_id,
                            "step_completed": step_number,
                            "status": if all_required_complete && step_number == steps.len() as u32 { "completed" } else { "in_progress" },
                            "next_step": if step_number < steps.len() as u32 { steps[step_number as usize]["name"].as_str().unwrap() } else { "completed" }
                        })))
                    } else {
                        Err(StatusCode::BAD_REQUEST)
                    }
                } else {
                    Err(StatusCode::NOT_FOUND)
                }
            } else {
                Err(StatusCode::NOT_FOUND)
            }
        }))
        .with_state(state.clone());

    let server = TestServer::new(app).unwrap();

    // Start onboarding workflow
    let onboarding_data = json!({
        "email": "newuser@example.com",
        "first_name": "New",
        "last_name": "User"
    });

    let response = server
        .post("/workflow/onboarding/start")
        .json(&onboarding_data)
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    let workflow_id = body["workflow_id"].as_str().unwrap();
    let user_id = body["user_id"].as_str().unwrap();

    // Complete step 1: email verification
    let step_data = json!({"verification_code": "123456"});
    let response = server
        .post(&format!("/workflow/onboarding/{}/step/1", workflow_id))
        .json(&step_data)
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);

    // Complete step 2: profile setup
    let step_data = json!({"profile_data": {"department": "Engineering", "role": "Developer"}});
    let response = server
        .post(&format!("/workflow/onboarding/{}/step/2", workflow_id))
        .json(&step_data)
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);

    // Complete step 3: security setup
    let step_data =
        json!({"security_settings": {"mfa_enabled": true, "password_strength": "strong"}});
    let response = server
        .post(&format!("/workflow/onboarding/{}/step/3", workflow_id))
        .json(&step_data)
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);

    // Skip optional step 4 and complete step 5: completion
    let step_data = json!({"completion_acknowledgment": true});
    let response = server
        .post(&format!("/workflow/onboarding/{}/step/5", workflow_id))
        .json(&step_data)
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["status"], "completed");
}

#[tokio::test]
async fn test_approval_workflow() {
    let state = WorkflowState::new();

    let app = Router::new()
        .route("/workflow/approval/create", post(move |State(state): State<WorkflowState>, Json(approval_data): Json<serde_json::Value>| async move {
            let mut workflows = state.workflows.lock().await;
            let mut workflow_steps = state.workflow_steps.lock().await;
            let mut approvals = state.approvals.lock().await;
            let mut notifications = state.notifications.lock().await;
            let mut audit_trail = state.audit_trail.lock().await;

            let workflow_id = format!("approval_{}", workflows.len() + 1);
            let requestor_id = approval_data["requestor_id"].as_str().unwrap();
            let approvers: Vec<String> = approval_data["approvers"].as_array().unwrap()
                .iter().map(|a| a.as_str().unwrap().to_string()).collect();

            // Create approval workflow
            workflows.insert(workflow_id.clone(), json!({
                "id": workflow_id,
                "type": "approval",
                "requestor_id": requestor_id,
                "status": "pending",
                "approvers": approvers,
                "approved_count": 0,
                "required_approvals": approvers.len(),
                "created_at": "2024-12-01T11:00:00Z"
            }));

            // Initialize approval steps
            workflow_steps.insert(workflow_id.clone(), vec![
                json!({"step": 1, "name": "collect_approvals", "status": "in_progress", "required": true}),
                json!({"step": 2, "name": "finalize_decision", "status": "pending", "required": true}),
            ]);

            // Initialize approvals tracking
            approvals.insert(workflow_id.clone(), vec![]);

            // Notify approvers
            for approver_id in &approvers {
                notifications.push(json!({
                    "type": "approval_request",
                    "approver_id": approver_id,
                    "workflow_id": workflow_id,
                    "requestor_id": requestor_id,
                    "message": "New approval request requires your review",
                    "timestamp": "2024-12-01T11:00:00Z"
                }));
            }

            audit_trail.push(json!({
                "event": "approval_workflow_created",
                "workflow_id": workflow_id,
                "requestor_id": requestor_id,
                "approvers": approvers,
                "timestamp": "2024-12-01T11:00:00Z"
            }));

            Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                "workflow_id": workflow_id,
                "status": "pending",
                "approvers": approvers,
                "message": "Approval workflow created successfully"
            })))
        }))
        .route("/workflow/approval/{workflow_id}/approve", post(move |State(state): State<WorkflowState>, Path(workflow_id): Path<String>, Json(approval): Json<serde_json::Value>| async move {
            let mut workflows = state.workflows.lock().await;
            let mut approvals = state.approvals.lock().await;
            let mut notifications = state.notifications.lock().await;
            let mut audit_trail = state.audit_trail.lock().await;

            if let Some(workflow) = workflows.get_mut(&workflow_id) {
                if workflow["status"] == "pending" {
                    let approver_id = approval["approver_id"].as_str().unwrap();
                    let decision = approval["decision"].as_str().unwrap();
                    let comments = approval.get("comments").and_then(|c| c.as_str()).unwrap_or("");

                    // Record approval
                    if let Some(approval_list) = approvals.get_mut(&workflow_id) {
                        approval_list.push(json!({
                            "approver_id": approver_id,
                            "decision": decision,
                            "comments": comments,
                            "timestamp": "2024-12-01T11:30:00Z"
                        }));
                    }

                    // Update workflow
                    if decision == "approved" {
                        let current_count = workflow["approved_count"].as_u64().unwrap();
                        workflow["approved_count"] = json!(current_count + 1);
                    }

                    // Check if all approvals received
                    let approved_count = workflow["approved_count"].as_u64().unwrap();
                    let required_count = workflow["required_approvals"].as_u64().unwrap();

                    if approved_count >= required_count {
                        workflow["status"] = json!("approved");

                        // Notify requestor
                        let requestor_id = workflow["requestor_id"].as_str().unwrap();
                        notifications.push(json!({
                            "type": "approval_completed",
                            "user_id": requestor_id,
                            "workflow_id": workflow_id,
                            "message": "Your request has been approved",
                            "timestamp": "2024-12-01T11:30:00Z"
                        }));

                        audit_trail.push(json!({
                            "event": "approval_workflow_completed",
                            "workflow_id": workflow_id,
                            "final_decision": "approved",
                            "timestamp": "2024-12-01T11:30:00Z"
                        }));
                    }

                    audit_trail.push(json!({
                        "event": "approval_submitted",
                        "workflow_id": workflow_id,
                        "approver_id": approver_id,
                        "decision": decision,
                        "timestamp": "2024-12-01T11:30:00Z"
                    }));

                    Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                        "workflow_id": workflow_id,
                        "approver_id": approver_id,
                        "decision": decision,
                        "status": workflow["status"]
                    })))
                } else {
                    Err(StatusCode::CONFLICT)
                }
            } else {
                Err(StatusCode::NOT_FOUND)
            }
        }))
        .with_state(state.clone());

    let server = TestServer::new(app).unwrap();

    // Create approval workflow
    let approval_data = json!({
        "requestor_id": "user_1",
        "approvers": ["user_2", "user_3"],
        "title": "Budget Approval Request",
        "description": "Request for $5000 budget approval",
        "amount": 5000
    });

    let response = server
        .post("/workflow/approval/create")
        .json(&approval_data)
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    let workflow_id = body["workflow_id"].as_str().unwrap();

    // First approver approves
    let approval_data = json!({
        "approver_id": "user_2",
        "decision": "approved",
        "comments": "Approved for Q4 budget"
    });

    let response = server
        .post(&format!("/workflow/approval/{}/approve", workflow_id))
        .json(&approval_data)
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);

    // Second approver approves (should complete the workflow)
    let approval_data = json!({
        "approver_id": "user_3",
        "decision": "approved",
        "comments": "Looks good to me"
    });

    let response = server
        .post(&format!("/workflow/approval/{}/approve", workflow_id))
        .json(&approval_data)
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["status"], "approved");
}

#[tokio::test]
async fn test_password_reset_workflow() {
    let state = WorkflowState::new();

    let app = Router::new()
        .route("/workflow/password-reset/request", post(move |State(state): State<WorkflowState>, Json(reset_data): Json<serde_json::Value>| async move {
            let users = state.users.lock().await;
            let mut workflows = state.workflows.lock().await;
            let mut workflow_steps = state.workflow_steps.lock().await;
            let mut notifications = state.notifications.lock().await;
            let mut audit_trail = state.audit_trail.lock().await;

            let email = reset_data["email"].as_str().unwrap();

            // Find user by email
            let user = users.values().find(|u| u["email"] == email);

            if let Some(user) = user {
                let user_id = user["id"].as_str().unwrap();
                let workflow_id = format!("password_reset_{}", user_id);

                // Create password reset workflow
                workflows.insert(workflow_id.clone(), json!({
                    "id": workflow_id,
                    "user_id": user_id,
                    "type": "password_reset",
                    "status": "pending",
                    "reset_token": format!("reset_token_{}", user_id),
                    "expires_at": "2024-12-01T12:00:00Z",
                    "created_at": "2024-12-01T11:45:00Z"
                }));

                // Initialize workflow steps
                workflow_steps.insert(workflow_id.clone(), vec![
                    json!({"step": 1, "name": "send_reset_email", "status": "completed", "required": true}),
                    json!({"step": 2, "name": "token_validation", "status": "pending", "required": true}),
                    json!({"step": 3, "name": "password_update", "status": "pending", "required": true}),
                    json!({"step": 4, "name": "cleanup", "status": "pending", "required": true}),
                ]);

                // Send reset email notification
                notifications.push(json!({
                    "type": "password_reset_email",
                    "user_id": user_id,
                    "email": email,
                    "reset_token": format!("reset_token_{}", user_id),
                    "message": "Password reset link sent to your email",
                    "timestamp": "2024-12-01T11:45:00Z"
                }));

                audit_trail.push(json!({
                    "event": "password_reset_requested",
                    "user_id": user_id,
                    "email": email,
                    "timestamp": "2024-12-01T11:45:00Z"
                }));

                Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                    "message": "Password reset email sent",
                    "workflow_id": workflow_id,
                    "expires_in": "15 minutes"
                })))
            } else {
                Err(StatusCode::NOT_FOUND)
            }
        }))
        .route("/workflow/password-reset/validate/{token}", post(move |State(state): State<WorkflowState>, Path(token): Path<String>, Json(validation_data): Json<serde_json::Value>| async move {
            let workflows = state.workflows.lock().await;
            let mut workflow_steps = state.workflow_steps.lock().await;
            let mut audit_trail = state.audit_trail.lock().await;

            // Find workflow by token
            let workflow = workflows.values().find(|w| w["reset_token"] == token && w["status"] == "pending");

            if let Some(workflow) = workflow {
                let workflow_id = workflow["id"].as_str().unwrap();
                let user_id = workflow["user_id"].as_str().unwrap();

                // Update workflow step
                if let Some(steps) = workflow_steps.get_mut(workflow_id) {
                    steps[1]["status"] = json!("completed");
                }

                audit_trail.push(json!({
                    "event": "password_reset_token_validated",
                    "user_id": user_id,
                    "workflow_id": workflow_id,
                    "timestamp": "2024-12-01T11:50:00Z"
                }));

                Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                    "valid": true,
                    "workflow_id": workflow_id,
                    "message": "Token validated successfully"
                })))
            } else {
                Err(StatusCode::UNAUTHORIZED)
            }
        }))
        .route("/workflow/password-reset/complete/{workflow_id}", post(move |State(state): State<WorkflowState>, Path(workflow_id): Path<String>, Json(completion_data): Json<serde_json::Value>| async move {
            let mut workflows = state.workflows.lock().await;
            let mut workflow_steps = state.workflow_steps.lock().await;
            let mut users = state.users.lock().await;
            let mut notifications = state.notifications.lock().await;
            let mut audit_trail = state.audit_trail.lock().await;

            if let Some(workflow) = workflows.get_mut(&workflow_id) {
                if workflow["status"] == "pending" {
                    let user_id = workflow["user_id"].as_str().unwrap().to_string();
                    let new_password = completion_data["new_password"].as_str().unwrap();

                    // Update user password (simplified)
                    if let Some(user) = users.get_mut(&user_id) {
                        user["password_updated_at"] = json!("2024-12-01T11:55:00Z");
                    }

                    // Complete workflow steps
                    if let Some(steps) = workflow_steps.get_mut(&workflow_id) {
                        steps[2]["status"] = json!("completed");
                        steps[3]["status"] = json!("completed");
                    }

                    // Mark workflow as completed
                    workflow["status"] = json!("completed");

                    // Send completion notification
                    notifications.push(json!({
                        "type": "password_reset_completed",
                        "user_id": user_id,
                        "message": "Your password has been successfully reset",
                        "timestamp": "2024-12-01T11:55:00Z"
                    }));

                    audit_trail.push(json!({
                        "event": "password_reset_completed",
                        "user_id": user_id,
                        "workflow_id": workflow_id,
                        "timestamp": "2024-12-01T11:55:00Z"
                    }));

                    Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                        "success": true,
                        "message": "Password reset completed successfully"
                    })))
                } else {
                    Err(StatusCode::CONFLICT)
                }
            } else {
                Err(StatusCode::NOT_FOUND)
            }
        }))
        .with_state(state.clone());

    let server = TestServer::new(app).unwrap();

    // First, create a user
    {
        let mut users = state.users.lock().await;
        users.insert(
            "user_1".to_string(),
            json!({
                "id": "user_1",
                "email": "test@example.com",
                "status": "active"
            }),
        );
    }

    // Request password reset
    let reset_data = json!({"email": "test@example.com"});
    let response = server
        .post("/workflow/password-reset/request")
        .json(&reset_data)
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    let workflow_id = body["workflow_id"].as_str().unwrap();

    // Validate reset token
    let response = server
        .post("/workflow/password-reset/validate/reset_token_user_1")
        .json(&json!({}))
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);

    // Complete password reset
    let completion_data = json!({"new_password": "new_secure_password"});
    let response = server
        .post(&format!(
            "/workflow/password-reset/complete/{}",
            workflow_id
        ))
        .json(&completion_data)
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["success"], true);
}

#[tokio::test]
async fn test_role_change_workflow() {
    let state = WorkflowState::new();

    let app = Router::new()
        .route("/workflow/role-change/request", post(move |State(state): State<WorkflowState>, Json(request_data): Json<serde_json::Value>| async move {
            let users = state.users.lock().await;
            let mut workflows = state.workflows.lock().await;
            let mut workflow_steps = state.workflow_steps.lock().await;
            let mut approvals = state.approvals.lock().await;
            let mut notifications = state.notifications.lock().await;
            let mut audit_trail = state.audit_trail.lock().await;

            let user_id = request_data["user_id"].as_str().unwrap();
            let requested_role = request_data["requested_role"].as_str().unwrap();

            // Verify user exists
            if users.contains_key(user_id) {
                let workflow_id = format!("role_change_{}", user_id);

                // Create role change workflow
                workflows.insert(workflow_id.clone(), json!({
                    "id": workflow_id,
                    "user_id": user_id,
                    "type": "role_change",
                    "status": "pending_approval",
                    "current_role": "user",
                    "requested_role": requested_role,
                    "created_at": "2024-12-01T12:00:00Z"
                }));

                // Initialize workflow steps
                workflow_steps.insert(workflow_id.clone(), vec![
                    json!({"step": 1, "name": "manager_approval", "status": "pending", "required": true}),
                    json!({"step": 2, "name": "hr_approval", "status": "pending", "required": true}),
                    json!({"step": 3, "name": "role_assignment", "status": "pending", "required": true}),
                    json!({"step": 4, "name": "notification", "status": "pending", "required": true}),
                ]);

                // Initialize approvals
                approvals.insert(workflow_id.clone(), vec![]);

                // Notify approvers
                notifications.push(json!({
                    "type": "role_change_request",
                    "approver_id": "manager_1",
                    "workflow_id": workflow_id,
                    "user_id": user_id,
                    "requested_role": requested_role,
                    "message": "Role change request requires approval",
                    "timestamp": "2024-12-01T12:00:00Z"
                }));

                audit_trail.push(json!({
                    "event": "role_change_requested",
                    "user_id": user_id,
                    "requested_role": requested_role,
                    "workflow_id": workflow_id,
                    "timestamp": "2024-12-01T12:00:00Z"
                }));

                Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                    "workflow_id": workflow_id,
                    "status": "pending_approval",
                    "message": "Role change request submitted for approval"
                })))
            } else {
                Err(StatusCode::NOT_FOUND)
            }
        }))
        .route("/workflow/role-change/{workflow_id}/approve", post(move |State(state): State<WorkflowState>, Path(workflow_id): Path<String>, Json(approval): Json<serde_json::Value>| async move {
            let mut workflows = state.workflows.lock().await;
            let mut workflow_steps = state.workflow_steps.lock().await;
            let mut approvals = state.approvals.lock().await;
            let mut users = state.users.lock().await;
            let mut notifications = state.notifications.lock().await;
            let mut audit_trail = state.audit_trail.lock().await;

            if let Some(workflow) = workflows.get_mut(&workflow_id) {
                let approver_id = approval["approver_id"].as_str().unwrap();
                let decision = approval["decision"].as_str().unwrap();

                // Record approval
                if let Some(approval_list) = approvals.get_mut(&workflow_id) {
                    approval_list.push(json!({
                        "approver_id": approver_id,
                        "decision": decision,
                        "timestamp": "2024-12-01T12:30:00Z"
                    }));
                }

                if decision == "approved" {
                    // Update workflow steps based on approver type
                    if let Some(steps) = workflow_steps.get_mut(&workflow_id) {
                        if approver_id == "manager_1" {
                            steps[0]["status"] = json!("completed");
                            // Notify HR
                            notifications.push(json!({
                                "type": "hr_approval_request",
                                "approver_id": "hr_1",
                                "workflow_id": workflow_id,
                                "message": "HR approval required for role change",
                                "timestamp": "2024-12-01T12:30:00Z"
                            }));
                        } else if approver_id == "hr_1" {
                            steps[1]["status"] = json!("completed");
                            // Complete role change
                            let user_id = workflow["user_id"].as_str().unwrap().to_string();
                            let new_role = workflow["requested_role"].as_str().unwrap().to_string();

                            if let Some(user) = users.get_mut(&user_id) {
                                user["role"] = json!(new_role);
                            }

                            steps[2]["status"] = json!("completed");
                            steps[3]["status"] = json!("completed");

                            workflow["status"] = json!("completed");

                            // Notify user
                            notifications.push(json!({
                                "type": "role_change_completed",
                                "user_id": user_id,
                                "new_role": new_role,
                                "message": "Your role has been successfully changed",
                                "timestamp": "2024-12-01T12:45:00Z"
                            }));

                            audit_trail.push(json!({
                                "event": "role_change_completed",
                                "user_id": user_id,
                                "new_role": new_role,
                                "workflow_id": workflow_id,
                                "timestamp": "2024-12-01T12:45:00Z"
                            }));
                        }
                    }
                } else {
                    // Request denied
                    workflow["status"] = json!("denied");

                    audit_trail.push(json!({
                        "event": "role_change_denied",
                        "workflow_id": workflow_id,
                        "denied_by": approver_id,
                        "timestamp": "2024-12-01T12:30:00Z"
                    }));
                }

                Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                    "workflow_id": workflow_id,
                    "decision": decision,
                    "status": workflow["status"]
                })))
            } else {
                Err(StatusCode::NOT_FOUND)
            }
        }))
        .with_state(state.clone());

    let server = TestServer::new(app).unwrap();

    // Create a user first
    {
        let mut users = state.users.lock().await;
        users.insert(
            "user_1".to_string(),
            json!({
                "id": "user_1",
                "email": "test@example.com",
                "role": "user",
                "status": "active"
            }),
        );
    }

    // Request role change
    let request_data = json!({
        "user_id": "user_1",
        "requested_role": "admin"
    });

    let response = server
        .post("/workflow/role-change/request")
        .json(&request_data)
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    let workflow_id = body["workflow_id"].as_str().unwrap();

    // Manager approves
    let approval_data = json!({
        "approver_id": "manager_1",
        "decision": "approved"
    });

    let response = server
        .post(&format!("/workflow/role-change/{}/approve", workflow_id))
        .json(&approval_data)
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);

    // HR approves (should complete the workflow)
    let approval_data = json!({
        "approver_id": "hr_1",
        "decision": "approved"
    });

    let response = server
        .post(&format!("/workflow/role-change/{}/approve", workflow_id))
        .json(&approval_data)
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["status"], "completed");
}
