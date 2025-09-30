//! Tests for Delegated Administration Framework

use authenc::services::delegated_admin::{
    DefaultDelegatedAdminService, DelegatedAdminPermission, DelegatedAdminRole,
    DelegatedAdminService,
};
use uuid::Uuid;

#[tokio::test]
async fn test_delegated_admin_role_creation() {
    let service = DefaultDelegatedAdminService::new();
    let realm_id = Uuid::new_v4();

    let role = DelegatedAdminRole {
        id: Uuid::new_v4(),
        name: "Realm Admin".to_string(),
        description: "Full administrative access to realm".to_string(),
        realm_id,
        permissions: [
            DelegatedAdminPermission::ManageUsers,
            DelegatedAdminPermission::ManageRoles,
            DelegatedAdminPermission::ManageClients,
        ]
        .into(),
        composite: false,
        composites: vec![],
    };

    let role_id = service.create_role(role.clone()).await.unwrap();
    assert_eq!(role_id, role.id);

    let roles = service.get_realm_roles(&realm_id).await.unwrap();
    assert_eq!(roles.len(), 1);
    assert_eq!(roles[0].name, "Realm Admin");
}

#[tokio::test]
async fn test_delegated_admin_permission_check() {
    let service = DefaultDelegatedAdminService::new();
    let realm_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();

    // Create a role with user management permissions
    let role = DelegatedAdminRole {
        id: Uuid::new_v4(),
        name: "User Manager".to_string(),
        description: "Can manage users".to_string(),
        realm_id,
        permissions: [DelegatedAdminPermission::ManageUsers].into(),
        composite: false,
        composites: vec![],
    };

    service.create_role(role.clone()).await.unwrap();

    // Initially user should not have permission
    let has_permission = service
        .has_permission(&user_id, &realm_id, &DelegatedAdminPermission::ManageUsers)
        .await
        .unwrap();
    assert!(!has_permission);

    // Assign role to user
    service
        .assign_role(&user_id, &realm_id, &role.id)
        .await
        .unwrap();

    // Now user should have permission
    let has_permission = service
        .has_permission(&user_id, &realm_id, &DelegatedAdminPermission::ManageUsers)
        .await
        .unwrap();
    assert!(has_permission);

    // User should not have other permissions
    let has_other_permission = service
        .has_permission(
            &user_id,
            &realm_id,
            &DelegatedAdminPermission::ManageClients,
        )
        .await
        .unwrap();
    assert!(!has_other_permission);
}

#[tokio::test]
async fn test_delegated_admin_role_revocation() {
    let service = DefaultDelegatedAdminService::new();
    let realm_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();

    // Create a role
    let role = DelegatedAdminRole {
        id: Uuid::new_v4(),
        name: "Test Role".to_string(),
        description: "Test role".to_string(),
        realm_id,
        permissions: [DelegatedAdminPermission::ManageUsers].into(),
        composite: false,
        composites: vec![],
    };

    service.create_role(role.clone()).await.unwrap();
    service
        .assign_role(&user_id, &realm_id, &role.id)
        .await
        .unwrap();

    // User should have permission
    let has_permission = service
        .has_permission(&user_id, &realm_id, &DelegatedAdminPermission::ManageUsers)
        .await
        .unwrap();
    assert!(has_permission);

    // Revoke role
    service
        .revoke_role(&user_id, &realm_id, &role.id)
        .await
        .unwrap();

    // User should no longer have permission
    let has_permission = service
        .has_permission(&user_id, &realm_id, &DelegatedAdminPermission::ManageUsers)
        .await
        .unwrap();
    assert!(!has_permission);
}

#[tokio::test]
async fn test_delegated_admin_composite_roles() {
    let service = DefaultDelegatedAdminService::new();
    let realm_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();

    // Create base roles
    let user_manager = DelegatedAdminRole {
        id: Uuid::new_v4(),
        name: "User Manager".to_string(),
        description: "Can manage users".to_string(),
        realm_id,
        permissions: [DelegatedAdminPermission::ManageUsers].into(),
        composite: false,
        composites: vec![],
    };

    let client_manager = DelegatedAdminRole {
        id: Uuid::new_v4(),
        name: "Client Manager".to_string(),
        description: "Can manage clients".to_string(),
        realm_id,
        permissions: [DelegatedAdminPermission::ManageClients].into(),
        composite: false,
        composites: vec![],
    };

    // Create composite role
    let full_admin = DelegatedAdminRole {
        id: Uuid::new_v4(),
        name: "Full Admin".to_string(),
        description: "Full administrative access".to_string(),
        realm_id,
        permissions: [DelegatedAdminPermission::ManageRealm].into(),
        composite: true,
        composites: vec![user_manager.id, client_manager.id],
    };

    service.create_role(user_manager).await.unwrap();
    service.create_role(client_manager).await.unwrap();
    service.create_role(full_admin.clone()).await.unwrap();

    // Assign composite role to user
    service
        .assign_role(&user_id, &realm_id, &full_admin.id)
        .await
        .unwrap();

    // User should have all permissions
    let permissions = service
        .get_user_permissions(&user_id, &realm_id)
        .await
        .unwrap();
    assert!(permissions.contains(&DelegatedAdminPermission::ManageUsers));
    assert!(permissions.contains(&DelegatedAdminPermission::ManageClients));
    assert!(permissions.contains(&DelegatedAdminPermission::ManageRealm));
}

#[tokio::test]
async fn test_delegated_admin_realm_isolation() {
    let service = DefaultDelegatedAdminService::new();
    let realm1_id = Uuid::new_v4();
    let realm2_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();

    // Create role in realm1
    let role = DelegatedAdminRole {
        id: Uuid::new_v4(),
        name: "Realm1 Admin".to_string(),
        description: "Admin for realm1".to_string(),
        realm_id: realm1_id,
        permissions: [DelegatedAdminPermission::ManageUsers].into(),
        composite: false,
        composites: vec![],
    };

    service.create_role(role.clone()).await.unwrap();
    service
        .assign_role(&user_id, &realm1_id, &role.id)
        .await
        .unwrap();

    // User should have permission in realm1
    let has_permission_realm1 = service
        .has_permission(&user_id, &realm1_id, &DelegatedAdminPermission::ManageUsers)
        .await
        .unwrap();
    assert!(has_permission_realm1);

    // User should not have permission in realm2
    let has_permission_realm2 = service
        .has_permission(&user_id, &realm2_id, &DelegatedAdminPermission::ManageUsers)
        .await
        .unwrap();
    assert!(!has_permission_realm2);
}
