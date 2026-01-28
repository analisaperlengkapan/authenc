use authenc::config::DatabaseConfig;
use authenc::database::Database;
use authenc::database::operations::groups;
use uuid::Uuid;

#[tokio::test]
#[ignore = "Requires PostgreSQL database to be running"]
async fn test_government_hierarchy_structure() {
    // 1. Setup Database Connection
    let database_config = DatabaseConfig {
        host: "localhost".to_string(),
        port: 5432,
        username: "test".to_string(),
        password: "test".to_string(),
        database: "test_db".to_string(),
        max_connections: 5,
        connection_timeout: 30,
        audit_log_url: None,
        connection_timeout_seconds: 30,
    };

    let db = match Database::new(&database_config).await {
        Ok(db) => db,
        Err(_) => {
            println!("Skipping test: Database not available");
            return;
        }
    };

    // 2. Define Realm (e.g., "Kementerian X")
    let realm_id = Uuid::new_v4();
    // In a real scenario, we would create the realm via authenc::database::operations::realms::create_realm
    // For this POC, we just use the ID as groups require it.

    // 3. Create Root Level (Tingkat Pusat)
    let pusat_name = "Pusat";
    let pusat_attrs = serde_json::json!({
        "unit_type": "hq",
        "address": "Jl. Merdeka No. 1"
    });

    let pusat_group = groups::create_group(
        &db,
        realm_id,
        pusat_name,
        None, // No parent
        Some("Kantor Pusat Kementerian"),
        &pusat_attrs,
    )
    .await
    .expect("Failed to create Pusat group");

    assert_eq!(pusat_group.path, "/Pusat");

    // 4. Create Regional Level (Tingkat Wilayah) - Child of Pusat
    let wilayah_name = "Kanwil_Jabar";
    let wilayah_attrs = serde_json::json!({
        "unit_type": "region",
        "region_code": "JB"
    });

    let wilayah_group = groups::create_group(
        &db,
        realm_id,
        wilayah_name,
        Some(pusat_group.id), // Parent is Pusat
        Some("Kantor Wilayah Jawa Barat"),
        &wilayah_attrs,
    )
    .await
    .expect("Failed to create Wilayah group");

    // Verify Hierarchy Path
    assert_eq!(wilayah_group.path, "/Pusat/Kanwil_Jabar");
    assert_eq!(wilayah_group.parent_id, Some(pusat_group.id));

    // 5. Create Work Unit Level (Satuan Kerja) - Child of Wilayah
    let satker_name = "Kanim_Bandung";
    let satker_attrs = serde_json::json!({
        "unit_type": "office",
        "office_code": "BDO-01"
    });

    let satker_group = groups::create_group(
        &db,
        realm_id,
        satker_name,
        Some(wilayah_group.id), // Parent is Wilayah
        Some("Kantor Imigrasi Bandung"),
        &satker_attrs,
    )
    .await
    .expect("Failed to create Satker group");

    // Verify Deep Hierarchy Path
    assert_eq!(satker_group.path, "/Pusat/Kanwil_Jabar/Kanim_Bandung");
    assert_eq!(satker_group.parent_id, Some(wilayah_group.id));

    println!("Hierarchy verification successful!");
    println!("Created structure: {}", satker_group.path);
}
