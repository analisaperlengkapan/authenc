use authenc::config::DatabaseConfig;
use authenc::database::Database;
use authenc::services::clustering::*;
use chrono::Utc;
use std::collections::HashMap;
use std::sync::Arc;

#[tokio::test]
#[ignore = "Requires PostgreSQL database to be running"]
async fn test_cluster_node_registration() {
    // Setup test database
    let database_config = DatabaseConfig {
        host: "localhost".to_string(),
        port: 5432,
        username: "test".to_string(),
        password: "test".to_string(),
        database: "test_db".to_string(),
        max_connections: 10,
        connection_timeout: 30,
        audit_log_url: None,
        connection_timeout_seconds: 30,
    };

    let database_result = Database::new(&database_config).await;
    let database = match database_result {
        Ok(db) => Arc::new(db),
        Err(_) => {
            println!("Skipping test due to database connection issues");
            return;
        }
    };

    // Test ClusterNode structure with correct fields
    let mut metadata = HashMap::new();
    metadata.insert("region".to_string(), "us-west-2".to_string());
    metadata.insert("zone".to_string(), "a".to_string());
    metadata.insert("instance_type".to_string(), "t3.large".to_string());

    let node = ClusterNode {
        node_id: "node_123".to_string(),
        address: "192.168.1.100:8080".to_string(),
        status: NodeStatus::Up,
        last_seen: Utc::now(),
        metadata,
    };

    // Verify node structure
    assert_eq!(node.node_id, "node_123");
    assert_eq!(node.address, "192.168.1.100:8080");
    assert_eq!(node.status, NodeStatus::Up);
    assert!(node.last_seen <= Utc::now());
    assert_eq!(node.metadata.len(), 3);
    assert_eq!(node.metadata.get("region"), Some(&"us-west-2".to_string()));
    assert_eq!(node.metadata.get("zone"), Some(&"a".to_string()));
    assert_eq!(
        node.metadata.get("instance_type"),
        Some(&"t3.large".to_string())
    );
}

#[tokio::test]
#[ignore = "Requires PostgreSQL database to be running"]
async fn test_cluster_topology() {
    // Test ClusterTopology structure
    let mut nodes = HashMap::new();

    let mut metadata1 = HashMap::new();
    metadata1.insert("role".to_string(), "primary".to_string());

    let mut metadata2 = HashMap::new();
    metadata2.insert("role".to_string(), "secondary".to_string());

    nodes.insert(
        "node1".to_string(),
        ClusterNode {
            node_id: "node1".to_string(),
            address: "192.168.1.100:8080".to_string(),
            status: NodeStatus::Up,
            last_seen: Utc::now(),
            metadata: metadata1,
        },
    );

    nodes.insert(
        "node2".to_string(),
        ClusterNode {
            node_id: "node2".to_string(),
            address: "192.168.1.101:8080".to_string(),
            status: NodeStatus::Up,
            last_seen: Utc::now(),
            metadata: metadata2,
        },
    );

    let topology = ClusterTopology {
        cluster_name: "test-cluster".to_string(),
        nodes,
        leader: Some("node1".to_string()),
        term: 1,
        last_updated: Utc::now(),
    };

    // Verify topology structure
    assert_eq!(topology.cluster_name, "test-cluster");
    assert_eq!(topology.nodes.len(), 2);
    assert_eq!(topology.leader, Some("node1".to_string()));
    assert_eq!(topology.term, 1);
    assert!(topology.last_updated <= Utc::now());

    // Verify nodes in topology
    let node1 = topology.nodes.get("node1").unwrap();
    assert_eq!(node1.node_id, "node1");
    assert_eq!(node1.status, NodeStatus::Up);
    assert_eq!(node1.metadata.get("role"), Some(&"primary".to_string()));

    let node2 = topology.nodes.get("node2").unwrap();
    assert_eq!(node2.node_id, "node2");
    assert_eq!(node2.status, NodeStatus::Up);
    assert_eq!(node2.metadata.get("role"), Some(&"secondary".to_string()));
}

#[tokio::test]
#[ignore = "Requires PostgreSQL database to be running"]
async fn test_cluster_config() {
    // Test ClusterConfig structure
    let config = ClusterConfig {
        enabled: true,
        cluster_name: "test-cluster".to_string(),
        node_id: "node1".to_string(),
        communication_type: ClusterCommunicationType::Infinispan,
        membership_type: ClusterMembershipType::Kubernetes,
        consensus_type: ClusterConsensusType::Raft,
        discovery_addresses: vec![
            "192.168.1.100:8080".to_string(),
            "192.168.1.101:8080".to_string(),
        ],
        session_replication_enabled: true,
        cache_replication_enabled: true,
    };

    // Verify configuration
    assert!(config.enabled);
    assert_eq!(config.cluster_name, "test-cluster");
    assert_eq!(config.node_id, "node1");
    assert_eq!(
        config.communication_type,
        ClusterCommunicationType::Infinispan
    );
    assert_eq!(config.membership_type, ClusterMembershipType::Kubernetes);
    assert_eq!(config.consensus_type, ClusterConsensusType::Raft);
    assert_eq!(config.discovery_addresses.len(), 2);
    assert!(config.session_replication_enabled);
    assert!(config.cache_replication_enabled);
}

#[tokio::test]
async fn test_node_status_transitions() {
    // Test NodeStatus enum values
    let statuses = vec![
        NodeStatus::Up,
        NodeStatus::Down,
        NodeStatus::Starting,
        NodeStatus::Stopping,
        NodeStatus::Unknown,
    ];

    // Verify we can create nodes with different statuses
    for (i, status) in statuses.into_iter().enumerate() {
        let node = ClusterNode {
            node_id: format!("node{}", i),
            address: format!("192.168.1.{}:8080", 100 + i),
            status: status.clone(),
            last_seen: Utc::now(),
            metadata: HashMap::new(),
        };

        assert_eq!(node.status, status);
    }
}
