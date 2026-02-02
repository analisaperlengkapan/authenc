use serde::{Deserialize, Serialize};

/// Cluster communication types
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[derive(Default)]
pub enum ClusterCommunicationType {
    /// Infinispan-based communication
    #[default]
    Infinispan,
    /// JGroups-based communication
    JGroups,
    /// Custom communication implementation
    Custom,
}

/// Cluster membership types
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[derive(Default)]
pub enum ClusterMembershipType {
    /// Kubernetes-based membership
    #[default]
    Kubernetes,
    /// Static membership configuration
    Static,
    /// Multicast-based discovery
    Multicast,
    /// Custom membership implementation
    Custom,
}

/// Cluster consensus types
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[derive(Default)]
pub enum ClusterConsensusType {
    /// Raft consensus algorithm
    #[default]
    Raft,
    /// Paxos consensus algorithm
    Paxos,
    /// Infinispan-based consensus
    Infinispan,
    /// Custom consensus implementation
    Custom,
}
