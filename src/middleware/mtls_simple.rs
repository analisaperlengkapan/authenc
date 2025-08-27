// Simple mTLS middleware re-exports
pub use crate::crypto::simple_mtls::{
    SimpleMtlsConfig, 
    ClientCertInfo, 
    simple_mtls_middleware as mtls_middleware
};
