//! Shared DNS primitives for Cole's DNS Tools.

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub mod edns;
pub mod error;
pub mod name;
pub mod query;
pub mod response;
pub mod reverse;
pub mod transport;

pub use edns::{EdnsMeta, ExtendedDnsError};
pub use error::{DnsCoreError, Result};
pub use name::DomainName;
pub use query::{QueryOptions, build_query, parse_record_type, record_type_name};
pub use response::{DnsRecord, DnsResponse, QueryResult, Transport};
pub use reverse::{ip_to_ptr_name, parse_reverse_target};
pub use transport::exchange;
