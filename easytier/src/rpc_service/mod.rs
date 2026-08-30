pub mod api;
#[cfg(feature = "http-rpc")]
pub mod http;
#[cfg(feature = "management")]
pub mod logger;
#[cfg(feature = "management")]
pub use easytier_core::management::remote_client;

#[cfg(feature = "management")]
pub type ApiRpcServer<T> = self::api::ApiRpcServer<T>;
pub type ReadOnlyApiRpcServer<T> = self::api::ReadOnlyApiRpcServer<T>;
