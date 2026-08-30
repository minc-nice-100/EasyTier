//! HTTP JSON-RPC control endpoint for the local management plane.
//!
//! The daemon exposes its management RPC over EasyTier tunnel transports
//! (TCP/UDP/WebSocket). This module adds an optional plain-HTTP control portal
//! so management clients, scripts, and the web console can drive the daemon
//! over standard HTTP POST requests instead of the custom binary tunnel
//! protocol.
//!
//! The endpoint is deliberately a thin bridge: each request is dispatched
//! through a local ring tunnel to the same `ServiceRegistry` that the tunnel
//! RPC portal uses, reusing every existing management service and its
//! JSON/protobuf conversions. It is opt-in (`--http-rpc-portal`) and defaults to
//! binding the loopback address so no management surface is exposed remotely by
//! accident.

use std::{net::SocketAddr, sync::Arc};

use http_body_util::{BodyExt, Full};
use hyper::{
    Method, Request, Response, StatusCode, body::{Bytes, Incoming},
    server::conn::http1,
    service::service_fn,
};
use serde::Deserialize;

use crate::proto::rpc_types::controller::BaseController;
use easytier_core::{
    rpc::{bidirect::BidirectRpcManager, service_registry::ServiceRegistry},
    tunnel::ring::create_ring_tunnel_pair,
};

#[derive(Debug, Deserialize)]
pub struct ProxyRpcRequest {
    pub service_name: String,
    pub method_name: String,
    pub payload: serde_json::Value,
    pub scope: Option<String>,
}

macro_rules! match_service {
    ($rpc:expr, $factory:ty, $method_name:expr, $payload:expr, $scope:expr) => {{
        let client = if let Some(domain) = $scope {
            $rpc.scoped_client::<$factory>(1, 1, domain.clone())
        } else {
            $rpc.scoped_client::<$factory>(1, 1, String::new())
        };
        client
            .json_call_method(BaseController::default(), $method_name, $payload)
            .await
    }};
}

/// Dispatches a JSON-RPC request against the local service registry.
async fn dispatch_rpc(
    registry: Arc<ServiceRegistry>,
    req: ProxyRpcRequest,
) -> anyhow::Result<serde_json::Value> {
    let ProxyRpcRequest {
        service_name,
        method_name,
        payload,
        scope,
    } = req;

    // Bridge the request into the management service registry through a local
    // ring tunnel, exactly like a management client over a tunnel transport.
    let (client_tunnel, server_tunnel) = create_ring_tunnel_pair();
    let server = BidirectRpcManager::new();
    server.rpc_server().registry().replace_registry(&registry);
    server.run_with_tunnel(server_tunnel);
    let client = BidirectRpcManager::new();
    client.run_with_tunnel(client_tunnel);
    let rpc = client.rpc_client();

    let resp = match service_name.as_str() {
        "api.manage.WebClientService" => match_service!(
            rpc,
            crate::proto::api::manage::WebClientServiceClientFactory<BaseController>,
            &method_name,
            payload,
            scope.as_ref()
        ),
        "api.instance.PeerManageRpcService" => match_service!(
            rpc,
            crate::proto::api::instance::PeerManageRpcClientFactory<BaseController>,
            &method_name,
            payload,
            scope.as_ref()
        ),
        "api.instance.PeerCenterManageRpcService" => match_service!(
            rpc,
            crate::proto::peer_rpc::PeerCenterRpcClientFactory<BaseController>,
            &method_name,
            payload,
            scope.as_ref()
        ),
        "api.instance.ConnectorManageRpcService" => match_service!(
            rpc,
            crate::proto::api::instance::ConnectorManageRpcClientFactory<BaseController>,
            &method_name,
            payload,
            scope.as_ref()
        ),
        "api.instance.MappedListenerManageRpcService" => match_service!(
            rpc,
            crate::proto::api::instance::MappedListenerManageRpcClientFactory<BaseController>,
            &method_name,
            payload,
            scope.as_ref()
        ),
        "api.instance.VpnPortalRpcService" => match_service!(
            rpc,
            crate::proto::api::instance::VpnPortalRpcClientFactory<BaseController>,
            &method_name,
            payload,
            scope.as_ref()
        ),
        "api.instance.TcpProxyRpcService" => match_service!(
            rpc,
            crate::proto::api::instance::TcpProxyRpcClientFactory<BaseController>,
            &method_name,
            payload,
            scope.as_ref()
        ),
        "api.instance.AclManageRpcService" => match_service!(
            rpc,
            crate::proto::api::instance::AclManageRpcClientFactory<BaseController>,
            &method_name,
            payload,
            scope.as_ref()
        ),
        "api.instance.PortForwardManageRpcService" => match_service!(
            rpc,
            crate::proto::api::instance::PortForwardManageRpcClientFactory<BaseController>,
            &method_name,
            payload,
            scope.as_ref()
        ),
        "api.instance.StatsRpcService" => match_service!(
            rpc,
            crate::proto::api::instance::StatsRpcClientFactory<BaseController>,
            &method_name,
            payload,
            scope.as_ref()
        ),
        "api.instance.CredentialManageRpcService" => match_service!(
            rpc,
            crate::proto::api::instance::CredentialManageRpcClientFactory<BaseController>,
            &method_name,
            payload,
            scope.as_ref()
        ),
        "api.logger.LoggerRpcService" => match_service!(
            rpc,
            crate::proto::api::logger::LoggerRpcClientFactory<BaseController>,
            &method_name,
            payload,
            scope.as_ref()
        ),
        "api.config.ConfigRpcService" => match_service!(
            rpc,
            crate::proto::api::config::ConfigRpcClientFactory<BaseController>,
            &method_name,
            payload,
            scope.as_ref()
        ),
        other => anyhow::bail!("unknown service: {other}"),
    };
    let resp = resp.map_err(|e| anyhow::anyhow!("RPC error: {e:?}"))?;
    Ok(resp)
}

async fn handle(
    req: Request<Incoming>,
    registry: Arc<ServiceRegistry>,
) -> Response<Full<Bytes>> {
    if req.method() != Method::POST || req.uri().path() != "/rpc" {
        return response_json(StatusCode::NOT_FOUND, "{\"error\":\"not found\"}");
    }

    let body = match req.collect().await {
        Ok(body) => body.to_bytes(),
        Err(e) => {
            return response_json(
                StatusCode::BAD_REQUEST,
                &format!("{{\"error\":\"failed to read body: {e}\"}}"),
            );
        }
    };
    let request: ProxyRpcRequest = match serde_json::from_slice(&body) {
        Ok(req) => req,
        Err(e) => {
            return response_json(
                StatusCode::BAD_REQUEST,
                &format!("{{\"error\":\"invalid request: {e}\"}}"),
            );
        }
    };

    match dispatch_rpc(registry, request).await {
        Ok(value) => response_json(StatusCode::OK, &value.to_string()),
        Err(e) => {
            tracing::warn!(?e, "HTTP RPC dispatch failed");
            response_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("{{\"error\":\"{e}\"}}"),
            )
        }
    }
}

fn response_json(status: StatusCode, body: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body.to_owned())))
        .expect("static response should build")
}

/// Serves the HTTP JSON-RPC control portal on `addr` until cancelled.
pub async fn serve(addr: SocketAddr, registry: Arc<ServiceRegistry>) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let actual = listener.local_addr()?;
    tracing::info!(%actual, "HTTP RPC portal listening");

    loop {
        let (stream, peer) = listener.accept().await?;
        let registry = registry.clone();
        tokio::spawn(async move {
            let service = service_fn(move |req| {
                let registry = registry.clone();
                async move {
                    Ok::<_, std::convert::Infallible>(handle(req, registry).await)
                }
            });
            if let Err(e) = http1::Builder::new().serve_connection(stream, service).await {
                tracing::debug!(?peer, ?e, "HTTP RPC connection closed");
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use crate::proto::{
        peer_rpc::{
            GetGlobalPeerMapRequest, GetGlobalPeerMapResponse, PeerCenterRpc,
            PeerCenterRpcServer, ReportPeersRequest, ReportPeersResponse,
        },
        rpc_types::error,
    };

    struct TestPeerCenter;

    #[async_trait]
    impl PeerCenterRpc for TestPeerCenter {
        type Controller = BaseController;

        async fn report_peers(
            &self,
            _controller: BaseController,
            _request: ReportPeersRequest,
        ) -> error::Result<ReportPeersResponse> {
            Ok(ReportPeersResponse::default())
        }

        async fn get_global_peer_map(
            &self,
            _controller: BaseController,
            _request: GetGlobalPeerMapRequest,
        ) -> error::Result<GetGlobalPeerMapResponse> {
            Ok(GetGlobalPeerMapResponse::default())
        }
    }

    #[tokio::test]
    async fn dispatch_rpc_reaches_a_registered_service() {
        let registry = Arc::new(ServiceRegistry::new());
        registry.register(PeerCenterRpcServer::new(TestPeerCenter), "");

        let result = dispatch_rpc(
            registry,
            ProxyRpcRequest {
                service_name: "api.instance.PeerCenterManageRpcService".to_owned(),
                method_name: "get_global_peer_map".to_owned(),
                payload: serde_json::json!({}),
                scope: None,
            },
        )
        .await;

        assert!(result.is_ok(), "dispatch failed: {result:?}");
    }

    #[tokio::test]
    async fn dispatch_rpc_rejects_unknown_service() {
        let registry = Arc::new(ServiceRegistry::new());
        let result = dispatch_rpc(
            registry,
            ProxyRpcRequest {
                service_name: "api.instance.NoSuchService".to_owned(),
                method_name: "any".to_owned(),
                payload: serde_json::json!({}),
                scope: None,
            },
        )
        .await;

        assert!(result.is_err());
    }
}
