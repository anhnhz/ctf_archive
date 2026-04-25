use log::{info, warn};
use edge_core::prelude::*;
use edge_core::server::Server;
use edge_core::upstreams::peer::HttpPeer;
use edge_http::{RequestHeader, ResponseHeader};
use edge_proxy::{ProxyHttp, Session};
use std::net::IpAddr;

pub struct EdgeProxy;

struct RoutingContext {
    upstream_host: String,
    upstream_port: u16,
    use_tls: bool,
}

impl RoutingContext {
    fn new(host: &str, port: u16) -> Self {
        Self {
            upstream_host: host.to_string(),
            upstream_port: port,
            use_tls: false,
        }
    }
}

fn resolve_route(path: &str) -> RoutingContext {
    if path.starts_with("/api/") || path.starts_with("/api") {
        RoutingContext::new("api-server", 3000)
    } else if path.starts_with("/build/") || path.starts_with("/build") {
        RoutingContext::new("build-runner", 9000)
    } else if path.starts_with("/health/policy-engine") {
        RoutingContext::new("policy-engine", 5000)
    } else if path.starts_with("/internal/") || path.starts_with("/internal") {
        RoutingContext::new("policy-engine", 5000)
    } else {
        RoutingContext::new("api-server", 3000)
    }
}

fn extract_client_ip(session: &Session) -> Option<IpAddr> {
    session
        .client_addr()
        .and_then(|addr| addr.as_inet().map(|sock| sock.ip()))
}

fn is_internal_network(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            octets[0] == 172 && (octets[1] >= 16 && octets[1] <= 31)
        }
        IpAddr::V6(_) => false,
    }
}

#[async_trait::async_trait]
impl ProxyHttp for EdgeProxy {
    type CTX = ();

    fn new_ctx(&self) -> Self::CTX {}

    async fn request_filter(
        &self,
        session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<bool> {
        let path = session.req_header().uri.path().to_string();

        if let Some(upgrade_val) = session.req_header().headers.get("upgrade") {
            if let Ok(val) = upgrade_val.to_str() {
                let val_lower = val.to_lowercase();
                let blocked = ["websocket", "h2c", "h2", "http2-settings", "tls", "ssl"];
                let is_blocked = blocked.iter().any(|p| val_lower.contains(p));
                if is_blocked {
                    warn!("blocked upgrade protocol: {}", val_lower);
                    let mut resp = ResponseHeader::build(403, None)?;
                    resp.insert_header("Content-Type", "application/json")?;
                    resp.insert_header("X-Edge-Policy", "upgrade-restricted")?;
                    session.write_response_header(Box::new(resp), false).await?;
                    session
                        .write_response_body(Some(
                            bytes::Bytes::from(
                                r#"{"error":"upgrade_protocol_not_permitted","policy":"edge-security-v2"}"#,
                            )
                            .into(),
                        ), true)
                        .await?;
                    return Ok(true);
                }
            }
        }

        if path.starts_with("/internal/") || path.starts_with("/internal") {
            warn!("blocked access to internal endpoint: {}", path);
            let mut resp = ResponseHeader::build(403, None)?;
            resp.insert_header("Content-Type", "application/json")?;
            resp.insert_header("X-Edge-Policy", "internal-only")?;
            session.write_response_header(Box::new(resp), false).await?;
            session
                .write_response_body(Some(
                    bytes::Bytes::from(
                        r#"{"error":"forbidden","scope":"internal_network_only"}"#,
                    )
                    .into(),
                ), true)
                .await?;
            return Ok(true);
        }

        Ok(false)
    }

    async fn upstream_peer(
        &self,
        session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        let path = session.req_header().uri.path().to_string();
        let route = resolve_route(&path);

        info!(
            "routing {} -> {}:{}",
            path, route.upstream_host, route.upstream_port
        );

        let peer = Box::new(HttpPeer::new(
            (&*route.upstream_host, route.upstream_port),
            route.use_tls,
            route.upstream_host.clone(),
        ));

        Ok(peer)
    }

    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_request: &mut RequestHeader,
        _ctx: &mut Self::CTX,
    ) -> Result<()> {
        upstream_request.insert_header("X-Forwarded-Proto", "https")?;
        Ok(())
    }

    async fn response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut ResponseHeader,
        _ctx: &mut Self::CTX,
    ) -> Result<()> {
        upstream_response.insert_header("X-Served-By", "edge-proxy")?;
        upstream_response.remove_header("Server");
        upstream_response.insert_header("Server", "dark-harbor-edge")?;
        Ok(())
    }
}

fn main() {
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("info"),
    )
    .init();

    let mut server = Server::new(None).unwrap();
    server.bootstrap();

    let mut proxy = edge_proxy::http_proxy_service(
        &server.configuration,
        EdgeProxy,
    );

    proxy.add_tcp("0.0.0.0:8080");

    info!("edge proxy starting on 0.0.0.0:8080");

    server.add_service(proxy);
    server.run_forever();
}
