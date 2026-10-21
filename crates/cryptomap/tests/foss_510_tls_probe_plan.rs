//! FOSS-510 B6.1: no-network exact-grant TLS probe planning.
#![cfg(feature = "tls-probe")]
#![allow(clippy::unwrap_used, clippy::expect_used)]
use cryptomap::{
    CollectionScopeId,
    collector::RequestedSource,
    collectors::tls::probe::{TlsProbeLimits, TlsProbePlan, TlsProbePlanError},
    network_scope::NetworkTarget,
    raw::RawSourceKind,
    scope::CollectionScope,
};
use std::{
    io::ErrorKind,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener},
    time::Duration,
};

fn scope() -> CollectionScope {
    CollectionScope::new(CollectionScopeId::new("b61-test-scope").unwrap())
}

fn requested(item: &str) -> RequestedSource {
    RequestedSource {
        kind: RawSourceKind::TlsEndpoint,
        item: item.to_owned(),
    }
}

#[test]
fn finite_plan_uses_only_host_pinned_ips_port_and_explicit_sni() {
    let mut scope = scope();
    let a = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    let b = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));
    scope
        .grant_endpoint(
            NetworkTarget::new("EXAMPLE.ORG", 9443, Some("SNI.Example.Org"), [b, a]).unwrap(),
        )
        .unwrap();
    let limits = TlsProbeLimits {
        max_attempts: 2,
        ..TlsProbeLimits::default()
    };
    let plan = TlsProbePlan::prepare(&scope, &requested("example.org:9443"), limits).unwrap();
    assert_eq!(plan.target_id(), "example.org:9443");
    assert_eq!(plan.sni(), Some("sni.example.org"));
    assert_eq!(plan.limits(), limits);
    assert_eq!(
        plan.destinations(),
        &[SocketAddr::new(a, 9443), SocketAddr::new(b, 9443)]
    );
    assert!(plan.includes(SocketAddr::new(a, 9443)));
    assert!(!plan.includes(SocketAddr::new(a, 9444)));
    assert!(!plan.includes(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443)));
    assert!(!plan.includes(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        9443
    )));
    let single = TlsProbePlan::prepare(
        &scope,
        &requested("example.org:9443"),
        TlsProbeLimits::default(),
    )
    .unwrap();
    assert_eq!(single.destinations(), &[SocketAddr::new(a, 9443)]);
    assert!(!single.includes(SocketAddr::new(b, 9443)));
}

#[test]
fn missing_wrong_kind_or_ungranted_endpoint_is_rejected() {
    let mut scope = scope();
    scope
        .grant_endpoint(NetworkTarget::new("127.0.0.1", 443, None, []).unwrap())
        .unwrap();
    for item in [
        "127.0.0.2:443",
        "127.0.0.1:444",
        "EXAMPLE.ORG:443",
        "",
        "127.0.0.1:443 ",
    ] {
        assert!(matches!(
            TlsProbePlan::prepare(&scope, &requested(item), TlsProbeLimits::default()),
            Err(TlsProbePlanError::Unauthorized)
        ));
    }
    let bad = RequestedSource {
        kind: RawSourceKind::Dependency,
        item: "127.0.0.1:443".into(),
    };
    assert!(matches!(
        TlsProbePlan::prepare(&scope, &bad, TlsProbeLimits::default()),
        Err(TlsProbePlanError::Unauthorized)
    ));
}

#[test]
fn no_ambient_dns_no_sni_fallback_and_ipv6_bracketing() {
    let mut scope = scope();
    scope
        .grant_endpoint(
            NetworkTarget::new("hostname.example", 443, None, [Ipv4Addr::LOCALHOST.into()])
                .unwrap(),
        )
        .unwrap();
    scope
        .grant_endpoint(NetworkTarget::new("::1", 8443, None, []).unwrap())
        .unwrap();
    let name = TlsProbePlan::prepare(
        &scope,
        &requested("hostname.example:443"),
        TlsProbeLimits::default(),
    )
    .unwrap();
    assert_eq!(name.sni(), None);
    assert_eq!(
        name.destinations(),
        &[SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443)]
    );
    let ipv6 =
        TlsProbePlan::prepare(&scope, &requested("[::1]:8443"), TlsProbeLimits::default()).unwrap();
    assert_eq!(ipv6.target_id(), "[::1]:8443");
    assert_eq!(ipv6.sni(), None);
    assert_eq!(
        ipv6.destinations(),
        &[SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 8443)]
    );
}

#[test]
fn budgets_reject_zero_oversized_and_inconsistent_values() {
    let base = TlsProbeLimits::default();
    assert!(base.validate().is_ok());
    for limit in [
        TlsProbeLimits {
            connect_timeout: Duration::ZERO,
            ..base
        },
        TlsProbeLimits {
            connect_timeout: Duration::from_secs(31),
            ..base
        },
        TlsProbeLimits {
            handshake_timeout: Duration::ZERO,
            ..base
        },
        TlsProbeLimits {
            handshake_timeout: Duration::from_secs(31),
            ..base
        },
        TlsProbeLimits {
            max_handshake_bytes: 0,
            ..base
        },
        TlsProbeLimits {
            max_handshake_bytes: usize::MAX,
            ..base
        },
        TlsProbeLimits {
            max_chain_der_bytes: 0,
            ..base
        },
        TlsProbeLimits {
            max_chain_der_bytes: usize::MAX,
            ..base
        },
        TlsProbeLimits {
            max_chain_der_bytes: base.max_handshake_bytes + 1,
            ..base
        },
        TlsProbeLimits {
            max_certificates: 0,
            ..base
        },
        TlsProbeLimits {
            max_certificates: 17,
            ..base
        },
        TlsProbeLimits {
            max_attempts: 0,
            ..base
        },
        TlsProbeLimits {
            max_attempts: 33,
            ..base
        },
    ] {
        assert_eq!(limit.validate(), Err(TlsProbePlanError::InvalidLimits));
    }
    let mut scope = scope();
    scope
        .grant_endpoint(NetworkTarget::new("127.0.0.1", 443, None, []).unwrap())
        .unwrap();
    assert!(matches!(
        TlsProbePlan::prepare(
            &scope,
            &requested("127.0.0.1:443"),
            TlsProbeLimits {
                max_attempts: 0,
                ..base
            },
        ),
        Err(TlsProbePlanError::InvalidLimits)
    ));
}

#[test]
fn preparing_plan_does_not_connect_even_when_loopback_listener_exists() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    let mut scope = scope();
    scope
        .grant_endpoint(NetworkTarget::new("127.0.0.1", port, None, []).unwrap())
        .unwrap();
    let plan = TlsProbePlan::prepare(
        &scope,
        &requested(&format!("127.0.0.1:{port}")),
        TlsProbeLimits::default(),
    )
    .unwrap();
    assert_eq!(plan.destinations().len(), 1);
    assert_eq!(listener.accept().unwrap_err().kind(), ErrorKind::WouldBlock);
}
