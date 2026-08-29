use egress_relay::relay_target::{Target, TargetError};

#[test]
fn accepts_public_https_target_and_supported_method() {
    let target = Target::parse("POST", "https://example.com/v1/responses?q=1").unwrap();

    assert_eq!(target.method(), "POST");
    assert_eq!(target.hostname(), "example.com");
    assert_eq!(target.port(), 443);
    assert_eq!(
        target.url().as_str(),
        "https://example.com/v1/responses?q=1"
    );
}

#[test]
fn normalizes_method_case_but_keeps_url_semantics() {
    let target = Target::parse("get", "https://Example.COM/a%2Fb?x=雪").unwrap();
    assert_eq!(target.method(), "GET");
    assert_eq!(target.hostname(), "example.com");
    assert_eq!(target.url().path(), "/a%2Fb");
}

#[test]
fn rejects_non_https_credentials_fragment_and_explicit_port() {
    for url in [
        "http://example.com/",
        "https://user:secret@example.com/",
        "https://@example.com/",
        "https://example.com/#fragment",
        "https://example.com:443/",
        "https://example.com:8443/",
    ] {
        assert!(
            matches!(
                Target::parse("GET", url),
                Err(TargetError::InvalidTarget(_))
            ),
            "must reject {url}"
        );
    }
}

#[test]
fn rejects_ip_literals_and_invalid_hostnames() {
    for url in [
        "https://127.0.0.1/",
        "https://[::1]/",
        "https://example..com/",
        "https://-example.com/",
        "https://example-.com/",
        "https://example.com%2f.evil/",
        "https:///missing-host",
    ] {
        assert!(Target::parse("GET", url).is_err(), "must reject {url}");
    }
}

#[test]
fn rejects_unsupported_methods() {
    for method in ["CONNECT", "TRACE", "PATCHX", "", "GET\n"] {
        assert!(
            matches!(
                Target::parse(method, "https://example.com/"),
                Err(TargetError::UnsupportedMethod(_))
            ),
            "must reject method {method:?}"
        );
    }
}

#[test]
fn rejects_targets_longer_than_the_wire_limit() {
    let url = format!("https://example.com/{}", "a".repeat(4096));

    assert!(matches!(
        Target::parse("GET", &url),
        Err(TargetError::TooLong)
    ));
}

#[test]
fn accepts_a_trailing_dot_but_not_an_empty_hostname() {
    let target = Target::parse("GET", "https://example.com./").unwrap();
    assert_eq!(target.hostname(), "example.com.");
    assert!(Target::parse("GET", "https://./").is_err());
}
