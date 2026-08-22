use url::{Host, Url};

pub const MAX_TARGET_BYTES: usize = 4096;

const SUPPORTED_METHODS: &[&str] = &["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetError {
    TooLong,
    InvalidTarget(&'static str),
    UnsupportedMethod(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    method: String,
    url: Url,
    hostname: String,
}

impl Target {
    pub fn parse(method: &str, raw_url: &str) -> Result<Self, TargetError> {
        if raw_url.len() > MAX_TARGET_BYTES {
            return Err(TargetError::TooLong);
        }

        let normalized_method = method.to_ascii_uppercase();
        if !SUPPORTED_METHODS.contains(&normalized_method.as_str()) {
            return Err(TargetError::UnsupportedMethod(method.to_owned()));
        }

        if !has_non_empty_authority(raw_url) {
            return Err(TargetError::InvalidTarget("hostname"));
        }

        let url = Url::parse(raw_url).map_err(|_| TargetError::InvalidTarget("url"))?;
        if url.scheme() != "https" {
            return Err(TargetError::InvalidTarget("scheme"));
        }
        if url.fragment().is_some() {
            return Err(TargetError::InvalidTarget("fragment"));
        }
        if url.port().is_some() || has_explicit_port(raw_url) {
            return Err(TargetError::InvalidTarget("port"));
        }
        if has_userinfo(raw_url) || !url.username().is_empty() || url.password().is_some() {
            return Err(TargetError::InvalidTarget("userinfo"));
        }

        let hostname = match url.host() {
            Some(Host::Domain(hostname)) => hostname.to_ascii_lowercase(),
            Some(Host::Ipv4(_)) | Some(Host::Ipv6(_)) => {
                return Err(TargetError::InvalidTarget("ip_literal"));
            }
            None => return Err(TargetError::InvalidTarget("hostname")),
        };
        validate_hostname(&hostname)?;

        Ok(Self {
            method: normalized_method,
            url,
            hostname,
        })
    }

    pub fn method(&self) -> &str {
        &self.method
    }

    pub fn hostname(&self) -> &str {
        &self.hostname
    }

    pub const fn port(&self) -> u16 {
        443
    }

    pub fn url(&self) -> &Url {
        &self.url
    }
}

fn has_userinfo(raw_url: &str) -> bool {
    let Some(authority_and_rest) = raw_url.split_once("://").map(|(_, rest)| rest) else {
        return false;
    };
    let authority_end = authority_and_rest
        .find(['/', '?', '#'])
        .unwrap_or(authority_and_rest.len());
    authority_and_rest[..authority_end].contains('@')
}

fn authority(raw_url: &str) -> Option<&str> {
    let (_, authority_and_rest) = raw_url.split_once("://")?;
    let authority_end = authority_and_rest
        .find(['/', '?', '#'])
        .unwrap_or(authority_and_rest.len());
    Some(&authority_and_rest[..authority_end])
}

fn has_non_empty_authority(raw_url: &str) -> bool {
    authority(raw_url)
        .map(|value| !value.is_empty() && !value.starts_with('/'))
        .unwrap_or(false)
}

fn has_explicit_port(raw_url: &str) -> bool {
    let Some(authority) = authority(raw_url) else {
        return false;
    };
    let authority = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    if authority.starts_with('[') {
        return authority
            .find(']')
            .is_some_and(|end| authority[end + 1..].starts_with(':'));
    }
    authority.contains(':')
}

fn validate_hostname(hostname: &str) -> Result<(), TargetError> {
    if hostname.is_empty() || hostname.len() > 253 {
        return Err(TargetError::InvalidTarget("hostname"));
    }

    let without_trailing_dot = hostname.strip_suffix('.').unwrap_or(hostname);
    if without_trailing_dot.is_empty() || without_trailing_dot.contains("..") {
        return Err(TargetError::InvalidTarget("hostname"));
    }

    for label in without_trailing_dot.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(TargetError::InvalidTarget("hostname_label"));
        }
        if !label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(TargetError::InvalidTarget("hostname_label"));
        }
        if !label.as_bytes()[0].is_ascii_alphanumeric()
            || !label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
        {
            return Err(TargetError::InvalidTarget("hostname_label"));
        }
    }

    Ok(())
}
