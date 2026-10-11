//! The env vars that point a cage's tools at its egress CA.
//!
//! Every HTTPS connection the egress intercepts is re-signed by the
//! cage's own CA, whose public certificate the cage sees at
//! [`CERT_PATH`]. A tool trusts it only if something tells it to: on
//! the container and vm backends the CA is not in the image's system
//! trust store. So the cage gets every CA-bundle env var the common
//! agent toolchains read, all pointing at that one file.
//!
//! Most of these *replace* the tool's default roots rather than add to
//! them, so a tool trusts the cage CA and nothing else. That is the
//! trade-off `SSL_CERT_FILE` has always made, and it holds because all
//! intercepted traffic is signed by that CA. A `container.env` entry
//! naming one of these vars wins: the default is left out, never
//! rendered beside the user's value.

/// Where the cage sees the egress's public CA certificate: the
/// `<name>-public-certs` volume, mounted read-only at `/certs`.
pub const CERT_PATH: &str = "/certs/agentcage-ca.pem";

/// Every env var the cage gets pointing at [`CERT_PATH`], in the order
/// the cage unit sets them.
///
/// Each one was checked against the tool that reads it, which ignores
/// `SSL_CERT_FILE` in at least one common build:
///
/// | Var | Read by |
/// | :-- | :-- |
/// | `NODE_EXTRA_CA_CERTS` | Node (so npm, pnpm, yarn) and Bun; adds to the bundled roots |
/// | `SSL_CERT_FILE` | OpenSSL's default paths (curl, Python `ssl`/httpx/aiohttp, Ruby), Go, uv, pip 24.2+ |
/// | `GIT_SSL_CAINFO` | git's `http.sslCAInfo`; git's libcurl ignores `SSL_CERT_FILE` |
/// | `REQUESTS_CA_BUNDLE` | Python `requests` (uses certifi otherwise) |
/// | `CURL_CA_BUNDLE` | the curl CLI, ahead of `SSL_CERT_FILE`; `requests` as a fallback |
/// | `PIP_CERT` | pip's `--cert`, for pips that use certifi |
/// | `AWS_CA_BUNDLE` | botocore (boto3, the AWS CLI); uses certifi otherwise |
/// | `CARGO_HTTP_CAINFO` | cargo's `http.cainfo`, for distro cargo built on a libcurl that ignores `SSL_CERT_FILE` |
/// | `DENO_CERT` | Deno, which bundles Mozilla's roots; adds to them |
/// | `GRPC_DEFAULT_SSL_ROOTS_FILE_PATH` | gRPC core (grpcio and the clients built on it), which bundles its own roots |
///
/// `NPM_CONFIG_CAFILE` is deliberately absent: `NODE_EXTRA_CA_CERTS`
/// already covers npm, and `cafile` would replace Node's roots for it.
pub const ENV_VARS: &[&str] = &[
    "NODE_EXTRA_CA_CERTS",
    "SSL_CERT_FILE",
    "GIT_SSL_CAINFO",
    "REQUESTS_CA_BUNDLE",
    "CURL_CA_BUNDLE",
    "PIP_CERT",
    "AWS_CA_BUNDLE",
    "CARGO_HTTP_CAINFO",
    "DENO_CERT",
    "GRPC_DEFAULT_SSL_ROOTS_FILE_PATH",
];

/// The [`ENV_VARS`] the cage gets by default, leaving out every one
/// `user_sets` says the cage's own `container.env` sets.
///
/// Leaving the default out, rather than relying on the later
/// definition winning, is what makes the override hold on every
/// backend: quadlet keeps the last `Environment=` for a key, but
/// `container run -e` hands the workload both entries, and which one a
/// process sees then depends on how it reads its environment.
pub fn defaults(user_sets: impl Fn(&str) -> bool) -> Vec<&'static str> {
    ENV_VARS
        .iter()
        .copied()
        .filter(|var| !user_sets(var))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{ENV_VARS, defaults};

    /// With no user env, every var is set, in [`ENV_VARS`] order.
    #[test]
    fn every_var_is_a_default_when_the_user_sets_none() {
        assert_eq!(defaults(|_| false), ENV_VARS);
    }

    /// A var the user sets is left out; the rest keep their order.
    #[test]
    fn a_user_set_var_is_left_out() {
        let got = defaults(|var| var == "GIT_SSL_CAINFO" || var == "SSL_CERT_FILE");
        assert!(!got.contains(&"GIT_SSL_CAINFO"));
        assert!(!got.contains(&"SSL_CERT_FILE"));
        assert_eq!(got.len(), ENV_VARS.len() - 2);
        assert_eq!(got[0], "NODE_EXTRA_CA_CERTS");
        assert_eq!(got[1], "REQUESTS_CA_BUNDLE");
    }

    /// No var is listed twice.
    #[test]
    fn no_var_is_listed_twice() {
        let mut sorted = ENV_VARS.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), ENV_VARS.len());
    }
}
