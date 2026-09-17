/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//! gRPC transport from the gateway to the RMS services of each machine-a-tron instance.
//!
//! machine-a-tron serves RMS on the same TLS listener as its simulated BMCs and status routes,
//! negotiating HTTP/2 over ALPN. The gateway reaches it at the source `base_url` and trusts it the
//! way the inventory poller does: the `[sources]` CA when one is configured, the system roots
//! otherwise, or nothing at all when `insecure_skip_verify` is set. Plain `http://` base URLs, as
//! used by tests, speak HTTP/2 with prior knowledge.

use std::sync::Arc;
use std::time::Duration;

use eyre::{Context, ensure};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::connect::HttpConnector;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use tonic::transport::{Channel, Endpoint};
use url::Url;

use crate::config::{RmsConfig, SourceClientConfig};

/// Builds the gRPC channels towards the machine-a-tron instances.
#[derive(Clone)]
pub(crate) struct BackendConnector {
    https: HttpsConnector<HttpConnector>,
    request_timeout: Duration,
}

impl BackendConnector {
    /// Builds the connector from the gateway's source trust settings and RMS timeout.
    ///
    /// The CA file is read here so that a missing or malformed file fails startup rather than
    /// the first forwarded request.
    pub(crate) fn new(sources: &SourceClientConfig, rms: &RmsConfig) -> eyre::Result<Self> {
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let builder = HttpsConnectorBuilder::new();
        let https = match tls_config(sources, provider.clone())? {
            Some(config) => builder.with_tls_config(config),
            None => builder
                .with_provider_and_native_roots(provider)
                .wrap_err("loading system TLS roots for machine-a-tron RMS connections")?,
        }
        .https_or_http()
        .enable_http2()
        .build();
        Ok(Self {
            https,
            request_timeout: rms.request_timeout,
        })
    }

    /// A channel to the instance at `base_url`; nothing is connected until the first call.
    pub(crate) fn channel(&self, base_url: &Url) -> eyre::Result<Channel> {
        let endpoint = Endpoint::from_shared(base_url.to_string())
            .wrap_err_with(|| format!("machine-a-tron base URL {base_url} is not a valid URI"))?
            .timeout(self.request_timeout);
        Ok(endpoint.connect_with_connector_lazy(self.https.clone()))
    }
}

/// The rustls configuration for the `[sources]` trust settings, or `None` for the system roots.
fn tls_config(
    sources: &SourceClientConfig,
    provider: Arc<CryptoProvider>,
) -> eyre::Result<Option<ClientConfig>> {
    let builder = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .wrap_err("rustls rejected the default protocol versions")?;

    if sources.insecure_skip_verify {
        tracing::warn!(
            "sources.insecure_skip_verify is set; machine-a-tron RMS certificates are not verified"
        );
        return Ok(Some(
            builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(SkipServerVerification(provider)))
                .with_no_client_auth(),
        ));
    }

    let Some(path) = sources.ca_cert_path.as_ref() else {
        return Ok(None);
    };
    let pem = std::fs::read(path)
        .wrap_err_with(|| format!("reading sources.ca_cert_path {}", path.display()))?;
    let mut roots = RootCertStore::empty();
    for certificate in rustls_pemfile::certs(&mut pem.as_slice()) {
        let certificate =
            certificate.wrap_err_with(|| format!("parsing PEM in {}", path.display()))?;
        roots
            .add(certificate)
            .wrap_err_with(|| format!("adding a root from {}", path.display()))?;
    }
    ensure!(
        !roots.is_empty(),
        "sources.ca_cert_path {} contains no certificates",
        path.display()
    );
    Ok(Some(
        builder.with_root_certificates(roots).with_no_client_auth(),
    ))
}

/// Accepts any server certificate. Signatures are still checked so that a broken handshake is
/// rejected; only the chain and the name are ignored, which is what `insecure_skip_verify` asks.
#[derive(Debug)]
struct SkipServerVerification(Arc<CryptoProvider>);

impl ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_or_empty_ca_file_fails_construction() {
        let missing = SourceClientConfig {
            ca_cert_path: Some("/nonexistent/ca.crt".into()),
            ..SourceClientConfig::default()
        };
        let error = BackendConnector::new(&missing, &RmsConfig::default())
            .map(drop)
            .unwrap_err();
        assert!(error.to_string().contains("ca_cert_path"), "{error}");

        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), "not a certificate\n").unwrap();
        let empty = SourceClientConfig {
            ca_cert_path: Some(file.path().to_path_buf()),
            ..SourceClientConfig::default()
        };
        let error = BackendConnector::new(&empty, &RmsConfig::default())
            .map(drop)
            .unwrap_err();
        assert!(error.to_string().contains("no certificates"), "{error}");
    }

    #[tokio::test]
    async fn default_and_insecure_settings_build_channels_for_http_and_https_origins() {
        for sources in [
            SourceClientConfig::default(),
            SourceClientConfig {
                insecure_skip_verify: true,
                ..SourceClientConfig::default()
            },
        ] {
            let connector = BackendConnector::new(&sources, &RmsConfig::default()).unwrap();
            for url in ["http://127.0.0.1:1", "https://mat.example:8443/"] {
                connector.channel(&Url::parse(url).unwrap()).unwrap();
            }
        }
    }
}
