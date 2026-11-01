// Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! TLS client-certificate authentication state of one BMC: the certificates a
//! client installed through the manager Truststore, whether the `TLS` auth
//! method is enabled, and the HTTPS certificate a client replaced.
//!
//! The listener accepts any client certificate during the handshake and the
//! connection layer forwards the peer's leaf certificate in
//! [`PEER_CERTIFICATE_HEADER`]. A request is authenticated by that certificate
//! only when this state has the `TLS` method enabled and the certificate chains
//! to an installed Truststore certificate, which is how a BlueField BMC behaves
//! after the DPF provisioning controller's mTLS set-up.

use std::sync::{Arc, Mutex};

use axum::http::HeaderValue;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, UnixTime};
use rustls::server::WebPkiClientVerifier;

/// Header the connection layer sets from the TLS peer certificate (base64 DER
/// of the leaf). It replaces any copy a client sent.
pub(crate) const PEER_CERTIFICATE_HEADER: &str = "x-bmc-mock-peer-certificate";

pub(crate) fn encode_peer_certificate(der: &[u8]) -> Option<HeaderValue> {
    HeaderValue::from_str(&BASE64.encode(der)).ok()
}

pub(crate) fn decode_peer_certificate(value: &HeaderValue) -> Option<CertificateDer<'static>> {
    let der = BASE64.decode(value.as_bytes()).ok()?;
    Some(CertificateDer::from(der))
}

/// A certificate installed through the Truststore, numbered from 1 in
/// installation order.
#[derive(Clone)]
pub(crate) struct InstalledCertificate {
    pub(crate) id: u32,
    pub(crate) pem: String,
    pub(crate) der: CertificateDer<'static>,
}

#[derive(Default)]
struct Inner {
    tls_enabled: bool,
    next_id: u32,
    truststore: Vec<InstalledCertificate>,
    https_certificate: Option<String>,
}

pub(crate) struct TlsAuthState {
    inner: Mutex<Inner>,
}

impl TlsAuthState {
    pub(crate) fn new() -> Self {
        Self {
            inner: Mutex::new(Inner {
                next_id: 1,
                ..Inner::default()
            }),
        }
    }

    pub(crate) fn tls_enabled(&self) -> bool {
        self.inner.lock().unwrap().tls_enabled
    }

    pub(crate) fn set_tls_enabled(&self, enabled: bool) {
        self.inner.lock().unwrap().tls_enabled = enabled;
    }

    /// Install a certificate. `None` when the same certificate is already
    /// installed, which a BlueField BMC reports as an internal error.
    pub(crate) fn install(
        &self,
        pem: String,
        der: CertificateDer<'static>,
    ) -> Option<InstalledCertificate> {
        let mut inner = self.inner.lock().unwrap();
        if inner
            .truststore
            .iter()
            .any(|installed| installed.der == der)
        {
            return None;
        }
        let certificate = InstalledCertificate {
            id: inner.next_id,
            pem,
            der,
        };
        inner.next_id += 1;
        inner.truststore.push(certificate.clone());
        Some(certificate)
    }

    /// Replace the installed certificate `id`. `None` when it does not exist.
    pub(crate) fn replace(
        &self,
        id: u32,
        pem: String,
        der: CertificateDer<'static>,
    ) -> Option<InstalledCertificate> {
        let mut inner = self.inner.lock().unwrap();
        let installed = inner
            .truststore
            .iter_mut()
            .find(|installed| installed.id == id)?;
        installed.pem = pem;
        installed.der = der;
        Some(installed.clone())
    }

    pub(crate) fn truststore(&self) -> Vec<InstalledCertificate> {
        self.inner.lock().unwrap().truststore.clone()
    }

    pub(crate) fn find(&self, id: u32) -> Option<InstalledCertificate> {
        self.inner
            .lock()
            .unwrap()
            .truststore
            .iter()
            .find(|installed| installed.id == id)
            .cloned()
    }

    /// The HTTPS server certificate a client replaced, as PEM. The listener
    /// keeps serving its own certificate: the DPF client skips verification.
    pub(crate) fn https_certificate(&self) -> Option<String> {
        self.inner.lock().unwrap().https_certificate.clone()
    }

    pub(crate) fn set_https_certificate(&self, pem: String) {
        self.inner.lock().unwrap().https_certificate = Some(pem);
    }

    /// Factory reset: forget every certificate and disable the method.
    pub(crate) fn reset(&self) {
        let mut inner = self.inner.lock().unwrap();
        *inner = Inner {
            next_id: 1,
            ..Inner::default()
        };
    }

    /// Whether a request presenting `peer` is authenticated: the `TLS` method is
    /// enabled and `peer` chains to an installed certificate.
    pub(crate) fn authenticates(&self, peer: &CertificateDer<'_>) -> bool {
        let (enabled, truststore) = {
            let inner = self.inner.lock().unwrap();
            (inner.tls_enabled, inner.truststore.clone())
        };
        if !enabled {
            return false;
        }
        let mut roots = RootCertStore::empty();
        for installed in truststore {
            // A leaf installed beside the CA is not a trust anchor; skip it.
            let _ = roots.add(installed.der);
        }
        if roots.is_empty() {
            return false;
        }
        let Ok(verifier) = WebPkiClientVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
        )
        .build() else {
            return false;
        };
        verifier
            .verify_client_cert(peer, &[], UnixTime::now())
            .is_ok()
    }
}

#[cfg(test)]
pub(crate) mod test_certificates {
    //! A CA with a client certificate it signed, for the authorizer and route
    //! tests. Generated once per call so tests stay independent.

    use rcgen::{
        BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    };
    use rustls::pki_types::CertificateDer;

    pub(crate) struct Authority {
        pub(crate) ca_pem: String,
        pub(crate) ca_der: CertificateDer<'static>,
        pub(crate) client_pem: String,
        pub(crate) client_key_pem: String,
        pub(crate) client_der: CertificateDer<'static>,
    }

    pub(crate) fn authority(name: &str) -> Authority {
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, format!("{name} CA"));
        let ca_key = KeyPair::generate().unwrap();
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();
        let issuer = Issuer::new(ca_params, ca_key);

        let mut client_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        client_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, format!("{name} client"));
        client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let client_key = KeyPair::generate().unwrap();
        let client_cert = client_params.signed_by(&client_key, &issuer).unwrap();

        Authority {
            ca_pem: ca_cert.pem(),
            ca_der: ca_cert.der().clone(),
            client_pem: client_cert.pem(),
            client_key_pem: client_key.serialize_pem(),
            client_der: client_cert.der().clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_certificates::authority;
    use super::*;

    #[test]
    fn authenticates_only_enabled_chains_to_the_truststore() {
        let ours = authority("ours");
        let theirs = authority("theirs");
        let state = TlsAuthState::new();
        let installed = state
            .install(ours.ca_pem.clone(), ours.ca_der.clone())
            .expect("first install succeeds");
        assert_eq!(installed.id, 1);
        assert!(
            state
                .install(ours.ca_pem.clone(), ours.ca_der.clone())
                .is_none(),
            "a duplicate install is refused"
        );
        for (scenario, enabled, peer, expected) in [
            ("method disabled", false, &ours.client_der, false),
            (
                "method enabled, chains to the installed CA",
                true,
                &ours.client_der,
                true,
            ),
            (
                "method enabled, foreign CA",
                true,
                &theirs.client_der,
                false,
            ),
        ] {
            state.set_tls_enabled(enabled);
            assert_eq!(state.authenticates(peer), expected, "{scenario}");
        }
        state.reset();
        assert!(!state.tls_enabled(), "reset disables the method");
        assert!(
            state.truststore().is_empty(),
            "reset empties the truststore"
        );
    }

    #[test]
    fn peer_certificate_header_round_trips() {
        let ours = authority("header");
        let header = encode_peer_certificate(&ours.client_der).unwrap();
        assert_eq!(
            decode_peer_certificate(&header).as_deref(),
            Some(ours.client_der.as_ref())
        );
        assert!(decode_peer_certificate(&HeaderValue::from_static("not base64!")).is_none());
    }
}
