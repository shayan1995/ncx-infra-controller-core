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

//! `CertificateService` with its `GenerateCSR` and `ReplaceCertificate` actions,
//! the manager `Truststore/Certificates` collection, and the manager HTTPS
//! certificate collection, for BMCs that model TLS client-certificate
//! authentication (`BmcState::tls_auth`). The DPF provisioning controller runs
//! this sequence before it talks to a BlueField BMC with a client certificate.

use std::borrow::Cow;
use std::net::IpAddr;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use axum::routing::{get, post};
use axum::{Json, Router};
use rustls::pki_types::CertificateDer;
use serde::Deserialize;
use serde_json::json;

use crate::bmc_state::BmcState;
use crate::json::{JsonExt, JsonPatch};
use crate::redfish::tls_auth::{InstalledCertificate, TlsAuthState};
use crate::{Callbacks, http, redfish};

pub(crate) fn resource() -> redfish::Resource<'static> {
    redfish::Resource {
        odata_id: Cow::Borrowed("/redfish/v1/CertificateService"),
        odata_type: Cow::Borrowed("#CertificateService.v1_0_0.CertificateService"),
        id: Cow::Borrowed("CertificateService"),
        name: Cow::Borrowed("Certificate Service"),
    }
}

fn generate_csr_target() -> String {
    format!(
        "{}/Actions/CertificateService.GenerateCSR",
        resource().odata_id
    )
}

fn replace_certificate_target() -> String {
    format!(
        "{}/Actions/CertificateService.ReplaceCertificate",
        resource().odata_id
    )
}

fn truststore_collection(manager_id: &str) -> redfish::Collection<'static> {
    redfish::Collection {
        odata_id: Cow::Owned(format!(
            "/redfish/v1/Managers/{manager_id}/Truststore/Certificates"
        )),
        odata_type: Cow::Borrowed("#CertificateCollection.CertificateCollection"),
        name: Cow::Borrowed("Truststore Certificates Collection"),
    }
}

fn https_collection(manager_id: &str) -> redfish::Collection<'static> {
    redfish::Collection {
        odata_id: Cow::Owned(format!(
            "/redfish/v1/Managers/{manager_id}/NetworkProtocol/HTTPS/Certificates"
        )),
        odata_type: Cow::Borrowed("#CertificateCollection.CertificateCollection"),
        name: Cow::Borrowed("HTTPS Certificates Collection"),
    }
}

/// The single HTTPS certificate slot a BlueField BMC exposes.
const HTTPS_CERTIFICATE_ID: &str = "1";

fn certificate_resource(
    collection: &redfish::Collection<'_>,
    id: &str,
) -> redfish::Resource<'static> {
    redfish::Resource {
        odata_id: Cow::Owned(format!("{}/{id}", collection.odata_id)),
        odata_type: Cow::Borrowed("#Certificate.v1_6_0.Certificate"),
        id: Cow::Owned(id.to_owned()),
        name: Cow::Borrowed("Certificate"),
    }
}

fn certificate_json(resource: &redfish::Resource<'_>, pem: &str) -> serde_json::Value {
    resource.json_patch().patch(json!({
        "CertificateType": "PEM",
        "CertificateString": pem,
    }))
}

pub(crate) fn add_routes<C: Callbacks>(r: Router<BmcState<C>>) -> Router<BmcState<C>> {
    const MGR_ID: &str = "{manager_id}";
    const CERT_ID: &str = "{certificate_id}";
    r.route(&resource().odata_id, get(get_certificate_service::<C>))
        .route(&generate_csr_target(), post(post_generate_csr::<C>))
        .route(
            &replace_certificate_target(),
            post(post_replace_certificate::<C>),
        )
        .route(
            &truststore_collection(MGR_ID).odata_id,
            get(get_truststore::<C>).post(post_truststore::<C>),
        )
        .route(
            &certificate_resource(&truststore_collection(MGR_ID), CERT_ID).odata_id,
            get(get_truststore_certificate::<C>),
        )
        .route(
            &https_collection(MGR_ID).odata_id,
            get(get_https_certificates::<C>),
        )
        .route(
            &certificate_resource(&https_collection(MGR_ID), HTTPS_CERTIFICATE_ID).odata_id,
            get(get_https_certificate::<C>),
        )
}

/// The TLS auth state of a BMC that models the feature and serves `manager_id`.
fn manager_tls_auth<'a, C: Callbacks>(
    state: &'a BmcState<C>,
    manager_id: &str,
) -> Option<&'a TlsAuthState> {
    state.manager.find(manager_id)?;
    state.tls_auth.as_deref()
}

#[derive(Deserialize)]
struct OdataRef {
    #[serde(rename = "@odata.id")]
    odata_id: String,
}

#[derive(Deserialize)]
enum CertificateType {
    #[serde(rename = "PEM")]
    Pem,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct CertificateRequest {
    certificate_string: String,
    #[allow(dead_code)]
    certificate_type: CertificateType,
    #[serde(default)]
    certificate_uri: Option<OdataRef>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct GenerateCsrRequest {
    common_name: String,
    certificate_collection: OdataRef,
    #[serde(default)]
    alternative_names: Vec<String>,
    #[serde(default)]
    organization: Option<String>,
    #[serde(default)]
    organizational_unit: Option<String>,
    #[serde(default)]
    country: Option<String>,
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    city: Option<String>,
}

type JsonBody<T> = Result<Json<T>, axum::extract::rejection::JsonRejection>;

/// The first certificate of a PEM document as DER, when it parses as X.509.
fn parse_pem_certificate(pem: &str) -> Option<CertificateDer<'static>> {
    let der = rustls_pemfile::certs(&mut pem.as_bytes()).next()?.ok()?;
    rustls::server::ParsedCertificate::try_from(&der).ok()?;
    Some(der)
}

enum CertificateLocation {
    Truststore { manager_id: String, id: u32 },
    Https { manager_id: String },
}

/// The manager whose HTTPS certificate collection `uri` names.
fn parse_https_collection_uri(uri: &str) -> Option<&str> {
    let rest = uri.strip_prefix("/redfish/v1/Managers/")?;
    let (manager_id, rest) = rest.split_once('/')?;
    (rest == "NetworkProtocol/HTTPS/Certificates").then_some(manager_id)
}

fn parse_certificate_uri(uri: &str) -> Option<CertificateLocation> {
    let rest = uri.strip_prefix("/redfish/v1/Managers/")?;
    let (manager_id, rest) = rest.split_once('/')?;
    if let Some(id) = rest.strip_prefix("Truststore/Certificates/") {
        return Some(CertificateLocation::Truststore {
            manager_id: manager_id.to_owned(),
            id: id.parse().ok()?,
        });
    }
    if rest.strip_prefix("NetworkProtocol/HTTPS/Certificates/")? == HTTPS_CERTIFICATE_ID {
        return Some(CertificateLocation::Https {
            manager_id: manager_id.to_owned(),
        });
    }
    None
}

async fn get_certificate_service<C: Callbacks>(State(state): State<BmcState<C>>) -> Response {
    if state.tls_auth.is_none() {
        return http::not_found();
    }
    resource()
        .json_patch()
        .patch(json!({
            "Actions": {
                "#CertificateService.GenerateCSR": {
                    "target": generate_csr_target(),
                },
                "#CertificateService.ReplaceCertificate": {
                    "target": replace_certificate_target(),
                    "CertificateType@Redfish.AllowableValues": ["PEM"],
                },
            },
        }))
        .into_ok_response()
}

async fn get_truststore<C: Callbacks>(
    State(state): State<BmcState<C>>,
    Path(manager_id): Path<String>,
) -> Response {
    let Some(tls_auth) = manager_tls_auth(&state, &manager_id) else {
        return http::not_found();
    };
    let collection = truststore_collection(&manager_id);
    let members = tls_auth
        .truststore()
        .iter()
        .map(|installed| certificate_resource(&collection, &installed.id.to_string()).entity_ref())
        .collect::<Vec<_>>();
    collection.with_members(&members).into_ok_response()
}

async fn get_truststore_certificate<C: Callbacks>(
    State(state): State<BmcState<C>>,
    Path((manager_id, certificate_id)): Path<(String, String)>,
) -> Response {
    let Some(tls_auth) = manager_tls_auth(&state, &manager_id) else {
        return http::not_found();
    };
    let Some(installed) = certificate_id.parse().ok().and_then(|id| tls_auth.find(id)) else {
        return http::not_found();
    };
    truststore_certificate_json(&manager_id, &installed).into_ok_response()
}

fn truststore_certificate_json(
    manager_id: &str,
    installed: &InstalledCertificate,
) -> serde_json::Value {
    certificate_json(
        &certificate_resource(
            &truststore_collection(manager_id),
            &installed.id.to_string(),
        ),
        &installed.pem,
    )
}

/// Install a trusted certificate. A duplicate answers 500 like a BlueField BMC,
/// which clients handle by replacing the existing certificate instead.
async fn post_truststore<C: Callbacks>(
    State(state): State<BmcState<C>>,
    Path(manager_id): Path<String>,
    request: JsonBody<CertificateRequest>,
) -> Response {
    let Some(tls_auth) = manager_tls_auth(&state, &manager_id) else {
        return http::not_found();
    };
    let Ok(Json(request)) = request else {
        return http::bad_request("invalid certificate request");
    };
    let Some(der) = parse_pem_certificate(&request.certificate_string) else {
        return http::bad_request("CertificateString is not a PEM certificate");
    };
    match tls_auth.install(request.certificate_string, der) {
        Some(installed) => truststore_certificate_json(&manager_id, &installed).into_ok_response(),
        None => http::redfish_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "certificate is already installed",
        ),
    }
}

async fn get_https_certificates<C: Callbacks>(
    State(state): State<BmcState<C>>,
    Path(manager_id): Path<String>,
) -> Response {
    let Some(tls_auth) = manager_tls_auth(&state, &manager_id) else {
        return http::not_found();
    };
    let collection = https_collection(&manager_id);
    let members = tls_auth
        .https_certificate()
        .map(|_| certificate_resource(&collection, HTTPS_CERTIFICATE_ID).entity_ref())
        .into_iter()
        .collect::<Vec<_>>();
    collection.with_members(&members).into_ok_response()
}

async fn get_https_certificate<C: Callbacks>(
    State(state): State<BmcState<C>>,
    Path(manager_id): Path<String>,
) -> Response {
    let Some(pem) = manager_tls_auth(&state, &manager_id).and_then(TlsAuthState::https_certificate)
    else {
        return http::not_found();
    };
    https_certificate_json(&manager_id, &pem).into_ok_response()
}

fn https_certificate_json(manager_id: &str, pem: &str) -> serde_json::Value {
    certificate_json(
        &certificate_resource(&https_collection(manager_id), HTTPS_CERTIFICATE_ID),
        pem,
    )
}

/// Generate a signing request for the manager HTTPS certificate with the
/// requested subject and alternative names. The key stays with the request:
/// the listener never serves the signed certificate, so it is not kept.
async fn post_generate_csr<C: Callbacks>(
    State(state): State<BmcState<C>>,
    request: JsonBody<GenerateCsrRequest>,
) -> Response {
    if state.tls_auth.is_none() {
        return http::not_found();
    }
    let Ok(Json(request)) = request else {
        return http::bad_request("invalid GenerateCSR request");
    };
    let collection_uri = request.certificate_collection.odata_id;
    let known_collection = parse_https_collection_uri(&collection_uri)
        .is_some_and(|manager_id| manager_tls_auth(&state, manager_id).is_some());
    if !known_collection {
        return http::bad_request(
            "CertificateCollection is not a manager HTTPS certificate collection",
        );
    }
    let mut params = match rcgen::CertificateParams::new(Vec::<String>::new()) {
        Ok(params) => params,
        Err(error) => return csr_error(&error),
    };
    let name = &mut params.distinguished_name;
    name.push(rcgen::DnType::CommonName, request.common_name);
    for (ty, value) in [
        (rcgen::DnType::OrganizationName, request.organization),
        (
            rcgen::DnType::OrganizationalUnitName,
            request.organizational_unit,
        ),
        (rcgen::DnType::CountryName, request.country),
        (rcgen::DnType::StateOrProvinceName, request.state),
        (rcgen::DnType::LocalityName, request.city),
    ] {
        if let Some(value) = value {
            name.push(ty, value);
        }
    }
    for alternative_name in &request.alternative_names {
        match parse_alternative_name(alternative_name) {
            Some(san) => params.subject_alt_names.push(san),
            None => {
                return http::bad_request(
                    "AlternativeNames entries must be \"IP: <address>\" or \"DNS: <name>\"",
                );
            }
        }
    }
    let key = match rcgen::KeyPair::generate() {
        Ok(key) => key,
        Err(error) => return csr_error(&error),
    };
    let csr = match params
        .serialize_request(&key)
        .and_then(|request| request.pem())
    {
        Ok(pem) => pem,
        Err(error) => return csr_error(&error),
    };
    json!({
        "CSRString": csr,
        "CertificateCollection": { "@odata.id": collection_uri },
    })
    .into_ok_response()
}

fn csr_error(error: &rcgen::Error) -> Response {
    tracing::error!(%error, "CSR generation failed");
    http::redfish_error(StatusCode::INTERNAL_SERVER_ERROR, "CSR generation failed")
}

/// `IP: 10.0.0.1` or `DNS: localhost`, the forms a BlueField BMC accepts.
fn parse_alternative_name(entry: &str) -> Option<rcgen::SanType> {
    let (kind, value) = entry.split_once(':')?;
    let value = value.trim();
    match kind.trim() {
        "IP" => value.parse::<IpAddr>().ok().map(rcgen::SanType::IpAddress),
        "DNS" => value.try_into().ok().map(rcgen::SanType::DnsName),
        _ => None,
    }
}

/// Replace an installed Truststore certificate or the HTTPS server certificate.
async fn post_replace_certificate<C: Callbacks>(
    State(state): State<BmcState<C>>,
    request: JsonBody<CertificateRequest>,
) -> Response {
    if state.tls_auth.is_none() {
        return http::not_found();
    }
    let Ok(Json(request)) = request else {
        return http::bad_request("invalid ReplaceCertificate request");
    };
    let Some(location) = request
        .certificate_uri
        .as_ref()
        .and_then(|uri| parse_certificate_uri(&uri.odata_id))
    else {
        return http::bad_request(
            "CertificateUri must name a manager Truststore or HTTPS certificate",
        );
    };
    let Some(der) = parse_pem_certificate(&request.certificate_string) else {
        return http::bad_request("CertificateString is not a PEM certificate");
    };
    match location {
        CertificateLocation::Truststore { manager_id, id } => {
            let Some(installed) = manager_tls_auth(&state, &manager_id)
                .and_then(|tls_auth| tls_auth.replace(id, request.certificate_string, der))
            else {
                return http::not_found();
            };
            truststore_certificate_json(&manager_id, &installed).into_ok_response()
        }
        CertificateLocation::Https { manager_id } => {
            let Some(tls_auth) = manager_tls_auth(&state, &manager_id) else {
                return http::not_found();
            };
            tls_auth.set_https_certificate(request.certificate_string.clone());
            https_certificate_json(&manager_id, &request.certificate_string).into_ok_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use axum::Router;
    use axum::body::{Body, to_bytes};
    use axum::http::{Request, StatusCode};
    use axum::response::Response;
    use serde_json::Value;
    use tower::ServiceExt;

    use super::*;
    use crate::redfish::tls_auth::test_certificates::authority;
    use crate::test_support::{TestBmcConfig, TestCallbacks, create_test_bmc, dpu_info, host_info};
    use crate::{HardwareType, MachineRouterOptions};

    const MANAGER: &str = "Bluefield_BMC";

    fn bluefield3() -> (Router, BmcState<TestCallbacks>) {
        create_test_bmc(
            &dpu_info(HardwareType::WiwynnGB200Nvl),
            TestBmcConfig::default(),
            "certificate-service".into(),
            false,
            MachineRouterOptions::default(),
        )
    }

    async fn call(router: &Router, method: &str, path: &str, body: Value) -> Response {
        router
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    async fn json(response: Response) -> Value {
        serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap()).unwrap()
    }

    fn certificate_body(pem: &str, uri: Option<&str>) -> Value {
        let mut body = json!({"CertificateString": pem, "CertificateType": "PEM"});
        if let Some(uri) = uri {
            body["CertificateUri"] = json!({"@odata.id": uri});
        }
        body
    }

    #[tokio::test]
    async fn truststore_install_lists_replaces_and_refuses_duplicates() {
        let (router, state) = bluefield3();
        let first = authority("first");
        let second = authority("second");
        let collection = format!("/redfish/v1/Managers/{MANAGER}/Truststore/Certificates");

        let response = call(
            &router,
            "POST",
            &collection,
            certificate_body(&first.ca_pem, None),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let installed = json(response).await;
        assert_eq!(installed["@odata.id"], format!("{collection}/1"));
        assert_eq!(installed["CertificateString"], first.ca_pem);

        let response = call(
            &router,
            "POST",
            &collection,
            certificate_body(&first.ca_pem, None),
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::INTERNAL_SERVER_ERROR,
            "a duplicate install answers like the BMC"
        );

        let listed = json(call(&router, "GET", &collection, Value::Null).await).await;
        assert_eq!(listed["Members@odata.count"], 1);

        let response = call(
            &router,
            "POST",
            "/redfish/v1/CertificateService/Actions/CertificateService.ReplaceCertificate",
            certificate_body(&second.ca_pem, Some(&format!("{collection}/1"))),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let member =
            json(call(&router, "GET", &format!("{collection}/1"), Value::Null).await).await;
        assert_eq!(member["CertificateString"], second.ca_pem);
        assert_eq!(
            state.tls_auth.as_ref().unwrap().truststore()[0].der,
            second.ca_der,
            "the replacement is what later client certificates chain to"
        );
    }

    #[tokio::test]
    async fn replace_certificate_rejects_unknown_locations_and_bodies() {
        let (router, _state) = bluefield3();
        let ours = authority("replace");
        let target = "/redfish/v1/CertificateService/Actions/CertificateService.ReplaceCertificate";
        for (scenario, body, expected) in [
            (
                "https certificate slot",
                certificate_body(
                    &ours.ca_pem,
                    Some(&format!(
                        "/redfish/v1/Managers/{MANAGER}/NetworkProtocol/HTTPS/Certificates/1"
                    )),
                ),
                StatusCode::OK,
            ),
            (
                "missing truststore member",
                certificate_body(
                    &ours.ca_pem,
                    Some(&format!(
                        "/redfish/v1/Managers/{MANAGER}/Truststore/Certificates/7"
                    )),
                ),
                StatusCode::NOT_FOUND,
            ),
            (
                "unknown manager",
                certificate_body(
                    &ours.ca_pem,
                    Some("/redfish/v1/Managers/Other/Truststore/Certificates/1"),
                ),
                StatusCode::NOT_FOUND,
            ),
            (
                "location outside the two collections",
                certificate_body(&ours.ca_pem, Some("/redfish/v1/AccountService")),
                StatusCode::BAD_REQUEST,
            ),
            (
                "no location",
                certificate_body(&ours.ca_pem, None),
                StatusCode::BAD_REQUEST,
            ),
            (
                "not a certificate",
                certificate_body(
                    "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
                    Some(&format!(
                        "/redfish/v1/Managers/{MANAGER}/NetworkProtocol/HTTPS/Certificates/1"
                    )),
                ),
                StatusCode::BAD_REQUEST,
            ),
        ] {
            let response = call(&router, "POST", target, body).await;
            assert_eq!(response.status(), expected, "{scenario}");
        }
        let slot = json(
            call(
                &router,
                "GET",
                &format!("/redfish/v1/Managers/{MANAGER}/NetworkProtocol/HTTPS/Certificates/1"),
                Value::Null,
            )
            .await,
        )
        .await;
        assert_eq!(slot["CertificateString"], ours.ca_pem);
    }

    #[tokio::test]
    async fn generate_csr_returns_a_request_a_ca_can_sign() {
        let (router, _state) = bluefield3();
        let target = "/redfish/v1/CertificateService/Actions/CertificateService.GenerateCSR";
        let collection =
            format!("/redfish/v1/Managers/{MANAGER}/NetworkProtocol/HTTPS/Certificates");
        // The DPF provisioning controller's request, verbatim shape.
        let response = call(
            &router,
            "POST",
            target,
            json!({
                "CommonName": "10.200.30.196",
                "City": "Santa Clara",
                "Country": "US",
                "Organization": "NVIDIA",
                "OrganizationalUnit": "NBU",
                "State": "CA",
                "CertificateCollection": {"@odata.id": collection},
                "AlternativeNames": ["IP: 10.200.30.196", "DNS: localhost", "IP: 127.0.0.1"],
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = json(response).await;
        assert_eq!(body["CertificateCollection"]["@odata.id"], collection);
        let csr =
            rcgen::CertificateSigningRequestParams::from_pem(body["CSRString"].as_str().unwrap())
                .expect("the CSR parses and its signature verifies");
        assert_eq!(
            csr.params
                .distinguished_name
                .get(&rcgen::DnType::CommonName)
                .map(|value| format!("{value:?}")),
            Some(format!(
                "{:?}",
                rcgen::DnValue::Utf8String("10.200.30.196".into())
            ))
        );
        assert_eq!(
            csr.params.subject_alt_names,
            vec![
                rcgen::SanType::IpAddress("10.200.30.196".parse().unwrap()),
                rcgen::SanType::DnsName("localhost".try_into().unwrap()),
                rcgen::SanType::IpAddress("127.0.0.1".parse().unwrap()),
            ]
        );
        // What cert-manager does with the request once the operator submits it.
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let issuer = rcgen::Issuer::new(ca_params, ca_key);
        csr.signed_by(&issuer).expect("a CA signs the request");

        for (scenario, body) in [
            (
                "collection outside the manager HTTPS slot",
                json!({"CommonName": "x", "CertificateCollection": {"@odata.id": format!("/redfish/v1/Managers/{MANAGER}/Truststore/Certificates")}}),
            ),
            (
                "malformed alternative name",
                json!({"CommonName": "x", "CertificateCollection": {"@odata.id": collection}, "AlternativeNames": ["URI: spiffe://x"]}),
            ),
        ] {
            let response = call(&router, "POST", target, body).await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{scenario}");
        }
    }

    #[tokio::test]
    async fn only_dpu_bmcs_advertise_and_serve_the_certificate_service() {
        let (host, _state) = create_test_bmc(
            &host_info(HardwareType::DellPowerEdgeR750),
            TestBmcConfig::default(),
            "host".into(),
            false,
            MachineRouterOptions::default(),
        );
        for path in [
            "/redfish/v1/CertificateService",
            "/redfish/v1/Managers/iDRAC.Embedded.1/Truststore/Certificates",
        ] {
            let response = call(&host, "GET", path, Value::Null).await;
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
        }
        let root = json(call(&host, "GET", "/redfish/v1", Value::Null).await).await;
        assert!(
            root.get("CertificateService").is_none(),
            "host root has no link"
        );

        let (dpu, _state) = bluefield3();
        let root = json(call(&dpu, "GET", "/redfish/v1", Value::Null).await).await;
        assert_eq!(
            root["CertificateService"]["@odata.id"],
            "/redfish/v1/CertificateService"
        );
        let service =
            json(call(&dpu, "GET", "/redfish/v1/CertificateService", Value::Null).await).await;
        assert_eq!(
            service["Actions"]["#CertificateService.GenerateCSR"]["target"],
            "/redfish/v1/CertificateService/Actions/CertificateService.GenerateCSR"
        );
    }

    /// The DPF controller's EnableMTLS PATCH carries a JSON string that its
    /// HTTP client labels text/plain; the BMC must apply it all the same.
    #[tokio::test]
    async fn enable_mtls_patch_is_applied_without_a_json_content_type() {
        let (router, state) = bluefield3();
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri("/redfish/v1/AccountService")
                    .header("content-type", "text/plain; charset=utf-8")
                    .body(Body::from(
                        r#"{"Oem": {"OpenBMC": {"AuthMethods": {"TLS": true}}}}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = json(response).await;
        assert_eq!(body["Oem"]["OpenBMC"]["AuthMethods"]["TLS"], true);
        assert!(state.tls_auth.as_ref().unwrap().tls_enabled());
    }

    /// Over real TLS: the listener requests the client certificate, the
    /// connection layer forwards it, and the authorizer accepts it only after
    /// the DPF controller's set-up sequence ran against this BMC.
    #[tokio::test]
    async fn client_certificate_authenticates_over_tls_after_the_set_up_sequence() {
        let (router, _state) = create_test_bmc(
            &dpu_info(HardwareType::WiwynnGB200Nvl),
            TestBmcConfig::default(),
            "mtls-tls".into(),
            true,
            MachineRouterOptions::default(),
        );
        let (_server, base) = crate::test_support::serve_https("mtls", router);
        let ours = authority("ours");
        let theirs = authority("theirs");
        let client = |identity: Option<&crate::redfish::tls_auth::test_certificates::Authority>| {
            let builder = reqwest::Client::builder().danger_accept_invalid_certs(true);
            let builder = match identity {
                Some(authority) => builder.identity(
                    reqwest::Identity::from_pem(
                        format!("{}{}", authority.client_pem, authority.client_key_pem).as_bytes(),
                    )
                    .unwrap(),
                ),
                None => builder,
            };
            builder.build().unwrap()
        };
        let anonymous = client(None);
        let ours_client = client(Some(&ours));
        let theirs_client = client(Some(&theirs));
        let url = |path: &str| base.join(path).unwrap();
        let probe = url("redfish/v1/Systems/Bluefield/Oem/Nvidia");

        let session = anonymous
            .post(url("redfish/v1/SessionService/Sessions"))
            .header("content-type", "application/json")
            .body(json!({"UserName": "root", "Password": "0penBmc"}).to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(session.status(), 201);
        let token = session.headers()["x-auth-token"]
            .to_str()
            .unwrap()
            .to_owned();

        let before = ours_client.get(probe.clone()).send().await.unwrap();
        assert_eq!(before.status(), 401, "before the set-up sequence");

        let install = anonymous
            .post(url(
                "redfish/v1/Managers/Bluefield_BMC/Truststore/Certificates",
            ))
            .header("x-auth-token", &token)
            .header("content-type", "application/json")
            .body(json!({"CertificateString": ours.ca_pem, "CertificateType": "PEM"}).to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(install.status(), 200);
        let enable = anonymous
            .patch(url("redfish/v1/AccountService"))
            .header("x-auth-token", &token)
            .header("content-type", "application/json")
            .body(json!({"Oem": {"OpenBMC": {"AuthMethods": {"TLS": true}}}}).to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(enable.status(), 200);

        for (scenario, client, expected) in [
            ("our certificate", &ours_client, 200),
            ("foreign certificate", &theirs_client, 401),
            ("no certificate", &anonymous, 401),
        ] {
            let response = client.get(probe.clone()).send().await.unwrap();
            assert_eq!(response.status(), expected, "{scenario}");
        }
    }
}
