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

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::header::WWW_AUTHENTICATE;
use axum::http::{HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use axum_extra::TypedHeader;
use axum_extra::headers::Authorization;
use axum_extra::headers::authorization::Basic;
use carbide_axum_utils::router::call_router_with_new_request;
use tracing::instrument;

use crate::redfish::account_service::AccountServiceState;
use crate::redfish::session_service::SessionServiceState;
use crate::redfish::tls_auth::{PEER_CERTIFICATE_HEADER, TlsAuthState, decode_peer_certificate};
use crate::redfish::{account_service, service_root, session_service};

const WWW_AUTHENTICATE_VALUE: HeaderValue = HeaderValue::from_static("Basic realm=\"bmc-mock\"");
const X_AUTH_TOKEN_HEADER: &str = "x-auth-token";

pub(super) fn append(router: Router, authorizer: Authorizer) -> Router {
    let service_root_path = service_root::resource().odata_id.to_string();
    let service_root_path_with_trailing_slash = format!("{service_root_path}/");
    let account_service_path = account_service::resource().odata_id.to_string();
    let account_service_subtree_path = format!("{account_service_path}/{{*all}}");
    let sessions_collection_path = session_service::sessions_collection().odata_id.to_string();

    Router::new()
        .route(&service_root_path, any(process_without_auth))
        .route(
            &service_root_path_with_trailing_slash,
            any(process_without_auth),
        )
        .route(&sessions_collection_path, any(process_sessions_collection))
        .route(&account_service_path, any(process_account_service))
        .route(&account_service_subtree_path, any(process_account_service))
        .route("/{*all}", any(process))
        .with_state(AuthMiddleware {
            inner: router,
            authorizer,
        })
}

#[instrument(skip_all)]
async fn process_without_auth(
    State(mut state): State<AuthMiddleware>,
    request: Request<Body>,
) -> Response {
    state.call_inner_router(request).await
}

#[instrument(skip_all)]
async fn process_sessions_collection(
    State(mut state): State<AuthMiddleware>,
    authorization: Option<TypedHeader<Authorization<Basic>>>,
    request: Request<Body>,
) -> Response {
    if request.method() == Method::POST {
        return state.call_inner_router(request).await;
    }
    match state
        .authorizer
        .authorize(&request, authorization.as_ref(), true)
    {
        AuthorizationResult::Authorized => state.call_inner_router(request).await,
        AuthorizationResult::Unauthorized => unauthorized_log_and_response(request),
        AuthorizationResult::FactoryDefaultPasswordForbidden => {
            unreachable!(
                "session collection authorization does not forbid factory-default passwords"
            )
        }
    }
}

#[instrument(skip_all)]
async fn process_account_service(
    State(mut state): State<AuthMiddleware>,
    authorization: Option<TypedHeader<Authorization<Basic>>>,
    request: Request<Body>,
) -> Response {
    match state
        .authorizer
        .authorize(&request, authorization.as_ref(), true)
    {
        AuthorizationResult::Authorized => state.call_inner_router(request).await,
        AuthorizationResult::Unauthorized => unauthorized_log_and_response(request),
        AuthorizationResult::FactoryDefaultPasswordForbidden => {
            unreachable!("account service authorization does not forbid factory-default passwords")
        }
    }
}

#[instrument(skip_all)]
async fn process(
    State(mut state): State<AuthMiddleware>,
    authorization: Option<TypedHeader<Authorization<Basic>>>,
    request: Request<Body>,
) -> Response {
    match state
        .authorizer
        .authorize(&request, authorization.as_ref(), false)
    {
        AuthorizationResult::Authorized => state.call_inner_router(request).await,
        AuthorizationResult::Unauthorized => unauthorized_log_and_response(request),
        AuthorizationResult::FactoryDefaultPasswordForbidden => {
            tracing::warn!(
                method = request.method().as_str(),
                path = request.uri().path(),
                "Factory-default password must be changed before accessing this resource",
            );
            StatusCode::FORBIDDEN.into_response()
        }
    }
}

fn unauthorized_log_and_response(request: Request<Body>) -> Response {
    tracing::warn!(
        method = request.method().as_str(),
        path = request.uri().path(),
        "Unauthorized request",
    );
    unauthorized_response()
}

fn unauthorized_response() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(WWW_AUTHENTICATE, WWW_AUTHENTICATE_VALUE)],
    )
        .into_response()
}

#[derive(Clone)]
struct AuthMiddleware {
    inner: Router,
    authorizer: Authorizer,
}

impl AuthMiddleware {
    async fn call_inner_router(&mut self, request: Request<Body>) -> Response {
        call_router_with_new_request(&mut self.inner, request).await
    }
}

#[derive(Clone)]
pub(super) struct Authorizer {
    account_service_state: Arc<AccountServiceState>,
    session_service_state: Arc<SessionServiceState>,
    /// TLS client-certificate authentication, for BMCs that model it.
    tls_auth: Option<Arc<TlsAuthState>>,
    forbid_factory_default_password: bool,
}

impl Authorizer {
    /// Builds the factory-default authorizer for a mock BMC state.
    pub(super) fn new(
        account_service_state: Arc<AccountServiceState>,
        session_service_state: Arc<SessionServiceState>,
        tls_auth: Option<Arc<TlsAuthState>>,
    ) -> Self {
        Self {
            account_service_state,
            session_service_state,
            tls_auth,
            forbid_factory_default_password: true,
        }
    }

    pub(super) fn permit_factory_default_password(mut self) -> Self {
        self.forbid_factory_default_password = false;
        self
    }

    fn authorize(
        &self,
        request: &Request<Body>,
        authorization: Option<&TypedHeader<Authorization<Basic>>>,
        permit_factory_default: bool,
    ) -> AuthorizationResult {
        if let Some(token) = request
            .headers()
            .get(X_AUTH_TOKEN_HEADER)
            .and_then(|v| v.to_str().ok())
            && self.session_service_state.is_token_valid(token)
        {
            return AuthorizationResult::Authorized;
        }

        // The connection layer sets this header from the TLS peer certificate.
        if let Some(tls_auth) = &self.tls_auth
            && let Some(peer) = request
                .headers()
                .get(PEER_CERTIFICATE_HEADER)
                .and_then(decode_peer_certificate)
            && tls_auth.authenticates(&peer)
        {
            return AuthorizationResult::Authorized;
        }

        let Some(authorization) = authorization else {
            return AuthorizationResult::Unauthorized;
        };
        let actual = &authorization.0.0;
        if self
            .account_service_state
            .is_authorized(actual.username(), actual.password())
        {
            if self.forbid_factory_default_password
                && !permit_factory_default
                && self
                    .account_service_state
                    .is_factory_default_password(actual.username(), actual.password())
            {
                AuthorizationResult::FactoryDefaultPasswordForbidden
            } else {
                AuthorizationResult::Authorized
            }
        } else {
            AuthorizationResult::Unauthorized
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AuthorizationResult {
    Authorized,
    Unauthorized,
    FactoryDefaultPasswordForbidden,
}

#[cfg(test)]
mod tests {
    use axum::Router;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::response::Response;
    use serde_json::json;
    use tower::ServiceExt;

    use crate::redfish::tls_auth::test_certificates::authority;
    use crate::redfish::tls_auth::{PEER_CERTIFICATE_HEADER, encode_peer_certificate};
    use crate::test_support::{TestBmcConfig, create_test_bmc, dpu_info};
    use crate::{HardwareType, MachineRouterOptions};

    const PROBE: &str = "/redfish/v1/Systems/Bluefield/Oem/Nvidia";

    async fn send(
        router: &Router,
        method: &str,
        path: &str,
        token: Option<&str>,
        peer_certificate: Option<&str>,
        body: serde_json::Value,
    ) -> Response {
        let mut request = Request::builder()
            .method(method)
            .uri(path)
            .header("content-type", "application/json");
        if let Some(token) = token {
            request = request.header("x-auth-token", token);
        }
        if let Some(peer_certificate) = peer_certificate {
            request = request.header(PEER_CERTIFICATE_HEADER, peer_certificate);
        }
        router
            .clone()
            .oneshot(request.body(Body::from(body.to_string())).unwrap())
            .await
            .unwrap()
    }

    /// The DPF provisioning controller's sequence against a BlueField-3 BMC:
    /// install the CA, enable the method, then probe with the client
    /// certificate and no credentials. The peer certificate header stands in
    /// for the connection layer.
    #[tokio::test]
    async fn client_certificate_authorizes_only_enabled_chains_to_the_truststore() {
        let (router, _state) = create_test_bmc(
            &dpu_info(HardwareType::WiwynnGB200Nvl),
            TestBmcConfig::default(),
            "mtls".into(),
            true,
            MachineRouterOptions::default(),
        );
        let ours = authority("ours");
        let theirs = authority("theirs");
        let our_header = encode_peer_certificate(&ours.client_der).unwrap();
        let their_header = encode_peer_certificate(&theirs.client_der).unwrap();
        let (ours_peer, theirs_peer) =
            (our_header.to_str().unwrap(), their_header.to_str().unwrap());

        let session = send(
            &router,
            "POST",
            "/redfish/v1/SessionService/Sessions",
            None,
            None,
            json!({"UserName": "root", "Password": "0penBmc"}),
        )
        .await;
        assert_eq!(session.status(), StatusCode::CREATED);
        let token = session.headers()["x-auth-token"]
            .to_str()
            .unwrap()
            .to_owned();

        let response = send(&router, "GET", PROBE, None, Some(ours_peer), json!(null)).await;
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "before any set-up"
        );

        let response = send(
            &router,
            "POST",
            "/redfish/v1/Managers/Bluefield_BMC/Truststore/Certificates",
            Some(&token),
            None,
            json!({"CertificateString": ours.ca_pem, "CertificateType": "PEM"}),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let response = send(&router, "GET", PROBE, None, Some(ours_peer), json!(null)).await;
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "an installed CA alone does not authenticate"
        );

        let response = send(
            &router,
            "PATCH",
            "/redfish/v1/AccountService",
            Some(&token),
            None,
            json!({"Oem": {"OpenBMC": {"AuthMethods": {"TLS": true}}}}),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);

        for (scenario, peer, expected) in [
            (
                "certificate chaining to the installed CA",
                Some(ours_peer),
                StatusCode::OK,
            ),
            (
                "certificate from a foreign CA",
                Some(theirs_peer),
                StatusCode::UNAUTHORIZED,
            ),
            (
                "malformed header",
                Some("not a certificate"),
                StatusCode::UNAUTHORIZED,
            ),
            (
                "no certificate and no credentials",
                None,
                StatusCode::UNAUTHORIZED,
            ),
        ] {
            let response = send(&router, "GET", PROBE, None, peer, json!(null)).await;
            assert_eq!(response.status(), expected, "{scenario}");
        }
    }
}
