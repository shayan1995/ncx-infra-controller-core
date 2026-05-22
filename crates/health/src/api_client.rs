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

use std::convert::TryFrom;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::{Arc, RwLock};

use nico_uuid::rack::RackId;
use nico_uuid::switch::SwitchId;
use nico_tls::client_config::ClientCert;
use mac_address::MacAddress;
use rpc::nico::MachineSearchConfig;
use rpc::nico_api_client::NicoApiClient;
use rpc::nico_tls_client::{ApiConfig, NicoClientConfig};
use url::Url;

use crate::HealthError;
use crate::endpoint::{
    BmcAddr, BmcCredentials, BmcEndpoint, BoxFuture, CredentialProvider, EndpointMetadata,
    EndpointSource, MachineData, PowerShelfData, SwitchData, SwitchEndpointRole,
};

#[derive(Clone)]
pub struct ApiClientWrapper {
    client: NicoApiClient,
}

#[derive(Clone)]
struct ApiCredentialProvider {
    client: NicoApiClient,
    kind: ApiCredentialKind,
}

#[derive(Clone)]
enum ApiCredentialKind {
    Bmc,
    SwitchNvosAdmin { switch_id: SwitchId },
}

impl CredentialProvider for ApiCredentialProvider {
    fn fetch_credentials<'a>(
        &'a self,
        endpoint: &'a BmcAddr,
    ) -> BoxFuture<'a, Result<BmcCredentials, HealthError>> {
        Box::pin(async move {
            let response = match &self.kind {
                ApiCredentialKind::Bmc => {
                    let request = rpc::nico::GetBmcCredentialsRequest {
                        mac_addr: endpoint.mac.to_string(),
                    };

                    self.client
                        .get_bmc_credentials(request)
                        .await
                        .map_err(HealthError::ApiInvocationError)?
                }
                ApiCredentialKind::SwitchNvosAdmin { switch_id } => {
                    let request = rpc::nico::GetSwitchNvosCredentialsRequest {
                        switch_id: Some(*switch_id),
                    };

                    self.client
                        .get_switch_nvos_credentials(request)
                        .await
                        .map_err(HealthError::ApiInvocationError)?
                }
            };

            response
                .credentials
                .and_then(|credentials| credentials.r#type)
                .map(Into::into)
                .ok_or_else(|| {
                    HealthError::GenericError("missing credentials in API response".to_string())
                })
        })
    }
}

fn switch_endpoint_metadata(
    switch: &rpc::nico::Switch,
    endpoint_role: SwitchEndpointRole,
    nmxt_enabled: bool,
) -> Result<EndpointMetadata, HealthError> {
    let serial = switch
        .config
        .as_ref()
        .map(|config| config.name.clone())
        .ok_or_else(|| HealthError::GenericError("switch endpoint does not have serial".into()))?;

    Ok(EndpointMetadata::Switch(SwitchData {
        id: switch.id,
        serial,
        slot_number: switch
            .placement_in_rack
            .as_ref()
            .and_then(|placement| placement.slot_number),
        tray_index: switch
            .placement_in_rack
            .as_ref()
            .and_then(|placement| placement.tray_index),
        endpoint_role,
        is_primary: switch.is_primary,
        nmxt_enabled,
    }))
}

impl ApiClientWrapper {
    pub fn new(root_ca: String, client_cert: String, client_key: String, api_url: &Url) -> Self {
        let client_config = NicoClientConfig::new(
            root_ca,
            Some(ClientCert {
                cert_path: client_cert,
                key_path: client_key,
            }),
        );
        let api_config = ApiConfig::new(api_url.as_str(), &client_config);

        let client = NicoApiClient::new(&api_config);

        Self { client }
    }

    pub async fn fetch_bmc_hosts(&self) -> Result<Vec<Arc<BmcEndpoint>>, HealthError> {
        let mut endpoints = self.fetch_machine_endpoints().await?;
        endpoints.extend(self.fetch_power_shelf_endpoints().await);
        endpoints.extend(self.fetch_switch_endpoints().await);

        tracing::info!("Prepared total {} endpoints", endpoints.len());

        Ok(endpoints)
    }

    async fn fetch_machine_endpoints(&self) -> Result<Vec<Arc<BmcEndpoint>>, HealthError> {
        let machine_ids = self
            .client
            .find_machine_ids(MachineSearchConfig {
                include_dpus: true,
                ..Default::default()
            })
            .await
            .map_err(HealthError::ApiInvocationError)?;

        tracing::info!("Found {} machines", machine_ids.machine_ids.len(),);

        let mut endpoints = Vec::new();

        for ids_chunk in machine_ids.machine_ids.chunks(100) {
            let request = ::rpc::nico::MachinesByIdsRequest {
                machine_ids: Vec::from(ids_chunk),
                ..Default::default()
            };
            let machines = self
                .client
                .find_machines_by_ids(request)
                .await
                .map_err(HealthError::ApiInvocationError)?;
            tracing::debug!(
                "Fetched details for {} machines with chunk size of 100",
                machines.machines.len(),
            );

            for machine in machines.machines {
                match self.extract_machine_endpoint(&machine).await {
                    Ok(endpoint) => endpoints.push(Arc::new(endpoint)),
                    Err(error) => tracing::warn!(
                        ?machine,
                        ?error,
                        "Could not add machine endpoint due to error"
                    ),
                }
            }
        }

        Ok(endpoints)
    }

    async fn fetch_switch_endpoints(&self) -> Vec<Arc<BmcEndpoint>> {
        let switch_request = rpc::nico::SwitchQuery {
            name: None,
            switch_id: None,
        };

        match self.client.find_switches(switch_request).await {
            Ok(response) => {
                let mut endpoints = Vec::new();

                for switch in response.switches {
                    match self.extract_switch_endpoint(&switch).await {
                        Ok(endpoint) => endpoints.push(Arc::new(endpoint)),
                        Err(error) => tracing::warn!(
                            ?switch,
                            ?error,
                            "Could not add switch endpoint due to error"
                        ),
                    }

                    match self.extract_switch_host_endpoint(&switch).await {
                        Ok(Some(endpoint)) => endpoints.push(Arc::new(endpoint)),
                        Ok(None) => {}
                        Err(error) => {
                            tracing::warn!(
                                ?switch,
                                ?error,
                                "Could not add switch host endpoint due to error"
                            );
                        }
                    }
                }

                tracing::debug!(count = endpoints.len(), "Fetched switch endpoints");
                endpoints
            }
            Err(error) => {
                tracing::warn!(?error, "Failed to fetch switch endpoints");
                Vec::new()
            }
        }
    }

    async fn fetch_power_shelf_endpoints(&self) -> Vec<Arc<BmcEndpoint>> {
        let request = rpc::nico::PowerShelfQuery {
            name: None,
            power_shelf_id: None,
        };

        match self.client.find_power_shelves(request).await {
            Ok(response) => {
                let mut endpoints = Vec::new();

                for power_shelf in response.power_shelves {
                    match self.extract_power_shelf_endpoint(&power_shelf).await {
                        Ok(endpoint) => endpoints.push(Arc::new(endpoint)),
                        Err(error) => tracing::warn!(
                            ?power_shelf,
                            ?error,
                            "Could not add power shelf endpoint due to error"
                        ),
                    }
                }

                tracing::debug!(count = endpoints.len(), "Fetched power shelf endpoints");
                endpoints
            }
            Err(error) => {
                tracing::warn!(?error, "Failed to fetch power shelf endpoints");
                Vec::new()
            }
        }
    }

    async fn extract_machine_endpoint(
        &self,
        machine: &rpc::nico::Machine,
    ) -> Result<BmcEndpoint, HealthError> {
        let Some(bmc_info) = &machine.bmc_info else {
            return Err(HealthError::GenericError(
                "Could not extract machine endpoint without BMC Info".to_string(),
            ));
        };
        let addr = BmcAddr::try_from(bmc_info)?;
        let metadata = machine.id.map(|machine_id| {
            EndpointMetadata::Machine(MachineData {
                machine_id,
                machine_serial: machine
                    .discovery_info
                    .as_ref()
                    .and_then(|info| info.dmi_data.as_ref())
                    .map(|dmi| dmi.chassis_serial.clone()),
                slot_number: machine
                    .placement_in_rack
                    .as_ref()
                    .and_then(|placement| placement.slot_number),
                tray_index: machine
                    .placement_in_rack
                    .as_ref()
                    .and_then(|placement| placement.tray_index),
                nvlink_domain_uuid: machine
                    .nvlink_info
                    .as_ref()
                    .and_then(|info| info.domain_uuid),
            })
        });

        self.endpoint_with_auth(
            addr,
            metadata,
            machine.rack_id.clone(),
            ApiCredentialKind::Bmc,
        )
        .await
    }

    async fn extract_switch_endpoint(
        &self,
        switch: &rpc::nico::Switch,
    ) -> Result<BmcEndpoint, HealthError> {
        let Some(bmc_info) = &switch.bmc_info else {
            return Err(HealthError::GenericError(
                "Could not extract switch endpoint without BMC Info".to_string(),
            ));
        };
        let addr = BmcAddr::try_from(bmc_info)?;

        self.endpoint_with_auth(
            addr,
            Some(switch_endpoint_metadata(
                switch,
                SwitchEndpointRole::Bmc,
                false,
            )?),
            switch.rack_id.clone(),
            ApiCredentialKind::Bmc,
        )
        .await
    }

    async fn extract_switch_host_endpoint(
        &self,
        switch: &rpc::nico::Switch,
    ) -> Result<Option<BmcEndpoint>, HealthError> {
        let Some(nvos_info) = switch.nvos_info.as_ref() else {
            return Ok(None);
        };
        let switch_id = switch.id.ok_or_else(|| {
            HealthError::GenericError("switch host endpoint missing switch ID".to_string())
        })?;
        let addr = BmcAddr::try_from(nvos_info)?;

        self.endpoint_with_auth(
            addr,
            Some(switch_endpoint_metadata(
                switch,
                SwitchEndpointRole::Host,
                switch.is_primary,
            )?),
            switch.rack_id.clone(),
            ApiCredentialKind::SwitchNvosAdmin { switch_id },
        )
        .await
        .map(Some)
    }

    async fn extract_power_shelf_endpoint(
        &self,
        power_shelf: &rpc::nico::PowerShelf,
    ) -> Result<BmcEndpoint, HealthError> {
        let Some(bmc_info) = &power_shelf.bmc_info else {
            return Err(HealthError::GenericError(
                "Could not extract power shelf endpoint without BMC Info".to_string(),
            ));
        };
        let addr = BmcAddr::try_from(bmc_info)?;
        let serial = power_shelf
            .config
            .as_ref()
            .map(|config| config.name.clone())
            .ok_or(HealthError::GenericError(
                "Power shelf endpoint does not have serial".to_string(),
            ))?;

        self.endpoint_with_auth(
            addr,
            Some(EndpointMetadata::PowerShelf(PowerShelfData {
                id: power_shelf.id,
                serial,
            })),
            None,
            ApiCredentialKind::Bmc,
        )
        .await
    }

    async fn endpoint_with_auth(
        &self,
        addr: BmcAddr,
        metadata: Option<EndpointMetadata>,
        rack_id: Option<RackId>,
        credential_kind: ApiCredentialKind,
    ) -> Result<BmcEndpoint, HealthError> {
        let provider = ApiCredentialProvider {
            client: self.client.clone(),
            kind: credential_kind,
        };

        let credentials = provider.fetch_credentials(&addr).await?;

        Ok(BmcEndpoint {
            addr,
            provider: Arc::new(provider),
            metadata,
            rack_id,
            credentials: Arc::new(RwLock::new(credentials)),
        })
    }

    pub async fn submit_health_report(
        &self,
        machine_id: &nico_uuid::machine::MachineId,
        report: health_report::HealthReport,
    ) -> Result<(), HealthError> {
        let ovrd = rpc::nico::HealthReportEntry {
            report: Some(report.into()),
            mode: rpc::nico::HealthReportApplyMode::Merge.into(),
        };

        let request = rpc::nico::InsertMachineHealthReportRequest {
            machine_id: Some(*machine_id),
            health_report_entry: Some(ovrd),
        };

        self.client
            .insert_machine_health_report(request)
            .await
            .map_err(HealthError::ApiInvocationError)?;

        Ok(())
    }

    pub async fn submit_rack_health_report(
        &self,
        rack_id: &nico_uuid::rack::RackId,
        report: health_report::HealthReport,
    ) -> Result<(), HealthError> {
        let ovrd = rpc::nico::HealthReportEntry {
            report: Some(report.into()),
            mode: rpc::nico::HealthReportApplyMode::Merge.into(),
        };

        let request = rpc::nico::InsertRackHealthReportRequest {
            rack_id: Some(rack_id.clone()),
            health_report_entry: Some(ovrd),
        };

        self.client
            .insert_rack_health_report(request)
            .await
            .map_err(HealthError::ApiInvocationError)?;

        Ok(())
    }

    pub async fn submit_switch_health_report(
        &self,
        switch_id: &nico_uuid::switch::SwitchId,
        report: health_report::HealthReport,
    ) -> Result<(), HealthError> {
        let ovrd = rpc::nico::HealthReportEntry {
            report: Some(report.into()),
            mode: rpc::nico::HealthReportApplyMode::Merge.into(),
        };

        let request = rpc::nico::InsertSwitchHealthReportRequest {
            switch_id: Some(*switch_id),
            health_report_entry: Some(ovrd),
        };

        self.client
            .insert_switch_health_report(request)
            .await
            .map_err(HealthError::ApiInvocationError)?;

        Ok(())
    }

    pub async fn submit_power_shelf_health_report(
        &self,
        power_shelf_id: &nico_uuid::power_shelf::PowerShelfId,
        report: health_report::HealthReport,
    ) -> Result<(), HealthError> {
        let ovrd = rpc::nico::HealthReportEntry {
            report: Some(report.into()),
            mode: rpc::nico::HealthReportApplyMode::Merge.into(),
        };

        let request = rpc::nico::InsertPowerShelfHealthReportRequest {
            power_shelf_id: Some(*power_shelf_id),
            health_report_entry: Some(ovrd),
        };

        self.client
            .insert_power_shelf_health_report(request)
            .await
            .map_err(HealthError::ApiInvocationError)?;

        Ok(())
    }
}

impl EndpointSource for ApiClientWrapper {
    fn fetch_bmc_hosts<'a>(&'a self) -> BoxFuture<'a, Result<Vec<Arc<BmcEndpoint>>, HealthError>> {
        Box::pin(self.fetch_bmc_hosts())
    }
}

impl TryFrom<&rpc::nico::BmcInfo> for BmcAddr {
    type Error = HealthError;

    fn try_from(bmc_info: &rpc::nico::BmcInfo) -> Result<Self, Self::Error> {
        let ip = bmc_info
            .ip
            .as_ref()
            .ok_or_else(|| HealthError::GenericError("missing BMC IP address".to_string()))?
            .parse::<IpAddr>()
            .map_err(|error| HealthError::GenericError(error.to_string()))?;
        let mac = bmc_info
            .mac
            .as_ref()
            .ok_or_else(|| HealthError::GenericError("missing BMC MAC address".to_string()))
            .and_then(|mac| {
                MacAddress::from_str(mac)
                    .map_err(|error| HealthError::GenericError(error.to_string()))
            })?;
        let port = bmc_info.port.map(|port| port.try_into().unwrap_or(443));

        Ok(Self { ip, port, mac })
    }
}

impl TryFrom<&rpc::nico::SwitchNvosInfo> for BmcAddr {
    type Error = HealthError;

    fn try_from(nvos_info: &rpc::nico::SwitchNvosInfo) -> Result<Self, Self::Error> {
        let ip = nvos_info
            .ip
            .as_ref()
            .ok_or_else(|| HealthError::GenericError("missing NVOS IP address".to_string()))?
            .parse::<IpAddr>()
            .map_err(|error| HealthError::GenericError(error.to_string()))?;
        let mac = nvos_info
            .mac
            .as_ref()
            .ok_or_else(|| HealthError::GenericError("missing NVOS MAC address".to_string()))
            .and_then(|mac| {
                MacAddress::from_str(mac)
                    .map_err(|error| HealthError::GenericError(error.to_string()))
            })?;
        let port = nvos_info.port.map(|port| port.try_into().unwrap_or(443));

        Ok(Self { ip, port, mac })
    }
}

impl From<rpc::nico::UsernamePassword> for BmcCredentials {
    fn from(value: rpc::nico::UsernamePassword) -> Self {
        Self::UsernamePassword {
            username: value.username,
            password: Some(value.password),
        }
    }
}

impl From<rpc::nico::SessionToken> for BmcCredentials {
    fn from(value: rpc::nico::SessionToken) -> Self {
        Self::SessionToken { token: value.token }
    }
}

impl From<rpc::nico::bmc_credentials::Type> for BmcCredentials {
    fn from(value: rpc::nico::bmc_credentials::Type) -> Self {
        match value {
            rpc::nico::bmc_credentials::Type::UsernamePassword(value) => value.into(),
            rpc::nico::bmc_credentials::Type::SessionToken(value) => value.into(),
        }
    }
}
