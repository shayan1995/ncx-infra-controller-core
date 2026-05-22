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

use model::rack::{Rack, RackSearchFilter, derive_rack_aggregate_health};

use crate as rpc;
use crate::Timestamp;
use crate::nico::LifecycleStatus;

impl From<Rack> for rpc::nico::Rack {
    fn from(value: Rack) -> Self {
        let health = derive_rack_aggregate_health(&value.health_reports);
        let health_sources = value
            .health_reports
            .iter()
            .map(|(hr, m)| rpc::nico::HealthSourceOrigin {
                mode: m as i32,
                source: hr.source.clone(),
            })
            .collect();

        let lifecycle = LifecycleStatus {
            state: serde_json::to_string(&value.controller_state.value).unwrap_or_default(),
            version: value.controller_state.version.version_string(),
            state_reason: value.controller_state_outcome.map(Into::into),
            sla: Some(rpc::nico::StateSla {
                sla: None, // TODO: Calculate SLA properly
                time_in_state_above_sla: false,
            }),
        };

        rpc::nico::Rack {
            id: Some(value.id),
            rack_state: value.controller_state.value.to_string(),
            created: Some(Timestamp::from(value.created)),
            updated: Some(Timestamp::from(value.updated)),
            deleted: value.deleted.map(Timestamp::from),
            metadata: Some(value.metadata.into()),
            version: value.version.version_string(),
            config: Some(rpc::nico::RackConfig {}),
            status: Some(rpc::nico::RackStatus {
                health: Some(health.into()),
                health_sources,
                lifecycle: Some(lifecycle),
            }),
        }
    }
}

impl From<rpc::nico::RackSearchFilter> for RackSearchFilter {
    fn from(filter: rpc::nico::RackSearchFilter) -> Self {
        RackSearchFilter {
            label: filter.label.map(model::metadata::LabelFilter::from),
        }
    }
}

#[cfg(test)]
mod tests {
    use model::rack::{LABEL_CHASSIS_MANUFACTURER, LABEL_LOCATION_DATACENTER};

    use super::*;

    #[test]
    fn rack_search_filter_from_rpc_with_label_key_and_value() {
        let rpc_filter = rpc::nico::RackSearchFilter {
            label: Some(rpc::nico::Label {
                key: LABEL_LOCATION_DATACENTER.to_string(),
                value: Some("az01".to_string()),
            }),
        };
        let filter = RackSearchFilter::from(rpc_filter);
        let label = filter.label.unwrap();
        assert_eq!(label.key, LABEL_LOCATION_DATACENTER);
        assert_eq!(label.value, Some("az01".to_string()));
    }

    #[test]
    fn rack_search_filter_from_rpc_with_label_key_only() {
        let rpc_filter = rpc::nico::RackSearchFilter {
            label: Some(rpc::nico::Label {
                key: LABEL_CHASSIS_MANUFACTURER.to_string(),
                value: None,
            }),
        };
        let filter = RackSearchFilter::from(rpc_filter);
        let label = filter.label.unwrap();
        assert_eq!(label.key, LABEL_CHASSIS_MANUFACTURER);
        assert!(label.value.is_none());
    }

    #[test]
    fn rack_search_filter_from_rpc_no_label() {
        let rpc_filter = rpc::nico::RackSearchFilter { label: None };
        let filter = RackSearchFilter::from(rpc_filter);
        assert!(filter.label.is_none());
    }
}
