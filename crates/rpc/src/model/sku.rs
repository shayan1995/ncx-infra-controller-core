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

use chrono::{DateTime, Utc};
use model::sku::{
    Sku, SkuComponentChassis, SkuComponentCpu, SkuComponentGpu, SkuComponentInfinibandDevices,
    SkuComponentMemory, SkuComponentStorage, SkuComponentTpm, SkuComponents, SkuStatus,
};

use crate as rpc;

impl From<Sku> for rpc::nico::Sku {
    fn from(value: Sku) -> Self {
        rpc::nico::Sku {
            schema_version: value.schema_version,
            id: value.id,
            description: Some(value.description),
            created: Some(value.created.into()),
            components: Some(value.components.into()),
            // filled in afterwards
            associated_machine_ids: Vec::default(),
            device_type: value.device_type,
        }
    }
}

impl From<rpc::nico::Sku> for Sku {
    fn from(value: rpc::nico::Sku) -> Self {
        Sku {
            schema_version: value.schema_version,
            id: value.id,
            description: value.description.unwrap_or_default(),
            // Handle optional created field - if not provided, use current time
            created: value
                .created
                .and_then(|t| DateTime::<Utc>::try_from(t).ok())
                .unwrap_or_else(Utc::now),
            components: value.components.unwrap_or_default().into(),
            device_type: value.device_type,
        }
    }
}

impl From<rpc::nico::SkuComponents> for SkuComponents {
    fn from(value: rpc::nico::SkuComponents) -> Self {
        SkuComponents {
            chassis: value.chassis.unwrap_or_default().into(),
            cpus: value
                .cpus
                .into_iter()
                .map(std::convert::Into::into)
                .collect(),
            gpus: value
                .gpus
                .into_iter()
                .map(std::convert::Into::into)
                .collect(),
            memory: value
                .memory
                .into_iter()
                .map(std::convert::Into::into)
                .collect(),
            infiniband_devices: value
                .infiniband_devices
                .into_iter()
                .map(std::convert::Into::into)
                .collect(),
            storage: value
                .storage
                .into_iter()
                .map(std::convert::Into::into)
                .collect(),
            tpm: value.tpm.map(std::convert::Into::into),
        }
    }
}

impl From<SkuComponents> for rpc::nico::SkuComponents {
    fn from(value: SkuComponents) -> Self {
        rpc::nico::SkuComponents {
            chassis: Some(value.chassis.into()),
            cpus: value
                .cpus
                .into_iter()
                .map(std::convert::Into::into)
                .collect(),
            gpus: value
                .gpus
                .into_iter()
                .map(std::convert::Into::into)
                .collect(),
            ethernet_devices: Vec::default(),
            infiniband_devices: value
                .infiniband_devices
                .into_iter()
                .map(std::convert::Into::into)
                .collect(),
            storage: value
                .storage
                .into_iter()
                .map(std::convert::Into::into)
                .collect(),
            memory: value
                .memory
                .into_iter()
                .map(std::convert::Into::into)
                .collect(),
            tpm: value.tpm.map(std::convert::Into::into),
        }
    }
}

impl From<rpc::nico::SkuComponentChassis> for SkuComponentChassis {
    fn from(value: rpc::nico::SkuComponentChassis) -> Self {
        SkuComponentChassis {
            vendor: value.vendor,
            model: value.model,
            architecture: value.architecture,
        }
    }
}

impl From<SkuComponentChassis> for rpc::nico::SkuComponentChassis {
    fn from(value: SkuComponentChassis) -> Self {
        rpc::nico::SkuComponentChassis {
            vendor: value.vendor,
            model: value.model,
            architecture: value.architecture,
        }
    }
}

impl From<rpc::nico::SkuComponentCpu> for SkuComponentCpu {
    fn from(value: rpc::nico::SkuComponentCpu) -> Self {
        SkuComponentCpu {
            vendor: value.vendor,
            model: value.model,
            count: value.count,
            thread_count: value.thread_count,
        }
    }
}

impl From<SkuComponentCpu> for rpc::nico::SkuComponentCpu {
    fn from(value: SkuComponentCpu) -> Self {
        rpc::nico::SkuComponentCpu {
            vendor: value.vendor,
            model: value.model,
            count: value.count,
            thread_count: value.thread_count,
        }
    }
}

impl From<rpc::nico::SkuComponentGpu> for SkuComponentGpu {
    fn from(value: rpc::nico::SkuComponentGpu) -> Self {
        SkuComponentGpu {
            vendor: value.vendor,
            model: value.model,
            total_memory: value.total_memory,
            count: value.count,
        }
    }
}

impl From<SkuComponentGpu> for rpc::nico::SkuComponentGpu {
    fn from(value: SkuComponentGpu) -> Self {
        rpc::nico::SkuComponentGpu {
            vendor: value.vendor,
            model: value.model,
            total_memory: value.total_memory,
            count: value.count,
        }
    }
}

impl From<rpc::nico::SkuComponentMemory> for SkuComponentMemory {
    fn from(value: rpc::nico::SkuComponentMemory) -> Self {
        SkuComponentMemory {
            memory_type: value.memory_type,
            capacity_mb: value.capacity_mb,
            count: value.count,
        }
    }
}

impl From<SkuComponentMemory> for rpc::nico::SkuComponentMemory {
    fn from(value: SkuComponentMemory) -> Self {
        rpc::nico::SkuComponentMemory {
            memory_type: value.memory_type,
            capacity_mb: value.capacity_mb,
            count: value.count,
        }
    }
}

impl From<rpc::nico::SkuComponentInfinibandDevices> for SkuComponentInfinibandDevices {
    fn from(value: rpc::nico::SkuComponentInfinibandDevices) -> Self {
        SkuComponentInfinibandDevices {
            vendor: value.vendor,
            model: value.model,
            count: value.count,
            inactive_devices: value.inactive_devices,
        }
    }
}

impl From<SkuComponentInfinibandDevices> for rpc::nico::SkuComponentInfinibandDevices {
    fn from(value: SkuComponentInfinibandDevices) -> Self {
        rpc::nico::SkuComponentInfinibandDevices {
            vendor: value.vendor,
            model: value.model,
            count: value.count,
            inactive_devices: value.inactive_devices,
        }
    }
}

impl From<rpc::nico::SkuComponentStorage> for SkuComponentStorage {
    fn from(value: rpc::nico::SkuComponentStorage) -> Self {
        SkuComponentStorage {
            model: value.model,
            count: value.count,
        }
    }
}

impl From<SkuComponentStorage> for rpc::nico::SkuComponentStorage {
    fn from(value: SkuComponentStorage) -> Self {
        rpc::nico::SkuComponentStorage {
            vendor: String::default(),
            model: value.model,
            capacity_mb: 0u32,
            count: value.count,
        }
    }
}

impl From<rpc::nico::SkuComponentTpm> for SkuComponentTpm {
    fn from(value: rpc::nico::SkuComponentTpm) -> Self {
        SkuComponentTpm {
            vendor: value.vendor,
            version: value.version,
        }
    }
}

impl From<SkuComponentTpm> for rpc::nico::SkuComponentTpm {
    fn from(value: SkuComponentTpm) -> Self {
        rpc::nico::SkuComponentTpm {
            vendor: value.vendor,
            version: value.version,
        }
    }
}

impl From<rpc::nico::SkuStatus> for SkuStatus {
    fn from(value: rpc::nico::SkuStatus) -> Self {
        let verify_request_time = value
            .verify_request_time
            .map(|t| DateTime::<Utc>::try_from(t).unwrap_or_default());
        let last_match_attempt = value
            .last_match_attempt
            .map(|t| DateTime::<Utc>::try_from(t).unwrap_or_default());
        let last_generate_attempt = value
            .last_generate_attempt
            .map(|t| DateTime::<Utc>::try_from(t).unwrap_or_default());

        SkuStatus {
            verify_request_time,
            last_match_attempt,
            last_generate_attempt,
        }
    }
}

impl From<SkuStatus> for rpc::nico::SkuStatus {
    fn from(value: SkuStatus) -> Self {
        rpc::nico::SkuStatus {
            verify_request_time: value.verify_request_time.map(|t| t.into()),
            last_match_attempt: value.last_match_attempt.map(|t| t.into()),
            last_generate_attempt: value.last_generate_attempt.map(|t| t.into()),
        }
    }
}
