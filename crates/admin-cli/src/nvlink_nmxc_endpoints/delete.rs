/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

use ::rpc::nico::DeleteNvlinkNmxcEndpointRequest;
use clap::Parser;

use crate::cfg::run::Run;
use crate::cfg::runtime::RuntimeContext;
use crate::errors::{NicoCliError, NicoCliResult};

#[derive(Parser, Debug)]
pub struct Args {
    #[clap(long, value_name = "SERIAL")]
    pub chassis_serial: String,
}

impl Run for Args {
    async fn run(self, ctx: &mut RuntimeContext) -> NicoCliResult<()> {
        if self.chassis_serial.is_empty() {
            return Err(NicoCliError::GenericError(
                "chassis_serial must not be empty".to_string(),
            ));
        }
        let serial = self.chassis_serial.clone();
        let req = DeleteNvlinkNmxcEndpointRequest {
            chassis_serial: self.chassis_serial,
        };
        ctx.api_client
            .0
            .delete_nvlink_nmxc_endpoint(req)
            .await
            .map_err(|e| NicoCliError::GenericError(e.to_string()))?;
        println!("deleted {serial}");
        Ok(())
    }
}
