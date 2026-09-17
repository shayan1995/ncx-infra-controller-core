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

//! RMS routing through `run`: fake machine-a-tron instances declare their racks on
//! `/racks/status` and serve the RMS mock, and an unmodified `librms` client talks to the gateway.

use std::net::SocketAddr;

use axum::http::StatusCode;
use librms::protos::rack_manager::rack_manager_client::RackManagerClient;
use librms::protos::rack_manager::{
    BatchGetNodeDeviceInfoRequest, ConfigureSwitchCertificateRequest, Endpoint,
    GetConfigureSwitchCertificateJobStatusRequest, GetJobStatusRequest,
    GetScaleUpFabricStatusRequest, GetVersionRequest, JobExecutionState, ListRacksRequest,
    NetworkInterface, NodeInfo, NodeSet, ReturnCode,
};
use mac_address::MacAddress;
use mat_protocol_gateway::{ExitReason, RMS_VERSION};
use rms_mock::{SimNode, SimNodeKind};
use tokio_util::sync::CancellationToken;
use tonic::Code;
use tonic::transport::Channel;

use crate::common::{
    FakeController, FakeMachineATron, GUID_A, GUID_B, finished, free_loopback_address,
    gateway_config, probe, spawn_run, wait_until,
};

const SWITCH_A: [u8; 6] = [0x02, 0x00, 0x11, 0x11, 0x22, 0x22];
const TRAY_A: [u8; 6] = [0x02, 0x00, 0xab, 0xcd, 0x12, 0x34];
const SWITCH_B: [u8; 6] = [0x02, 0x00, 0x22, 0x22, 0x33, 0x33];

fn device(kind: SimNodeKind, mac: [u8; 6], rack_id: &str, slot: u32) -> SimNode {
    SimNode {
        kind: Some(kind),
        bmc_mac: Some(MacAddress::new(mac)),
        rack_id: Some(rack_id.to_string()),
        slot_number: Some(slot),
        tray_index: (kind == SimNodeKind::Compute).then_some(2),
        ..SimNode::default()
    }
}

/// The devices of the instance owning `rack-001`: a switch and a compute tray.
fn devices_a() -> Vec<SimNode> {
    vec![
        device(SimNodeKind::Switch, SWITCH_A, "rack-001", 30),
        device(SimNodeKind::Compute, TRAY_A, "rack-001", 12),
    ]
}

/// The devices of the instance owning `rack-002`: one switch.
fn devices_b() -> Vec<SimNode> {
    vec![device(SimNodeKind::Switch, SWITCH_B, "rack-002", 30)]
}

/// A node the way NICo names it: an opaque id, its rack, and the BMC MAC the mock matches on.
fn node(node_id: &str, rack_id: &str, mac: [u8; 6]) -> NodeInfo {
    NodeInfo {
        node_id: node_id.to_string(),
        rack_id: rack_id.to_string(),
        bmc_endpoint: Some(Endpoint {
            interface: Some(NetworkInterface {
                ip_address: String::new(),
                mac_address: MacAddress::new(mac).to_string(),
                host_name: None,
            }),
            port: 443,
            credentials: None,
        }),
        ..NodeInfo::default()
    }
}

fn nodes(nodes: Vec<NodeInfo>) -> Option<NodeSet> {
    Some(NodeSet { nodes })
}

async fn rms_client(gateway: SocketAddr) -> RackManagerClient<Channel> {
    RackManagerClient::connect(format!("http://{gateway}"))
        .await
        .expect("the gateway listener speaks gRPC")
}

/// Status and body of `/readyz`; `None` while nothing answers.
async fn readyz(client: &reqwest::Client, gateway: SocketAddr) -> Option<(StatusCode, String)> {
    let response = client
        .get(format!("http://{gateway}/readyz"))
        .send()
        .await
        .ok()?;
    let status = response.status();
    Some((status, response.text().await.unwrap()))
}

async fn wait_until_ready(http: &reqwest::Client, gateway: SocketAddr) {
    wait_until("the gateway reports ready", || async {
        probe(http, gateway, "/readyz").await == Some(StatusCode::OK)
    })
    .await;
}

/// `GetScaleUpFabricStatus` for one switch of `rack_id`, the rack-scoped call NICo makes.
async fn fabric_status(
    rms: &mut RackManagerClient<Channel>,
    rack_id: &str,
    mac: [u8; 6],
) -> Result<String, tonic::Status> {
    let response = rms
        .get_scale_up_fabric_status(GetScaleUpFabricStatusRequest {
            nodes: nodes(vec![node("switch", rack_id, mac)]),
            ..GetScaleUpFabricStatusRequest::default()
        })
        .await?
        .into_inner();
    assert_eq!(response.status, ReturnCode::Success as i32);
    let switches = response.fabric_status.expect("fabric status").switches;
    assert_eq!(switches.len(), 1);
    assert_eq!(switches[0].node_id, "switch");
    Ok(switches[0].error_message.clone())
}

/// A rack-scoped call reaches the instance owning the rack, a batch spanning two instances is
/// split and merged back in request order with the node nobody owns failed in place, and the
/// batch's certificate jobs poll to completion through gateway ids, the aggregate parent first.
#[tokio::test]
async fn rms_requests_are_routed_by_rack_and_batches_split_across_instances_are_merged() {
    let mat_a =
        FakeMachineATron::start_with_racks("mat-a", &[GUID_A], &["rack-001"], devices_a()).await;
    let mat_b =
        FakeMachineATron::start_with_racks("mat-b", &[GUID_B], &["rack-002"], devices_b()).await;
    let controller = FakeController::new(vec![mat_a.source(), mat_b.source()], 1);
    let listen = free_loopback_address().await;
    let config = gateway_config(controller.serve().await, listen);
    let http = reqwest::Client::new();
    let shutdown = CancellationToken::new();
    let running = spawn_run(config, shutdown.clone());
    wait_until_ready(&http, listen).await;
    let mut rms = rms_client(listen).await;

    let version = rms.get_version(GetVersionRequest {}).await.unwrap();
    assert_eq!(version.into_inner().version, RMS_VERSION);

    // Rack-scoped: the mock on mat-b knows the switch, the one on mat-a would report it unmatched.
    assert_eq!(
        fabric_status(&mut rms, "rack-002", SWITCH_B).await.unwrap(),
        ""
    );
    let status = rms
        .get_scale_up_fabric_status(GetScaleUpFabricStatusRequest {
            nodes: nodes(vec![
                node("s1", "rack-001", SWITCH_A),
                node("s2", "rack-002", SWITCH_B),
            ]),
            ..GetScaleUpFabricStatusRequest::default()
        })
        .await
        .expect_err("a rack-scoped call over two racks is refused");
    assert_eq!(status.code(), Code::InvalidArgument);

    // Batch across both instances plus a node whose rack nobody simulates.
    let response = rms
        .batch_get_node_device_info(BatchGetNodeDeviceInfoRequest {
            nodes: nodes(vec![
                node("t1", "rack-001", TRAY_A),
                node("s2", "rack-002", SWITCH_B),
                node("x", "rack-999", [0x02, 0, 0, 0, 0, 0x99]),
            ]),
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(response.status, ReturnCode::Failure as i32);
    let details: Vec<(&str, Option<u32>, Option<u32>)> = response
        .node_device_details
        .iter()
        .map(|detail| {
            (
                detail.node_id.as_str(),
                detail.slot_number,
                detail.tray_index,
            )
        })
        .collect();
    assert_eq!(
        details,
        vec![("t1", Some(12), Some(2)), ("s2", Some(30), None)],
        "details come back in request order, only for nodes an instance knows"
    );
    let stats = response.stats.unwrap();
    assert_eq!(
        (
            stats.total_nodes,
            stats.successful_nodes,
            stats.failed_nodes
        ),
        (3, 2, 1)
    );
    assert!(
        response
            .message
            .contains("node x: no machine-a-tron instance owns rack \"rack-999\""),
        "{}",
        response.message
    );

    // A batch with jobs: one per switch and one aggregate parent for the two instances' parents.
    let response = rms
        .configure_switch_certificate(ConfigureSwitchCertificateRequest {
            nodes: nodes(vec![
                node("s1", "rack-001", SWITCH_A),
                node("s2", "rack-002", SWITCH_B),
            ]),
            services: Vec::new(),
            test_hello: false,
            domain: Some("site.example.com".to_string()),
        })
        .await
        .unwrap()
        .into_inner();
    let batch = response.response.unwrap();
    assert_eq!(batch.status, ReturnCode::Success as i32);
    assert_eq!(batch.stats.unwrap().failed_nodes, 0);
    let job_ids: Vec<&str> = response
        .jobs
        .iter()
        .map(|job| job.job_id.as_str())
        .collect();
    assert_eq!(
        response
            .jobs
            .iter()
            .map(|job| job.node_id.as_str())
            .collect::<Vec<_>>(),
        vec!["s1", "s2"]
    );
    assert!(
        job_ids
            .iter()
            .chain([&batch.job_id.as_str()])
            .all(|id| id.starts_with("gw-")),
        "every id handed out is a gateway id: {job_ids:?}, {}",
        batch.job_id
    );
    assert_ne!(
        job_ids[0], job_ids[1],
        "equal mock ids on two instances are two jobs"
    );
    assert!(
        !job_ids.contains(&batch.job_id.as_str()),
        "the batch id is the aggregate"
    );

    // The aggregate parent is running while any part is, lists the parts as children, and is
    // complete once every part is (the mock completes a job on its second poll).
    for expected in [JobExecutionState::Running, JobExecutionState::Completed] {
        let states = rms
            .get_job_status(GetJobStatusRequest {
                job_id: batch.job_id.clone(),
                include_child_job_states: true,
            })
            .await
            .unwrap()
            .into_inner()
            .job_states;
        assert_eq!(states[0].job_id, batch.job_id);
        assert_eq!(states[0].execution_state, expected as i32, "{states:?}");
        assert_eq!(states[0].child_job_ids, job_ids);
        assert_eq!(states.len(), 3, "children follow the parent: {states:?}");
        assert!(
            states[1..]
                .iter()
                .all(
                    |child| child.parent_job_id.as_deref() == Some(batch.job_id.as_str())
                        && child.execution_state == expected as i32
                ),
            "{states:?}"
        );
    }
    let response = rms
        .get_configure_switch_certificate_job_status(
            GetConfigureSwitchCertificateJobStatusRequest {
                job_id: job_ids[0].to_string(),
            },
        )
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        response.job_id, job_ids[0],
        "the gateway id is echoed, not the mock's"
    );
    assert_eq!(response.state, "completed");

    // An id from before a restart is unknown to this process and reported complete, as the mock
    // does; an RPC the mock does not implement is not routed.
    let states = rms
        .get_job_status(GetJobStatusRequest {
            job_id: "gw-0-999".to_string(),
            include_child_job_states: true,
        })
        .await
        .unwrap()
        .into_inner()
        .job_states;
    assert_eq!(states.len(), 1);
    assert_eq!(states[0].job_id, "gw-0-999");
    assert_eq!(
        states[0].execution_state,
        JobExecutionState::Completed as i32
    );
    let status = rms
        .list_racks(ListRacksRequest::default())
        .await
        .expect_err("not routed");
    assert_eq!(status.code(), Code::Unimplemented);
    assert!(
        status.message().contains("does not route list_racks"),
        "{status}"
    );

    shutdown.cancel();
    assert_eq!(finished(running).await, ExitReason::Shutdown);
}

/// Two instances reporting one rack is a conflict: `/readyz` names it, routed RPCs are refused
/// rather than sent to either instance, and both clear once one instance stops reporting it.
#[tokio::test]
async fn a_rack_reported_by_two_instances_blocks_readiness_and_routing_until_one_withdraws() {
    let mat_a = FakeMachineATron::start_with_racks(
        "mat-a",
        &[GUID_A],
        &["rack-001", "rack-shared"],
        devices_a(),
    )
    .await;
    let mat_b = FakeMachineATron::start_with_racks(
        "mat-b",
        &[GUID_B],
        &["rack-002", "rack-shared"],
        devices_b(),
    )
    .await;
    let controller = FakeController::new(vec![mat_a.source(), mat_b.source()], 1);
    let listen = free_loopback_address().await;
    let config = gateway_config(controller.serve().await, listen);
    let http = reqwest::Client::new();
    let shutdown = CancellationToken::new();
    let running = spawn_run(config, shutdown.clone());

    wait_until("the gateway explains the conflict", || async {
        readyz(&http, listen)
            .await
            .is_some_and(|(_, body)| body.starts_with("rack "))
    })
    .await;
    assert_eq!(
        readyz(&http, listen).await,
        Some((
            StatusCode::SERVICE_UNAVAILABLE,
            "rack rack-shared is reported by mat-a, mat-b".to_string()
        ))
    );
    let mut rms = rms_client(listen).await;
    let status = fabric_status(&mut rms, "rack-001", SWITCH_A)
        .await
        .expect_err("nothing is routed while ownership is conflicted");
    assert_eq!(status.code(), Code::Unavailable);

    mat_b.set_racks(&["rack-002"]);
    wait_until_ready(&http, listen).await;
    assert_eq!(
        fabric_status(&mut rms, "rack-shared", SWITCH_A)
            .await
            .unwrap(),
        ""
    );
    assert_eq!(
        fabric_status(&mut rms, "rack-002", SWITCH_B).await.unwrap(),
        ""
    );

    shutdown.cancel();
    assert_eq!(finished(running).await, ExitReason::Shutdown);
}

/// An instance whose status routes stop answering keeps its racks for `stale_after` and then
/// loses them: rack-scoped calls are `UNAVAILABLE` naming it, batch nodes fail in place, nothing
/// is redirected, `/readyz` stays 200, and the racks return with the instance.
#[tokio::test]
async fn a_source_that_stops_answering_keeps_its_racks_until_stale_after_then_answers_unavailable()
{
    let mat_a =
        FakeMachineATron::start_with_racks("mat-a", &[GUID_A], &["rack-001"], devices_a()).await;
    let mat_b =
        FakeMachineATron::start_with_racks("mat-b", &[GUID_B], &["rack-002"], devices_b()).await;
    let controller = FakeController::new(vec![mat_a.source(), mat_b.source()], 1);
    let listen = free_loopback_address().await;
    let config = gateway_config(controller.serve().await, listen);
    let http = reqwest::Client::new();
    let shutdown = CancellationToken::new();
    let running = spawn_run(config, shutdown.clone());
    wait_until_ready(&http, listen).await;
    let mut rms = rms_client(listen).await;

    mat_b.set_available(false);
    assert_eq!(
        fabric_status(&mut rms, "rack-002", SWITCH_B).await.unwrap(),
        "",
        "the last answer keeps routing while the source is merely stale"
    );
    wait_until("mat-b is dropped from routing", || async {
        fabric_status(&mut rms_client(listen).await, "rack-002", SWITCH_B)
            .await
            .is_err()
    })
    .await;
    let status = fabric_status(&mut rms, "rack-002", SWITCH_B)
        .await
        .unwrap_err();
    assert_eq!(status.code(), Code::Unavailable);
    assert!(
        status
            .message()
            .contains("machine-a-tron mat-b owns rack \"rack-002\""),
        "{status}"
    );
    assert_eq!(probe(&http, listen, "/readyz").await, Some(StatusCode::OK));

    let response = rms
        .batch_get_node_device_info(BatchGetNodeDeviceInfoRequest {
            nodes: nodes(vec![
                node("t1", "rack-001", TRAY_A),
                node("s2", "rack-002", SWITCH_B),
            ]),
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        response
            .node_device_details
            .iter()
            .map(|detail| detail.node_id.as_str())
            .collect::<Vec<_>>(),
        vec!["t1"]
    );
    let stats = response.stats.unwrap();
    assert_eq!(
        (
            stats.total_nodes,
            stats.successful_nodes,
            stats.failed_nodes
        ),
        (2, 1, 1)
    );
    assert!(
        response
            .message
            .contains("node s2: machine-a-tron mat-b owns rack"),
        "{}",
        response.message
    );

    mat_b.set_available(true);
    wait_until("mat-b routes again", || async {
        fabric_status(&mut rms_client(listen).await, "rack-002", SWITCH_B)
            .await
            .is_ok()
    })
    .await;

    shutdown.cancel();
    assert_eq!(finished(running).await, ExitReason::Shutdown);
}

/// An instance that is down when the gateway starts holds `/readyz` and routing, naming itself,
/// only until `stale_after`; then the rest of the fleet is served and its racks are unknown until
/// it answers.
#[tokio::test]
async fn a_source_down_at_startup_blocks_readiness_only_until_stale_after() {
    let mat_a =
        FakeMachineATron::start_with_racks("mat-a", &[GUID_A], &["rack-001"], devices_a()).await;
    let mat_b =
        FakeMachineATron::start_with_racks("mat-b", &[GUID_B], &["rack-002"], devices_b()).await;
    mat_b.set_available(false);
    let controller = FakeController::new(vec![mat_a.source(), mat_b.source()], 1);
    let listen = free_loopback_address().await;
    let config = gateway_config(controller.serve().await, listen);
    let http = reqwest::Client::new();
    let shutdown = CancellationToken::new();
    let running = spawn_run(config, shutdown.clone());

    wait_until("the gateway names the pending source", || async {
        readyz(&http, listen)
            .await
            .is_some_and(|(_, body)| body.starts_with("no rack status"))
    })
    .await;
    let (status, body) = readyz(&http, listen).await.unwrap();
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        body.starts_with("no rack status from source mat-b yet: GET http://"),
        "{body}"
    );
    let mut rms = rms_client(listen).await;
    assert_eq!(
        fabric_status(&mut rms, "rack-001", SWITCH_A)
            .await
            .unwrap_err()
            .code(),
        Code::Unavailable
    );

    wait_until_ready(&http, listen).await;
    assert_eq!(
        fabric_status(&mut rms, "rack-001", SWITCH_A).await.unwrap(),
        ""
    );
    let status = fabric_status(&mut rms, "rack-002", SWITCH_B)
        .await
        .unwrap_err();
    assert_eq!(status.code(), Code::NotFound, "{status}");

    mat_b.set_available(true);
    wait_until("mat-b's rack is owned", || async {
        fabric_status(&mut rms_client(listen).await, "rack-002", SWITCH_B)
            .await
            .is_ok()
    })
    .await;

    shutdown.cancel();
    assert_eq!(finished(running).await, ExitReason::Shutdown);
}
