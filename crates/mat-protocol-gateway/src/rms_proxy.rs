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

//! The RMS routing proxy: one `RackManager` and `RackManagerV2` front for the whole fleet.
//!
//! Every machine-a-tron instance serves the RMS mock for the racks it simulates. NICo is
//! configured with one RMS endpoint, so the gateway implements both services itself and forwards
//! each request by the rack its nodes name, as decided by [`Ownership`]:
//!
//! - Rack-scoped RPCs (`GetScaleUpFabricStatus`, `RackManagerV2.ConfigureScaleUpFabricManager`)
//!   go to the owner of the one rack the nodes belong to, unchanged.
//! - Node batches are split by rack owner, forwarded concurrently and merged back in request
//!   order. A node whose rack nobody owns is a per-node failure and is never sent to an arbitrary
//!   instance; an instance that fails a call fails only its own nodes.
//! - Job ids in every response are replaced by gateway ids from [`JobMap`], and the job status
//!   RPCs resolve their id through the same map. A batch split across instances gets one
//!   aggregate parent whose status is the worst, least advanced of the per-instance parents. An
//!   id the map does not know is reported complete, as the RMS mock does for ids it never issued.
//! - `GetVersion` is answered locally. Every RPC the RMS mock does not implement is
//!   `UNIMPLEMENTED` here as well.
//!
//! Until the source list is bound and ownership is ready, routed RPCs answer `UNAVAILABLE`.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::sync::{Arc, RwLock};

use axum::Router;
use futures::future::join_all;
use librms::protos::rack_manager::rack_manager_client::RackManagerClient;
use librms::protos::rack_manager::rack_manager_server::{RackManager, RackManagerServer};
use librms::protos::rack_manager_v2::rack_manager_v2_client::RackManagerV2Client;
use librms::protos::rack_manager_v2::rack_manager_v2_server::{RackManagerV2, RackManagerV2Server};
use librms::protos::{rack_manager as rms, rack_manager_v2 as rms_v2};
use tonic::server::NamedService;
use tonic::transport::Channel;
use tonic::{Request, Response, Status};

use crate::config::{RmsConfig, SourceClientConfig};
use crate::ownership::{Owner, Ownership, SourceId};
use crate::rms_client::BackendConnector;
use crate::rms_jobs::{BackendJob, JobMap, JobPhase, JobRecord};
use crate::sources::SourceList;

/// What `GetVersion` reports; `librms` probes new connections with it.
pub const RMS_VERSION: &str = concat!("mat-protocol-gateway/", env!("CARGO_PKG_VERSION"));

/// The stubs for one machine-a-tron instance.
#[derive(Clone)]
struct Backend {
    source: SourceId,
    v1: RackManagerClient<Channel>,
    v2: RackManagerV2Client<Channel>,
}

type Backends = Arc<HashMap<SourceId, Backend>>;

/// Routes RMS requests to the instances of the bound source set.
pub(crate) struct RmsProxy {
    ownership: Arc<dyn Ownership>,
    connector: BackendConnector,
    backends: RwLock<Option<Backends>>,
    jobs: JobMap,
}

impl RmsProxy {
    /// A proxy with no instances yet; [`Self::bind_sources`] adds them once the controller's list
    /// is known. The CA file named by `sources` is read here.
    pub(crate) fn new(
        ownership: Arc<dyn Ownership>,
        sources: &SourceClientConfig,
        rms: &RmsConfig,
    ) -> eyre::Result<Self> {
        Ok(Self {
            ownership,
            connector: BackendConnector::new(sources, rms)?,
            backends: RwLock::new(None),
            jobs: JobMap::new(),
        })
    }

    /// Points the proxy at the instances of `list`. Connections are opened by the first forwarded
    /// request, so an unreachable instance is reported per request rather than here.
    pub(crate) fn bind_sources(&self, list: &SourceList) -> eyre::Result<()> {
        let mut backends = HashMap::with_capacity(list.sources.len());
        for source in &list.sources {
            let channel = self.connector.channel(&source.base_url)?;
            let id = SourceId::from(source);
            backends.insert(
                id.clone(),
                Backend {
                    source: id,
                    v1: RackManagerClient::new(channel.clone()),
                    v2: RackManagerV2Client::new(channel),
                },
            );
        }
        tracing::info!(sources = ?list.names(), "Routing RMS requests to the controller source set");
        *self
            .backends
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(Arc::new(backends));
        Ok(())
    }

    fn backends(&self) -> Result<Backends, Status> {
        self.backends
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
            .ok_or_else(|| {
                Status::unavailable("the gateway is waiting for the controller source list")
            })
    }

    fn backend(&self, source: &SourceId) -> Result<Backend, Status> {
        self.backends()?.get(source).cloned().ok_or_else(|| {
            Status::failed_precondition(format!(
                "machine-a-tron {source} is not in the gateway source set"
            ))
        })
    }

    fn ensure_ownership_ready(&self) -> Result<(), Status> {
        if self.ownership.is_ready() {
            Ok(())
        } else {
            Err(Status::unavailable(
                "the gateway has not learned which machine-a-tron instance owns each rack yet",
            ))
        }
    }

    /// Groups the nodes of a batch by the instance owning their rack, in order of first
    /// appearance; nodes without a routable owner are kept with the reason.
    fn split(&self, nodes: &[rms::NodeInfo]) -> Result<Split, Status> {
        self.ensure_ownership_ready()?;
        let backends = self.backends()?;
        let mut groups: Vec<Group> = Vec::new();
        let mut unowned = Vec::new();
        for (index, node) in nodes.iter().enumerate() {
            let owner = match self.rack_owner_of(node) {
                Ok(owner) => owner,
                Err(reason) => {
                    unowned.push((index, reason));
                    continue;
                }
            };
            let Some(backend) = backends.get(&owner) else {
                unowned.push((
                    index,
                    format!("machine-a-tron {owner} owns rack {:?} but is not in the gateway source set", node.rack_id),
                ));
                continue;
            };
            match groups
                .iter_mut()
                .find(|group| group.backend.source == owner)
            {
                Some(group) => group.indices.push(index),
                None => groups.push(Group {
                    backend: backend.clone(),
                    indices: vec![index],
                }),
            }
        }
        Ok(Split { groups, unowned })
    }

    /// The instance simulating the rack `node` names, or why there is none.
    fn rack_owner_of(&self, node: &rms::NodeInfo) -> Result<SourceId, String> {
        if node.rack_id.trim().is_empty() {
            return Err(format!("node {:?} names no rack", node.node_id));
        }
        match self.ownership.owner_of_rack(&node.rack_id) {
            Owner::Source(source) => Ok(source),
            Owner::Dropped(source) => Err(format!(
                "machine-a-tron {source} owns rack {:?} but has not answered its status polls for ownership.stale_after; retry once it answers",
                node.rack_id
            )),
            Owner::Ambiguous(sources) => Err(format!(
                "rack {:?} is reported by machine-a-tron instances {}",
                node.rack_id,
                sources
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(" and ")
            )),
            Owner::Unknown => Err(format!(
                "no machine-a-tron instance owns rack {:?}",
                node.rack_id
            )),
        }
    }

    /// The single instance a rack-scoped request goes to. Every node must name the same owner's
    /// rack: the RMS operations routed this way act on one rack, so a request spanning instances
    /// is a caller error, a dropped owner is `UNAVAILABLE` and an unknown rack `NOT_FOUND`.
    fn rack_owner(&self, nodes: &[rms::NodeInfo]) -> Result<Backend, Status> {
        self.ensure_ownership_ready()?;
        let Some(first) = nodes.first() else {
            return Err(Status::invalid_argument("the request names no nodes"));
        };
        let owner = self.rack_owner_of(first).map_err(|reason| {
            match self.ownership.owner_of_rack(&first.rack_id) {
                Owner::Dropped(_) => Status::unavailable(reason),
                Owner::Ambiguous(_) => Status::invalid_argument(reason),
                Owner::Source(_) | Owner::Unknown => Status::not_found(reason),
            }
        })?;
        for node in &nodes[1..] {
            if self.rack_owner_of(node).as_ref() != Ok(&owner) {
                return Err(Status::invalid_argument(format!(
                    "the nodes span rack {:?} on machine-a-tron {owner} and rack {:?}; a rack-scoped request must name one rack",
                    first.rack_id, node.rack_id
                )));
            }
        }
        self.backend(&owner)
    }

    /// Forwards one batch to every owning instance at once. `call` performs the RPC on an
    /// instance and the subset of `nodes` it owns; a failing instance is kept as a failed part so
    /// the merge can report its nodes individually.
    async fn fan_out<T, F, Fut>(
        &self,
        nodes: &[rms::NodeInfo],
        call: F,
    ) -> Result<FanOut<T>, Status>
    where
        F: Fn(Backend, Vec<rms::NodeInfo>) -> Fut,
        Fut: Future<Output = Result<T, Status>>,
    {
        let split = self.split(nodes)?;
        let calls = split.groups.into_iter().map(|group| {
            let subset = group
                .indices
                .iter()
                .map(|&index| nodes[index].clone())
                .collect();
            let source = group.backend.source.clone();
            let future = call(group.backend, subset);
            async move {
                Part {
                    source,
                    indices: group.indices,
                    outcome: future.await,
                }
            }
        });
        Ok(FanOut {
            parts: join_all(calls).await,
            unowned: split.unowned,
        })
    }

    /// Merges the per-instance batch envelopes back into one, in request order.
    ///
    /// The caller checks the batch status, the per-node results and `stats.failed_nodes`
    /// independently, so all three are derived from the same merged results. The batch job id is
    /// the gateway id for whatever parents the instances issued.
    fn merge_batches<T>(
        &self,
        nodes: &[rms::NodeInfo],
        fan: &FanOut<T>,
        envelope: impl Fn(&T) -> Option<&rms::NodeBatchResponse>,
    ) -> rms::NodeBatchResponse {
        let mut results: Vec<Option<rms::NodeOperationResult>> = vec![None; nodes.len()];
        let mut messages = Vec::new();
        let mut parents = Vec::new();
        for part in &fan.parts {
            let batch = match &part.outcome {
                Ok(response) => envelope(response),
                Err(status) => {
                    let reason = backend_failure(&part.source, status);
                    messages.push(reason.clone());
                    for &index in &part.indices {
                        results[index] = Some(failed(&nodes[index].node_id, reason.clone()));
                    }
                    continue;
                }
            };
            let Some(batch) = batch else {
                let reason = format!("machine-a-tron {} returned no batch response", part.source);
                messages.push(reason.clone());
                for &index in &part.indices {
                    results[index] = Some(failed(&nodes[index].node_id, reason.clone()));
                }
                continue;
            };
            let answers = correlate(nodes, &part.indices, &batch.node_results, |result| {
                &result.node_id
            });
            for (&index, answer) in part.indices.iter().zip(answers) {
                results[index] = Some(answer.cloned().unwrap_or_else(|| {
                    failed(
                        &nodes[index].node_id,
                        format!(
                            "machine-a-tron {} returned no result for this node",
                            part.source
                        ),
                    )
                }));
            }
            if !batch.message.is_empty() {
                messages.push(format!("machine-a-tron {}: {}", part.source, batch.message));
            }
            if !batch.job_id.is_empty() {
                parents.push(BackendJob {
                    source: part.source.clone(),
                    job_id: batch.job_id.clone(),
                });
            }
        }
        for (index, reason) in &fan.unowned {
            results[*index] = Some(failed(&nodes[*index].node_id, reason.clone()));
        }

        let node_results: Vec<rms::NodeOperationResult> = results.into_iter().flatten().collect();
        let total = node_results.len() as u32;
        let failed_nodes = node_results
            .iter()
            .filter(|result| result.status != rms::ReturnCode::Success as i32)
            .count() as u32;
        if failed_nodes > 0 && messages.is_empty() {
            messages.push(format!("{failed_nodes} of {total} nodes failed"));
        }
        rms::NodeBatchResponse {
            status: return_code(failed_nodes == 0),
            message: messages.join("; "),
            node_results,
            job_id: self.jobs.batch_id(parents),
            stats: Some(rms::NodeOperationStats {
                total_nodes: total,
                successful_nodes: total - failed_nodes,
                failed_nodes,
            }),
        }
    }

    /// An id this process does not know is reported complete, as the RMS mock does for ids it
    /// never issued: the gateway forgets its table on restart and after the retention, and NICo
    /// persists job ids across both.
    fn resolve_job(&self, gateway_job_id: &str) -> Result<Option<JobRecord>, Status> {
        if gateway_job_id.is_empty() {
            return Err(Status::not_found("the request names no job id"));
        }
        let record = self.jobs.resolve(gateway_job_id);
        if record.is_none() {
            tracing::warn!(
                job_id = gateway_job_id,
                "Reporting an unknown job as complete"
            );
        }
        Ok(record)
    }

    /// Rewrites the ids of one instance's `JobStatus` to gateway ids. A per-instance parent that
    /// was folded into an aggregate reports the aggregate as its parent.
    fn translate_job_status(
        &self,
        source: &SourceId,
        mut status: rms::JobStatus,
    ) -> rms::JobStatus {
        let aggregate = self.jobs.aggregate_of(&BackendJob {
            source: source.clone(),
            job_id: status.job_id.clone(),
        });
        status.job_id = self.jobs.intern(source, &status.job_id);
        status.parent_job_id = aggregate.or_else(|| {
            status
                .parent_job_id
                .as_deref()
                .filter(|parent| !parent.is_empty())
                .map(|parent| self.jobs.intern(source, parent))
        });
        status.child_job_ids = status
            .child_job_ids
            .iter()
            .map(|child| self.jobs.intern(source, child))
            .collect();
        status
    }

    /// Polls the per-instance parents of an aggregate, failing on the first instance error.
    async fn poll_parts<T, F, Fut>(&self, parts: &[BackendJob], call: F) -> Result<Vec<T>, Status>
    where
        F: Fn(Backend, String) -> Fut,
        Fut: Future<Output = Result<T, Status>>,
    {
        let call = &call;
        let polls = parts.iter().map(|part| {
            let backend = self.backend(&part.source);
            let job_id = part.job_id.clone();
            async move {
                let backend = backend?;
                let source = backend.source.clone();
                call(backend, job_id)
                    .await
                    .map_err(|status| backend_error(&source, status))
            }
        });
        join_all(polls).await.into_iter().collect()
    }
}

/// Both RMS gRPC services, served by `proxy`, on the paths `librms` clients call.
///
/// Mounted as plain `tower` services like `rms_mock::router` does, so the UFM router's fallback
/// survives the merge, with the paths taken from each service's `NamedService::NAME`.
pub(crate) fn router(proxy: Arc<RmsProxy>) -> Router {
    let v1_path = format!(
        "/{}/{{*rpc}}",
        <RackManagerServer<RmsProxy> as NamedService>::NAME
    );
    let v2_path = format!(
        "/{}/{{*rpc}}",
        <RackManagerV2Server<RmsProxy> as NamedService>::NAME
    );
    Router::new()
        .route_service(&v1_path, RackManagerServer::from_arc(proxy.clone()))
        .route_service(&v2_path, RackManagerV2Server::from_arc(proxy))
}

/// A batch's nodes grouped by owning instance.
struct Group {
    backend: Backend,
    indices: Vec<usize>,
}

struct Split {
    groups: Vec<Group>,
    /// Request indices with no routable owner, and why.
    unowned: Vec<(usize, String)>,
}

/// One instance's share of a fanned-out batch.
struct Part<T> {
    source: SourceId,
    indices: Vec<usize>,
    outcome: Result<T, Status>,
}

struct FanOut<T> {
    parts: Vec<Part<T>>,
    unowned: Vec<(usize, String)>,
}

/// Pairs the request entries of one part (`indices` into `nodes`) with the entries an instance
/// answered for them.
///
/// When the part's request node ids are distinct and non-empty the answers are matched by node
/// id, which tolerates an instance answering in another order. NICo can send the same node id
/// twice, or none at all, and then a match by id would hand two nodes the same answer; in that
/// case the answers are taken in request order, which is how the mock returns them, and a count
/// mismatch leaves the part's nodes unmatched rather than guessing.
fn correlate<'a, E>(
    nodes: &[rms::NodeInfo],
    indices: &[usize],
    entries: &'a [E],
    node_id: impl Fn(&E) -> &str,
) -> Vec<Option<&'a E>> {
    let requested: Vec<&str> = indices
        .iter()
        .map(|&index| nodes[index].node_id.as_str())
        .collect();
    let distinct = requested.iter().all(|id| !id.is_empty())
        && requested.iter().collect::<HashSet<_>>().len() == requested.len();
    if distinct {
        let by_id: HashMap<&str, &E> = entries
            .iter()
            .map(|entry| (node_id(entry), entry))
            .collect();
        requested.iter().map(|id| by_id.get(id).copied()).collect()
    } else if entries.len() == indices.len() {
        entries.iter().map(Some).collect()
    } else {
        vec![None; indices.len()]
    }
}

fn requested_nodes(nodes: &Option<rms::NodeSet>) -> Vec<rms::NodeInfo> {
    nodes
        .as_ref()
        .map(|set| set.nodes.clone())
        .unwrap_or_default()
}

fn return_code(success: bool) -> i32 {
    if success {
        rms::ReturnCode::Success as i32
    } else {
        rms::ReturnCode::Failure as i32
    }
}

fn failed(node_id: &str, error_message: String) -> rms::NodeOperationResult {
    rms::NodeOperationResult {
        node_id: node_id.to_owned(),
        status: rms::ReturnCode::Failure as i32,
        error_message,
    }
}

fn backend_failure(source: &SourceId, status: &Status) -> String {
    format!(
        "machine-a-tron {source}: {} ({:?})",
        status.message(),
        status.code()
    )
}

fn backend_error(source: &SourceId, status: Status) -> Status {
    Status::new(
        status.code(),
        format!("machine-a-tron {source}: {}", status.message()),
    )
}

/// The non-empty error messages of an aggregate's parts, each attributed to its instance.
fn join_errors<'a>(errors: impl IntoIterator<Item = (&'a SourceId, &'a str)>) -> String {
    errors
        .into_iter()
        .filter(|(_, message)| !message.is_empty())
        .map(|(source, message)| format!("machine-a-tron {source}: {message}"))
        .collect::<Vec<_>>()
        .join("; ")
}

/// Builds the whole `RackManager` impl.
///
/// Every generated method must exist, so the ones the gateway does not route are generated to
/// return `UNIMPLEMENTED`; a `librms` bump that adds an RPC fails to compile here. The macro
/// emits the `async_trait` attribute itself: attribute macros expand before the function-like
/// macros in their body, so a nested invocation would leave plain `async fn`s the trait cannot
/// accept.
macro_rules! rack_manager_impl {
    (
        routed { $($routed:tt)* }
        unimplemented { $($method:ident($request:ident) -> $response:ident,)* }
    ) => {
        #[tonic::async_trait]
        impl RackManager for RmsProxy {
            $($routed)*

            $(
                /// Not implemented by the RMS mock, so not routed by the gateway.
                async fn $method(
                    &self,
                    _request: Request<rms::$request>,
                ) -> Result<Response<rms::$response>, Status> {
                    Err(Status::unimplemented(concat!(
                        "the machine-a-tron protocol gateway does not route ",
                        stringify!($method),
                    )))
                }
            )*
        }
    };
}

rack_manager_impl! {
    routed {
        /// Answered locally: this is the connection probe, and it must not depend on any
        /// instance being reachable.
        async fn get_version(
            &self,
            _request: Request<rms::GetVersionRequest>,
        ) -> Result<Response<rms::GetVersionResponse>, Status> {
            Ok(Response::new(rms::GetVersionResponse {
                version: RMS_VERSION.to_owned(),
            }))
        }

        /// Rack-scoped: forwarded unchanged to the rack's owner.
        async fn get_scale_up_fabric_status(
            &self,
            request: Request<rms::GetScaleUpFabricStatusRequest>,
        ) -> Result<Response<rms::GetScaleUpFabricStatusResponse>, Status> {
            let request = request.into_inner();
            let mut backend = self.rack_owner(&requested_nodes(&request.nodes))?;
            backend
                .v1
                .get_scale_up_fabric_status(request)
                .await
                .map_err(|status| backend_error(&backend.source, status))
        }

        /// Node batch; device details are only returned for nodes an instance knows.
        async fn batch_get_node_device_info(
            &self,
            request: Request<rms::BatchGetNodeDeviceInfoRequest>,
        ) -> Result<Response<rms::BatchGetNodeDeviceInfoResponse>, Status> {
            let request = request.into_inner();
            let nodes = requested_nodes(&request.nodes);
            let fan = self
                .fan_out(&nodes, |mut backend, subset| {
                    let mut part = request.clone();
                    part.nodes = Some(rms::NodeSet { nodes: subset });
                    async move {
                        backend
                            .v1
                            .batch_get_node_device_info(part)
                            .await
                            .map(Response::into_inner)
                    }
                })
                .await?;

            let mut details: Vec<Option<rms::NodeDeviceInfo>> = vec![None; nodes.len()];
            let mut messages = Vec::new();
            let mut successful = 0u32;
            for part in &fan.parts {
                match &part.outcome {
                    Err(status) => messages.push(backend_failure(&part.source, status)),
                    Ok(response) => {
                        let answers = correlate(
                            &nodes,
                            &part.indices,
                            &response.node_device_details,
                            |detail| &detail.node_id,
                        );
                        for (&index, answer) in part.indices.iter().zip(answers) {
                            details[index] = answer.cloned();
                        }
                        successful += response.stats.as_ref().map_or_else(
                            || response.node_device_details.len() as u32,
                            |stats| stats.successful_nodes,
                        );
                        if !response.message.is_empty() {
                            messages.push(format!(
                                "machine-a-tron {}: {}",
                                part.source, response.message
                            ));
                        }
                    }
                }
            }
            for (index, reason) in &fan.unowned {
                messages.push(format!("node {}: {reason}", nodes[*index].node_id));
            }
            let total = nodes.len() as u32;
            let successful = successful.min(total);
            let failed_nodes = total - successful;
            if failed_nodes > 0 && messages.is_empty() {
                messages.push(format!("{failed_nodes} of {total} nodes failed"));
            }
            Ok(Response::new(rms::BatchGetNodeDeviceInfoResponse {
                status: return_code(failed_nodes == 0),
                message: messages.join("; "),
                node_device_details: details.into_iter().flatten().collect(),
                stats: Some(rms::NodeOperationStats {
                    total_nodes: total,
                    successful_nodes: successful,
                    failed_nodes,
                }),
            }))
        }

        /// Node batch; the per-switch map is the union of the instances' maps, and a node nobody
        /// answered for gets an entry carrying the reason.
        async fn batch_get_scale_up_fabric_service_status(
            &self,
            request: Request<rms::BatchGetScaleUpFabricServiceStatusRequest>,
        ) -> Result<Response<rms::BatchGetScaleUpFabricServiceStatusResponse>, Status> {
            let request = request.into_inner();
            let nodes = requested_nodes(&request.nodes);
            let fan = self
                .fan_out(&nodes, |mut backend, subset| {
                    let mut part = request.clone();
                    part.nodes = Some(rms::NodeSet { nodes: subset });
                    async move {
                        backend
                            .v1
                            .batch_get_scale_up_fabric_service_status(part)
                            .await
                            .map(Response::into_inner)
                    }
                })
                .await?;

            let error_entry = |error_message: String| rms::ScaleUpFabricServiceStatusEntry {
                status_json: String::new(),
                error_message,
            };
            let mut service_statuses = HashMap::with_capacity(nodes.len());
            let mut all_succeeded = true;
            for part in &fan.parts {
                match &part.outcome {
                    Err(status) => {
                        all_succeeded = false;
                        let reason = backend_failure(&part.source, status);
                        for &index in &part.indices {
                            service_statuses
                                .insert(nodes[index].node_id.clone(), error_entry(reason.clone()));
                        }
                    }
                    Ok(response) => {
                        all_succeeded &= response.status == rms::ReturnCode::Success as i32;
                        for &index in &part.indices {
                            let node_id = &nodes[index].node_id;
                            let entry = response.service_statuses.get(node_id).cloned().unwrap_or_else(
                                || {
                                    error_entry(format!(
                                        "machine-a-tron {} returned no status for this node",
                                        part.source
                                    ))
                                },
                            );
                            service_statuses.insert(node_id.clone(), entry);
                        }
                    }
                }
            }
            for (index, reason) in &fan.unowned {
                service_statuses.insert(nodes[*index].node_id.clone(), error_entry(reason.clone()));
            }
            let total = nodes.len() as u32;
            let failed_nodes = service_statuses
                .values()
                .filter(|entry| !entry.error_message.is_empty())
                .count() as u32;
            Ok(Response::new(rms::BatchGetScaleUpFabricServiceStatusResponse {
                status: return_code(all_succeeded && failed_nodes == 0),
                service_statuses,
                stats: Some(rms::NodeOperationStats {
                    total_nodes: total,
                    successful_nodes: total.saturating_sub(failed_nodes),
                    failed_nodes,
                }),
            }))
        }

        /// Node batch returning a per-switch job each; the batch job id is the gateway parent.
        async fn configure_switch_certificate(
            &self,
            request: Request<rms::ConfigureSwitchCertificateRequest>,
        ) -> Result<Response<rms::ConfigureSwitchCertificateResponse>, Status> {
            let request = request.into_inner();
            let nodes = requested_nodes(&request.nodes);
            let fan = self
                .fan_out(&nodes, |mut backend, subset| {
                    let mut part = request.clone();
                    part.nodes = Some(rms::NodeSet { nodes: subset });
                    async move {
                        backend
                            .v1
                            .configure_switch_certificate(part)
                            .await
                            .map(Response::into_inner)
                    }
                })
                .await?;

            let mut jobs: Vec<Option<rms::ConfigureSwitchCertificateJobInfo>> = vec![None; nodes.len()];
            for part in &fan.parts {
                let Ok(response) = &part.outcome else {
                    continue;
                };
                let answers = correlate(&nodes, &part.indices, &response.jobs, |job| &job.node_id);
                for (&index, answer) in part.indices.iter().zip(answers) {
                    jobs[index] = answer.map(|job| rms::ConfigureSwitchCertificateJobInfo {
                        node_id: job.node_id.clone(),
                        job_id: self.jobs.intern(&part.source, &job.job_id),
                    });
                }
            }
            Ok(Response::new(rms::ConfigureSwitchCertificateResponse {
                response: Some(self.merge_batches(&nodes, &fan, |r| r.response.as_ref())),
                jobs: jobs.into_iter().flatten().collect(),
            }))
        }

        /// Resolves the gateway job id. A single-instance job is forwarded and its ids rewritten;
        /// an aggregate polls every per-instance parent and reports the worst, least advanced of
        /// them, listing the parents as its children; an unknown id is reported complete.
        async fn get_job_status(
            &self,
            request: Request<rms::GetJobStatusRequest>,
        ) -> Result<Response<rms::GetJobStatusResponse>, Status> {
            let request = request.into_inner();
            let include_children = request.include_child_job_states;
            match self.resolve_job(&request.job_id)? {
                None => Ok(Response::new(rms::GetJobStatusResponse {
                    job_states: vec![rms::JobStatus {
                        job_id: request.job_id,
                        execution_state: JobPhase::Completed.execution_state(),
                        state_description: JobPhase::Completed.wire_str().to_owned(),
                        ..rms::JobStatus::default()
                    }],
                })),
                Some(JobRecord::Single(job)) => {
                    let mut backend = self.backend(&job.source)?;
                    let response = backend
                        .v1
                        .get_job_status(rms::GetJobStatusRequest {
                            job_id: job.job_id.clone(),
                            include_child_job_states: include_children,
                        })
                        .await
                        .map_err(|status| backend_error(&job.source, status))?
                        .into_inner();
                    Ok(Response::new(rms::GetJobStatusResponse {
                        job_states: response
                            .job_states
                            .into_iter()
                            .map(|status| self.translate_job_status(&job.source, status))
                            .collect(),
                    }))
                }
                Some(JobRecord::Aggregate(parts)) => {
                    let responses = self
                        .poll_parts(&parts, |mut backend, job_id| async move {
                            backend
                                .v1
                                .get_job_status(rms::GetJobStatusRequest {
                                    job_id,
                                    include_child_job_states: include_children,
                                })
                                .await
                                .map(Response::into_inner)
                        })
                        .await?;

                    // Each part's own status is the entry for the id that was polled; an instance
                    // that echoes nothing usable counts as unknown, never as done.
                    let own: Vec<rms::JobStatus> = parts
                        .iter()
                        .zip(&responses)
                        .map(|(part, response)| {
                            response
                                .job_states
                                .iter()
                                .find(|status| status.job_id == part.job_id)
                                .or_else(|| response.job_states.first())
                                .cloned()
                                .unwrap_or_else(|| rms::JobStatus {
                                    job_id: part.job_id.clone(),
                                    ..rms::JobStatus::default()
                                })
                        })
                        .collect();
                    let phases: Vec<JobPhase> = own
                        .iter()
                        .map(|status| JobPhase::from_execution_state(status.execution_state))
                        .collect();
                    let deciding = &own[JobPhase::deciding_index(&phases).unwrap_or_default()];

                    let parent = rms::JobStatus {
                        job_id: request.job_id.clone(),
                        parent_job_id: None,
                        child_job_ids: parts
                            .iter()
                            .map(|part| self.jobs.intern(&part.source, &part.job_id))
                            .collect(),
                        execution_state: deciding.execution_state,
                        error_message: join_errors(
                            parts
                                .iter()
                                .zip(&own)
                                .map(|(part, status)| (&part.source, status.error_message.as_str())),
                        ),
                        error_code: deciding.error_code,
                        result_json: String::new(),
                        state_description: deciding.state_description.clone(),
                        rack_id: deciding.rack_id.clone(),
                        node_id: None,
                        created_at: None,
                        updated_at: None,
                    };

                    let mut job_states = vec![parent];
                    if include_children {
                        for (part, response) in parts.iter().zip(responses) {
                            job_states.extend(
                                response
                                    .job_states
                                    .into_iter()
                                    .map(|status| self.translate_job_status(&part.source, status)),
                            );
                        }
                    }
                    Ok(Response::new(rms::GetJobStatusResponse { job_states }))
                }
            }
        }

        /// Resolves the gateway job id like [`RackManager::get_job_status`], with the state spelled
        /// as a string.
        async fn get_configure_switch_certificate_job_status(
            &self,
            request: Request<rms::GetConfigureSwitchCertificateJobStatusRequest>,
        ) -> Result<Response<rms::GetConfigureSwitchCertificateJobStatusResponse>, Status> {
            let gateway_job_id = request.into_inner().job_id;
            let poll = |mut backend: Backend, job_id: String| async move {
                backend
                    .v1
                    .get_configure_switch_certificate_job_status(
                        rms::GetConfigureSwitchCertificateJobStatusRequest { job_id },
                    )
                    .await
                    .map(Response::into_inner)
            };
            match self.resolve_job(&gateway_job_id)? {
                None => Ok(Response::new(rms::GetConfigureSwitchCertificateJobStatusResponse {
                    status: return_code(true),
                    job_id: gateway_job_id,
                    state: JobPhase::Completed.wire_str().to_owned(),
                    ..rms::GetConfigureSwitchCertificateJobStatusResponse::default()
                })),
                Some(JobRecord::Single(job)) => {
                    let backend = self.backend(&job.source)?;
                    let mut response = poll(backend, job.job_id)
                        .await
                        .map_err(|status| backend_error(&job.source, status))?;
                    response.job_id = gateway_job_id;
                    Ok(Response::new(response))
                }
                Some(JobRecord::Aggregate(parts)) => {
                    let responses = self.poll_parts(&parts, poll).await?;
                    let phases: Vec<JobPhase> = responses
                        .iter()
                        .map(|response| JobPhase::from_wire_str(&response.state))
                        .collect();
                    let deciding = &responses[JobPhase::deciding_index(&phases).unwrap_or_default()];
                    let all_found = responses
                        .iter()
                        .all(|response| response.status == rms::ReturnCode::Success as i32);
                    Ok(Response::new(rms::GetConfigureSwitchCertificateJobStatusResponse {
                        status: return_code(all_found),
                        job_id: gateway_job_id,
                        state: deciding.state.clone(),
                        message: deciding.message.clone(),
                        rack_id: deciding.rack_id.clone(),
                        node_id: String::new(),
                        error_message: join_errors(
                            parts
                                .iter()
                                .zip(&responses)
                                .map(|(part, response)| (&part.source, response.error_message.as_str())),
                        ),
                        result_json: String::new(),
                        created_at: None,
                        updated_at: None,
                    }))
                }
            }
        }
    }

    unimplemented {
        set_power_state(SetPowerStateRequest) -> SetPowerStateResponse,
        batch_set_power_state(BatchSetPowerStateRequest) -> BatchSetPowerStateResponse,
        get_power_state(GetPowerStateRequest) -> GetPowerStateResponse,
        batch_get_power_state(BatchGetPowerStateRequest) -> BatchGetPowerStateResponse,
        sequence_rack_power(SequenceRackPowerRequest) -> SequenceRackPowerResponse,
        list_node_inventory(ListNodeInventoryRequest) -> ListNodeInventoryResponse,
        create_nodes(CreateNodesRequest) -> CreateNodesResponse,
        update_node(UpdateNodeRequest) -> UpdateNodeResponse,
        delete_node(DeleteNodeRequest) -> DeleteNodeResponse,
        get_rack_power_on_sequence(GetRackPowerOnSequenceRequest) -> GetRackPowerOnSequenceResponse,
        set_rack_power_on_sequence(SetRackPowerOnSequenceRequest) -> SetRackPowerOnSequenceResponse,
        list_racks(ListRacksRequest) -> ListRacksResponse,
        get_node_device_info(GetNodeDeviceInfoRequest) -> GetNodeDeviceInfoResponse,
        list_node_device_info_by_node_type(ListNodeDeviceInfoByNodeTypeRequest) -> ListNodeDeviceInfoByNodeTypeResponse,
        get_node_firmware_inventory(GetNodeFirmwareInventoryRequest) -> GetNodeFirmwareInventoryResponse,
        update_firmware(UpdateFirmwareRequest) -> UpdateFirmwareResponse,
        batch_update_firmware_by_node_type(BatchUpdateFirmwareByNodeTypeRequest) -> BatchUpdateFirmwareByNodeTypeResponse,
        batch_update_firmware(BatchUpdateFirmwareRequest) -> BatchUpdateFirmwareResponse,
        update_switch_system_image(UpdateSwitchSystemImageRequest) -> UpdateSwitchSystemImageResponse,
        get_rack_firmware_inventory(GetRackFirmwareInventoryRequest) -> GetRackFirmwareInventoryResponse,
        add_firmware_object(AddFirmwareObjectRequest) -> AddFirmwareObjectResponse,
        get_firmware_object(GetFirmwareObjectRequest) -> GetFirmwareObjectResponse,
        list_firmware_objects(ListFirmwareObjectsRequest) -> ListFirmwareObjectsResponse,
        delete_firmware_object(DeleteFirmwareObjectRequest) -> DeleteFirmwareObjectResponse,
        set_default_firmware_object(SetDefaultFirmwareObjectRequest) -> SetDefaultFirmwareObjectResponse,
        apply_stored_firmware_object(ApplyStoredFirmwareObjectRequest) -> ApplyStoredFirmwareObjectResponse,
        apply_firmware_object(ApplyFirmwareObjectRequest) -> ApplyFirmwareObjectResponse,
        apply_switch_system_image(ApplySwitchSystemImageRequest) -> ApplySwitchSystemImageResponse,
        apply_stored_switch_system_image(ApplyStoredSwitchSystemImageRequest) -> ApplyStoredSwitchSystemImageResponse,
        get_firmware_object_history(GetFirmwareObjectHistoryRequest) -> GetFirmwareObjectHistoryResponse,
        list_switch_firmware(ListSwitchFirmwareRequest) -> ListSwitchFirmwareResponse,
        push_switch_firmware(PushSwitchFirmwareRequest) -> PushSwitchFirmwareResponse,
        batch_reset_switch_factory_default(BatchResetSwitchFactoryDefaultRequest) -> BatchResetSwitchFactoryDefaultResponse,
        configure_scale_up_fabric_manager(ConfigureScaleUpFabricManagerRequest) -> ConfigureScaleUpFabricManagerResponse,
        batch_reset_switch_sdn_factory_default(BatchResetSwitchSdnFactoryDefaultRequest) -> BatchResetSwitchSdnFactoryDefaultResponse,
        get_scale_up_fabric_state(GetScaleUpFabricStateRequest) -> GetScaleUpFabricStateResponse,
        batch_set_scale_up_fabric_state(BatchSetScaleUpFabricStateRequest) -> BatchSetScaleUpFabricStateResponse,
        set_scale_up_fabric_telemetry_interface_state(SetScaleUpFabricTelemetryInterfaceStateRequest) -> SetScaleUpFabricTelemetryInterfaceStateResponse,
        batch_disable_switch_mtls(BatchDisableSwitchMtlsRequest) -> BatchDisableSwitchMtlsResponse,
        list_switch_system_images(ListSwitchSystemImagesRequest) -> ListSwitchSystemImagesResponse,
        get_switch_system_image_job_status(GetSwitchSystemImageJobStatusRequest) -> GetSwitchSystemImageJobStatusResponse,
        update_switch_system_password(UpdateSwitchSystemPasswordRequest) -> UpdateSwitchSystemPasswordResponse,
        get_firmware_job_status(GetFirmwareJobStatusRequest) -> GetFirmwareJobStatusResponse,
    }
}

#[tonic::async_trait]
impl RackManagerV2 for RmsProxy {
    /// Rack-scoped: forwarded to the rack's owner, with the job id it returns mapped to a gateway
    /// id that `GetJobStatus` resolves.
    async fn configure_scale_up_fabric_manager(
        &self,
        request: Request<rms_v2::ConfigureScaleUpFabricManagerRequest>,
    ) -> Result<Response<rms_v2::ConfigureScaleUpFabricManagerResponse>, Status> {
        let request = request.into_inner();
        let mut backend = self.rack_owner(&requested_nodes(&request.nodes))?;
        let response = backend
            .v2
            .configure_scale_up_fabric_manager(request)
            .await
            .map_err(|status| backend_error(&backend.source, status))?
            .into_inner();
        Ok(Response::new(
            rms_v2::ConfigureScaleUpFabricManagerResponse {
                job_id: self.jobs.intern(&backend.source, &response.job_id),
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(node_id: &str) -> rms::NodeInfo {
        rms::NodeInfo {
            node_id: node_id.to_owned(),
            ..rms::NodeInfo::default()
        }
    }

    fn result(node_id: &str, error_message: &str) -> rms::NodeOperationResult {
        rms::NodeOperationResult {
            node_id: node_id.to_owned(),
            status: rms::ReturnCode::Success as i32,
            error_message: error_message.to_owned(),
        }
    }

    fn messages<'a>(answers: &[Option<&'a rms::NodeOperationResult>]) -> Vec<Option<&'a str>> {
        answers
            .iter()
            .map(|answer| answer.map(|result| result.error_message.as_str()))
            .collect()
    }

    #[test]
    fn answers_are_matched_by_node_id_when_distinct_and_by_position_otherwise() {
        let nodes = [node("n1"), node("n2"), node("n3")];
        let answers = [result("n3", "third"), result("n1", "first")];
        let matched = correlate(&nodes, &[0, 2, 1], &answers, |r| &r.node_id);
        assert_eq!(
            messages(&matched),
            vec![Some("first"), Some("third"), None],
            "n2 was not answered and stays unmatched"
        );

        let nodes = [node("dup"), node("dup"), node("")];
        let answers = [result("dup", "a"), result("dup", "b")];
        let matched = correlate(&nodes, &[0, 1], &answers, |r| &r.node_id);
        assert_eq!(messages(&matched), vec![Some("a"), Some("b")]);
        let answers = [result("", "x")];
        let matched = correlate(&nodes, &[2], &answers, |r| &r.node_id);
        assert_eq!(messages(&matched), vec![Some("x")]);

        let answers = [result("dup", "only one")];
        let matched = correlate(&nodes, &[0, 1], &answers, |r| &r.node_id);
        assert_eq!(
            messages(&matched),
            vec![None, None],
            "a count mismatch without distinct ids matches nothing"
        );
    }
}
