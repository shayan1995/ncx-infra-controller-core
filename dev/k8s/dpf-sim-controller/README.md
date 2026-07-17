# dpf-sim-controller

A **development-only** simulator for the DOCA Platform Framework (DPF) operator,
built to let machine-a-tron simulated fleets progress past the `dpuinit`
machine state without real BlueField hardware or a real DPF install.

Tracking issue: [NVIDIA/infra-controller#3323](https://github.com/NVIDIA/infra-controller/issues/3323).

## What it does

In a real deployment NICo drives DPU provisioning through DPF like this:

```
NICo (machine-controller/handler/dpf.rs)          DPF operator
  ── creates DPUDevice + DPUNode CRs ───────────►  watches them
                                                   creates a DPU CR
  watches DPU.status.phase  ◄────────────────────  walks phase:
                                                     Initializing → … → Ready
  when phase == "Rebooting":                        sets Rebooting + reboot annotation
    reboots host via Redfish (→ machine-a-tron)
    calls reboot_complete (clears annotation) ────► resumes → Ready
  when phase == "Ready": machine leaves dpuinit
```

There is **no** real DPF on a machine-a-tron simulation cluster (`dpf.enabled=true`
on every machine, zero DPU CRDs installed), so simulated hosts wedge in
`dpuinit` forever. This controller plays the operator's half:
it watches the `DPUDevice`/`DPUNode` CRs NICo creates and drives a matching
`DPU` CR through the authentic phase sequence, honoring the node-effect hold
and the reboot round-trip that NICo's state machine depends on.

It is a **simulator**, not the operator: no BFB is flashed, no ARM OS boots,
no DPU cluster is joined. Only the CR status transitions NICo observes are
reproduced, on a configurable per-phase timer.

## Why Go + reuse from doca-platform

Per the #3323 discussion, this is a controller-runtime job and the CR types
come straight from the upstream module — no hand-written schema, no codegen,
no drift:

```go
import provisioningv1 "github.com/nvidia/doca-platform/api/provisioning/v1alpha1"
```

`github.com/nvidia/doca-platform/api/provisioning/v1alpha1` exports typed
structs + deepcopy + scheme registration for `DPU`, `DPUDevice`, `DPUNode`,
`DPUNodeMaintenance`, `BFB`, `DPUFlavor`, `DPUSet` (group
`provisioning.dpu.nvidia.com`), and the full `DPUPhase` constant set the
simulator walks. The real operator's per-phase logic lives in
`internal/provisioning/controllers/dpu/state/` upstream (one file per phase) —
not importable (`internal/`), but the definitive reference for entry/exit
criteria of each phase.

> **Pin the dependency** to the doca-platform release whose CRDs match the ones
> NICo ships in `crates/dpf/crds/*.yaml`, not `public-main`, so the simulator's
> types and the installed CRDs cannot skew.

## The NICo ⇄ DPF contract this reproduces

Sourced from `crates/dpf/src/sdk.rs` and `crates/machine-controller/src/dpf.rs`:

| Thing | Value | Owner |
|---|---|---|
| DPUNode CR name | `node-{dpf_id}` (`dpf_id` = host BMC MAC, `:`→`-`) | NICo creates |
| DPUDevice CR name | `device-{device_id}` | NICo creates |
| DPU CR name | `node-{dpf_id}-device-{device_id}` | **operator/simulator creates** |
| machine link label | `carbide.nvidia.com/dpu-machine-id` (copy DPUDevice→DPU) | must propagate |
| device marker | `carbide.nvidia.com/controlled.device=true` | on DPUDevice |
| host BMC IP label | `carbide.nvidia.com/host-bmc-ip` | on device+node |
| primary DPU label | `carbide.nvidia.com/is-primary-dpu` | on DPUDevice |
| node-effect hold | annotation `provisioning.dpu.nvidia.com/wait-for-external-nodeeffect` | NICo sets, sim honors |
| reboot signal | annotation `provisioning.dpu.nvidia.com/dpunode-external-reboot-required` | **sim sets**, NICo clears |

**Phase sequence NICo tolerates** (it collapses intermediates to
`Provisioning(detail)` and only acts on `NodeEffect`/`Rebooting`/`Ready`/`Error`):

```
Initializing → Node Effect → Pending → Config FW Parameters → Prepare BFB →
Update Firmware → Initialize Interface → OS Installing → DPU Config →
DPU Cluster Config → Host Network Configuration → Node Effect Removal → Ready
```

## Layout

```
dpf-sim-controller/
├── PROJECT                          # kubebuilder project marker
├── go.mod
├── Makefile
├── Dockerfile
├── cmd/main.go                      # manager wiring, flags
├── internal/
│   ├── controller/
│   │   └── dpudevice_controller.go  # reconcile DPUDevice → ensure+advance DPU
│   ├── simulator/
│   │   └── phases.go                # phase state machine + dwell timing
│   └── carbide/
│       └── labels.go                # NICo label/annotation/name constants
└── config/
    ├── manager/manager.yaml         # Deployment
    ├── rbac/role.yaml               # least-privilege on DPF CRs
    └── samples/                     # standalone DPUDevice/DPUNode for local test
```

## Independence from the real DPF operator (and setup.sh)

This simulator needs **only the DPF CRDs** (`DPUDevice`, `DPUNode`, `DPU`, and
the CRs NICo references) present on the cluster — never the DPF operator. Those
CRDs ship in this repo at `crates/dpf/crds/`, so `make deploy` applies them
directly. It does **not** depend on the setup.sh DPF-install work: that branch
installs the real operator, which you must **not** run here — the operator and
the simulator would both drive `DPU.status.phase` and fight.

The only coupling is version consistency: the simulator's Go types are pinned to
doca-platform **v26.4.0** (`go.mod`), so the applied CRDs must be v26.4.0
compatible. `crates/dpf/crds/` is that version.

## Quick start (against a machine-a-tron cluster)

```bash
export KUBECONFIG=/path/to/site/kubeconfig

# In-cluster (recommended): build + push, then one-command deploy.
# `deploy` installs the CRDs, RBAC and Deployment. Pass PULL_SECRET if the
# nodes need creds to pull IMG (the secret must already exist in the namespace).
make image  IMG=<registry>/dpf-sim-controller:<tag>
make deploy IMG=<registry>/dpf-sim-controller:<tag> \
            DPF_NAMESPACE=dpf-operator-system \
            PULL_SECRET=<existing-pull-secret-name>

# Then bring up machine-a-tron: simulated hosts reach dpuinit, NICo writes
# DPUDevice/DPUNode CRs, the simulator creates DPUs and walks them to Ready.
```

Out-of-cluster alternative (no image needed), useful for local iteration:

```bash
make install-crds
make run DPF_NAMESPACE=dpf-operator-system PHASE_DWELL=3s
```

To exercise the simulator without NICo, apply the standalone sample and watch a
DPU walk to `Ready`:

```bash
kubectl apply -f config/samples/dpudevice_dpunode.yaml
kubectl get dpu -n dpf-operator-system -w
```

> **Building on Apple Silicon:** the multi-stage `golang:1.25` build segfaults
> under QEMU. `make docker-build` sets `--platform linux/amd64`, which works on
> native amd64 (CI); on an Apple-Silicon laptop, cross-compile first
> (`GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o bin/dpf-sim-controller ./cmd`)
> and build a copy-only image, or build on an amd64 host.

## Status

Buildable and deployable. `go build` / `go vet` / `go test` pass; `go.mod` pins
doca-platform v26.4.0 with a committed `go.sum`. The reconcile loop, phase
walker, node-effect hold, reboot round-trip (with a simulator-local marker so a
clear-by-deletion is told apart from never-requested), DPU ownerRef/GC, identity
resolution via the parent `DPUNode` (`spec.dpus[]`), the required `DPU.Spec`
fields, RBAC, manifests, and a one-command `make deploy` are all in place.

Remaining `TODO(#3323)` markers flag fidelity decisions, not blockers: per-phase
dwell durations + phase-entry-time tracking (today the dwell is the requeue
cadence), and confirming `DPURef.Name` semantics to tighten the device→node
match.
