// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"fmt"
	"strings"
	"time"

	provisioningv1 "github.com/nvidia/doca-platform/api/provisioning/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/nvidia/infra-controller/dev/k8s/dpf-sim-controller/internal/carbide"
	"github.com/nvidia/infra-controller/dev/k8s/dpf-sim-controller/internal/simulator"
)

// DPUDeviceReconciler plays the DPF operator's role for simulation. NICo creates
// a DPUDevice (and a parent DPUNode) for every simulated DPU that reaches
// dpuinit; this reconciler ensures a matching DPU CR exists and advances its
// status.phase through the happy path so NICo's machine controller can proceed.
//
// It reconciles on DPUDevice (the CR NICo owns), sets a controller ownerRef on
// each DPU it creates so DPU status writes re-enqueue the parent DPUDevice
// (via Owns) and deleting the DPUDevice garbage-collects its DPU.
type DPUDeviceReconciler struct {
	client.Client
	Scheme *runtime.Scheme

	// Namespace to operate in (the DPF namespace NICo is configured with).
	Namespace string
	// PhaseDwell is how long each dwell-gated phase lingers before advancing.
	PhaseDwell time.Duration
}

// RBAC — least privilege on exactly the DPF CRs the simulator touches.
//+kubebuilder:rbac:groups=provisioning.dpu.nvidia.com,resources=dpudevices,verbs=get;list;watch
//+kubebuilder:rbac:groups=provisioning.dpu.nvidia.com,resources=dpunodes,verbs=get;list;watch;update;patch
//+kubebuilder:rbac:groups=provisioning.dpu.nvidia.com,resources=dpus,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=provisioning.dpu.nvidia.com,resources=dpus/status,verbs=get;update;patch

func (r *DPUDeviceReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	l := log.FromContext(ctx)

	var device provisioningv1.DPUDevice
	if err := r.Get(ctx, req.NamespacedName, &device); err != nil {
		// DPUDevice gone: NICo tore the machine down. The DPU carries a
		// controller ownerRef to the DPUDevice, so the DPU is garbage-collected
		// automatically — nothing to do here.
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Resolve the CR names from the NICo naming scheme. deviceID is the
	// DPUDevice's own name minus the "device-" prefix; the node_id comes from
	// the parent DPUNode that references this device (NICo owns both).
	deviceID := carbide.DeviceIDFromDeviceCRName(device.Name)
	nodeID, err := r.resolveNodeID(ctx, &device)
	if err != nil {
		// The parent DPUNode may not be created yet; requeue and retry.
		l.V(1).Info("parent DPUNode not found yet; requeueing", "device", device.Name, "err", err.Error())
		return ctrl.Result{RequeueAfter: r.PhaseDwell}, nil
	}
	dpuName := carbide.DPUName(nodeID, deviceID)
	nodeName := carbide.DPUNodeName(nodeID)

	// 1. Ensure the DPU CR exists, phase=Initializing, machine-id label copied,
	//    ownerRef set to the DPUDevice.
	dpu, err := r.ensureDPU(ctx, &device, dpuName, nodeName)
	if err != nil {
		return ctrl.Result{}, err
	}

	// 2. Terminal? stop ticking.
	if simulator.IsTerminal(dpu.Status.Phase) {
		l.V(1).Info("DPU terminal", "dpu", dpuName, "phase", dpu.Status.Phase)
		return ctrl.Result{}, nil
	}

	// 3. Gate on the current phase.
	switch simulator.Gate(dpu.Status.Phase) {
	case simulator.GateHold:
		held, err := r.nodeHasAnnotationTrue(ctx, nodeName, carbide.AnnHoldNodeEffect)
		if err != nil {
			return ctrl.Result{}, err
		}
		if held {
			l.V(1).Info("node-effect hold active; parking", "dpu", dpuName)
			return ctrl.Result{RequeueAfter: r.PhaseDwell}, nil
		}

	case simulator.GateReboot:
		// Request the reboot once; wait for NICo to complete it.
		cleared, err := r.ensureRebootHandshake(ctx, nodeName, dpu)
		if err != nil {
			return ctrl.Result{}, err
		}
		if !cleared {
			l.V(1).Info("waiting for NICo to complete host reboot", "node", nodeName)
			return ctrl.Result{RequeueAfter: r.PhaseDwell}, nil
		}

	case simulator.GateDwell:
		// TODO(#3323): honor a per-phase dwell (some phases — OS Installing —
		// should linger longer than others), and record the phase-entry time
		// in DPU status so an out-of-band reconcile (informer resync, manual
		// edit) does not advance the phase before PhaseDwell has elapsed. Today
		// the dwell is only the RequeueAfter cadence between reconciles.
	}

	// 4. Advance to the next phase and write status.
	next, ok := simulator.Next(dpu.Status.Phase)
	if !ok {
		// Unknown/empty phase (e.g. a DPU created outside the happy path, or a
		// status subresource that was never populated). Re-seed to Initializing
		// rather than wedging silently with no requeue.
		l.Info("DPU has unknown phase; re-seeding to Initializing", "dpu", dpuName, "phase", dpu.Status.Phase)
		dpu.Status.Phase = provisioningv1.DPUInitializing
		if err := r.Status().Update(ctx, dpu); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: r.PhaseDwell}, nil
	}
	dpu.Status.Phase = next
	if err := r.Status().Update(ctx, dpu); err != nil {
		if apierrors.IsConflict(err) {
			return ctrl.Result{Requeue: true}, nil
		}
		return ctrl.Result{}, err
	}
	l.Info("advanced DPU phase", "dpu", dpuName, "phase", next)

	return ctrl.Result{RequeueAfter: r.PhaseDwell}, nil
}

// resolveNodeID returns the node_id for a DPUDevice by locating the parent
// DPUNode that references it. NICo creates the DPUNode with spec.dpus[].name
// listing its attached devices (crates/dpf/src/sdk.rs register_dpu_node); the
// node_id is that DPUNode's name with the "node-" prefix stripped.
//
// TODO(#3323): DPURef.Name is documented upstream as "Name of the DPU device";
// confirm whether it is the DPUDevice CR name (device-{id}) or the raw id, and
// tighten the match below. The suffix match tolerates either form.
func (r *DPUDeviceReconciler) resolveNodeID(ctx context.Context, device *provisioningv1.DPUDevice) (string, error) {
	var nodes provisioningv1.DPUNodeList
	if err := r.List(ctx, &nodes, client.InNamespace(r.Namespace)); err != nil {
		return "", err
	}
	deviceID := carbide.DeviceIDFromDeviceCRName(device.Name)
	for i := range nodes.Items {
		n := &nodes.Items[i]
		for _, ref := range n.Spec.DPUs {
			if ref.Name == device.Name || strings.HasSuffix(ref.Name, deviceID) {
				return carbide.NodeIDFromNodeCRName(n.Name), nil
			}
		}
	}
	return "", fmt.Errorf("no DPUNode references DPUDevice %q", device.Name)
}

// ensureDPU creates the DPU CR if absent, seeded at Initializing with the
// machine-id label copied off the DPUDevice (required for NICo reverse lookup)
// and a controller ownerRef to the DPUDevice for GC and Owns() re-enqueue.
func (r *DPUDeviceReconciler) ensureDPU(
	ctx context.Context, device *provisioningv1.DPUDevice, dpuName, nodeName string,
) (*provisioningv1.DPU, error) {
	var dpu provisioningv1.DPU
	err := r.Get(ctx, types.NamespacedName{Namespace: r.Namespace, Name: dpuName}, &dpu)
	if err == nil {
		return &dpu, nil
	}
	if !apierrors.IsNotFound(err) {
		return nil, err
	}

	noEffect := true
	dpu = provisioningv1.DPU{
		ObjectMeta: metav1.ObjectMeta{
			Name:      dpuName,
			Namespace: r.Namespace,
			Labels: map[string]string{
				// MUST propagate — NICo maps DPU events back to a machine by this.
				carbide.LabelDPUMachineID: device.Labels[carbide.LabelDPUMachineID],
				carbide.LabelHostBMCIP:    device.Labels[carbide.LabelHostBMCIP],
			},
		},
		Spec: provisioningv1.DPUSpec{
			DPUNodeName:   nodeName,
			DPUDeviceName: device.Name,
			SerialNumber:  device.Spec.SerialNumber,
			// DPUFlavor and BFB are required by the CRD but have no meaning for
			// the simulator; use placeholder values so the CR is accepted.
			DPUFlavor: "sim",
			BFB:       "sim",
			// NoEffect: the simulator never touches real K8s node taints/drains.
			// NodeEffect embeds Action; NoEffect lives on Action, not NodeEffect directly.
			NodeEffect: provisioningv1.NodeEffect{
				Action: provisioningv1.Action{NoEffect: &noEffect},
			},
		},
	}
	if err := controllerutil.SetControllerReference(device, &dpu, r.Scheme); err != nil {
		return nil, err
	}
	if err := r.Create(ctx, &dpu); err != nil {
		return nil, err
	}
	// Create does not persist the status subresource, so write the initial
	// phase explicitly rather than relying on the in-memory value.
	dpu.Status.Phase = provisioningv1.DPUInitializing
	if err := r.Status().Update(ctx, &dpu); err != nil {
		return nil, err
	}
	return &dpu, nil
}

// ensureRebootHandshake requests a host reboot once per Rebooting phase and
// reports cleared=true after NICo has completed it. NICo clears
// AnnRebootRequired by REMOVING it, which is indistinguishable from
// "never requested" by presence alone; the simulator therefore records its own
// AnnSimRebootRequested marker on the DPU to tell the two apart.
func (r *DPUDeviceReconciler) ensureRebootHandshake(
	ctx context.Context, nodeName string, dpu *provisioningv1.DPU,
) (bool, error) {
	var node provisioningv1.DPUNode
	if err := r.Get(ctx, types.NamespacedName{Namespace: r.Namespace, Name: nodeName}, &node); err != nil {
		return false, client.IgnoreNotFound(err)
	}
	nodeWantsReboot := node.Annotations[carbide.AnnRebootRequired] == "true"
	alreadyRequested := dpu.Annotations[carbide.AnnSimRebootRequested] == "true"

	if nodeWantsReboot {
		return false, nil // reboot still pending on NICo
	}
	if alreadyRequested {
		// We requested it and NICo has since cleared the annotation → done.
		// Clear our marker so a later Rebooting phase requests afresh.
		if err := r.setDPUAnnotation(ctx, dpu, carbide.AnnSimRebootRequested, ""); err != nil {
			return false, err
		}
		return true, nil
	}
	// Not yet requested: set the node annotation and record our marker.
	if err := r.setNodeAnnotation(ctx, &node, carbide.AnnRebootRequired, "true"); err != nil {
		return false, err
	}
	if err := r.setDPUAnnotation(ctx, dpu, carbide.AnnSimRebootRequested, "true"); err != nil {
		return false, err
	}
	return false, nil
}

func (r *DPUDeviceReconciler) setNodeAnnotation(ctx context.Context, node *provisioningv1.DPUNode, key, val string) error {
	patch := client.MergeFrom(node.DeepCopy())
	if node.Annotations == nil {
		node.Annotations = map[string]string{}
	}
	if val == "" {
		delete(node.Annotations, key)
	} else {
		node.Annotations[key] = val
	}
	return r.Patch(ctx, node, patch)
}

func (r *DPUDeviceReconciler) setDPUAnnotation(ctx context.Context, dpu *provisioningv1.DPU, key, val string) error {
	patch := client.MergeFrom(dpu.DeepCopy())
	if dpu.Annotations == nil {
		dpu.Annotations = map[string]string{}
	}
	if val == "" {
		delete(dpu.Annotations, key)
	} else {
		dpu.Annotations[key] = val
	}
	return r.Patch(ctx, dpu, patch)
}

func (r *DPUDeviceReconciler) nodeHasAnnotationTrue(ctx context.Context, nodeName, ann string) (bool, error) {
	var node provisioningv1.DPUNode
	if err := r.Get(ctx, types.NamespacedName{Namespace: r.Namespace, Name: nodeName}, &node); err != nil {
		return false, client.IgnoreNotFound(err)
	}
	return node.Annotations[ann] == "true", nil
}

// SetupWithManager wires the reconciler: own DPU, watch DPUDevice as primary.
func (r *DPUDeviceReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.PhaseDwell == 0 {
		r.PhaseDwell = 3 * time.Second
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&provisioningv1.DPUDevice{}).
		Owns(&provisioningv1.DPU{}).
		Complete(r)
}
