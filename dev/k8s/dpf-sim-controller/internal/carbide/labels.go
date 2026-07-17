// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package carbide holds the label, annotation, and CR-naming constants that
// form the contract between NICo and the DPF operator. The simulator must use
// these verbatim — they are mirrored from the NICo source of truth:
//
//	crates/machine-controller/src/dpf.rs   (labels)
//	crates/dpf/src/sdk.rs                   (annotations, CR-name derivation)
//
// If NICo changes any of these, this file must change with it.
package carbide

import "strings"

// Labels NICo sets on DPUDevice CRs. The dpu-machine-id label MUST be copied
// from the DPUDevice onto the DPU CR the simulator creates, or NICo cannot map
// a DPU event back to its machine (reverse lookup in dpf.rs).
const (
	LabelDPUMachineID    = "carbide.nvidia.com/dpu-machine-id"
	LabelControlledDev   = "carbide.nvidia.com/controlled.device" // "true"
	LabelHostBMCIP       = "carbide.nvidia.com/host-bmc-ip"
	LabelIsPrimaryDPU    = "carbide.nvidia.com/is-primary-dpu"
	LabelControlledNode2 = "carbide.nvidia.com/controlled.node.v2" // on DPUNode
)

// Annotations exchanged on the DPUNode CR.
const (
	// AnnHoldNodeEffect: NICo sets this to park the DPU in the Node Effect
	// phase until an external actor releases it. The simulator must NOT
	// advance past Node Effect while this is present/true.
	AnnHoldNodeEffect = "provisioning.dpu.nvidia.com/wait-for-external-nodeeffect"

	// AnnRebootRequired: the operator/simulator SETS this when it needs the
	// host rebooted; NICo performs the reboot (via Redfish against the
	// machine-a-tron mock) and CLEARS it (by removing the annotation), which
	// the simulator waits for before continuing to Ready.
	AnnRebootRequired = "provisioning.dpu.nvidia.com/dpunode-external-reboot-required"

	// AnnSimRebootRequested is the simulator's OWN bookkeeping marker, written
	// on the DPU CR when it has requested a reboot for the current Rebooting
	// phase. NICo clears AnnRebootRequired by deleting it, which is
	// indistinguishable from "never requested" by presence alone; this marker
	// lets the handshake tell "requested & cleared" (advance) from "not yet
	// requested" (request now). Not part of the NICo contract — simulator-local.
	AnnSimRebootRequested = "sim.dpu.nvidia.com/reboot-requested"
)

// CR-name derivation, mirrored from crates/dpf/src/sdk.rs:382-410.
//
//	DPUNode   = "node-{dpfID}"          dpfID = host BMC MAC with ':' -> '-'
//	DPUDevice = "device-{deviceID}"
//	DPU       = "node-{dpfID}-device-{deviceID}"

func DPUNodeName(dpfID string) string   { return "node-" + dpfID }
func DPUDeviceName(devID string) string { return "device-" + devID }

// DPUName builds the DPU CR name the operator would create. It concatenates
// the node and device CR names exactly (the device- prefix is intentional).
func DPUName(dpfID, deviceID string) string {
	return DPUNodeName(dpfID) + "-" + DPUDeviceName(deviceID)
}

// NodeIDFromNodeCRName strips the "node-" prefix (sdk.rs:409).
func NodeIDFromNodeCRName(nodeCRName string) string {
	return strings.TrimPrefix(nodeCRName, "node-")
}

// DeviceIDFromDeviceCRName strips the "device-" prefix, yielding the raw
// device_id NICo uses (sdk.rs dpu_cr_name takes the raw id, not the CR name).
func DeviceIDFromDeviceCRName(deviceCRName string) string {
	return strings.TrimPrefix(deviceCRName, "device-")
}

// DPFIDFromBMCMAC converts a BMC MAC (aa:bb:...) into the dpf_id form (aa-bb-...).
func DPFIDFromBMCMAC(mac string) string {
	return strings.ReplaceAll(mac, ":", "-")
}
