// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Command dpf-sim-controller runs a development-only simulator of the DPF
// operator so machine-a-tron simulated hosts can progress past dpuinit.
// See the package README for the NICo <-> DPF contract it reproduces.
package main

import (
	"flag"
	"os"
	"time"

	provisioningv1 "github.com/nvidia/doca-platform/api/provisioning/v1alpha1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/nvidia/infra-controller/dev/k8s/dpf-sim-controller/internal/controller"
)

var scheme = runtime.NewScheme()

func init() {
	_ = clientgoscheme.AddToScheme(scheme)
	// Register the upstream DPF types — this is the whole point of importing
	// the doca-platform module: no local CRD/type authoring.
	_ = provisioningv1.AddToScheme(scheme)
}

func main() {
	var (
		metricsAddr  string
		probeAddr    string
		dpfNamespace string
		phaseDwell   time.Duration
	)
	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080", "metrics endpoint")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "health probe endpoint")
	flag.StringVar(&dpfNamespace, "dpf-namespace", "dpf-operator-system",
		"namespace where NICo creates DPF CRs (must match site config)")
	flag.DurationVar(&phaseDwell, "phase-dwell", 3*time.Second,
		"time each dwell-gated DPU phase lingers before advancing")
	opts := zap.Options{Development: true}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))
	setupLog := ctrl.Log.WithName("setup")

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsserver.Options{BindAddress: metricsAddr},
		HealthProbeBindAddress: probeAddr,
		// Simulator is single-instance dev tooling; no leader election.
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	if err = (&controller.DPUDeviceReconciler{
		Client:     mgr.GetClient(),
		Scheme:     mgr.GetScheme(),
		Namespace:  dpfNamespace,
		PhaseDwell: phaseDwell,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "DPUDevice")
		os.Exit(1)
	}

	_ = mgr.AddHealthzCheck("healthz", healthz.Ping)
	_ = mgr.AddReadyzCheck("readyz", healthz.Ping)

	setupLog.Info("starting dpf-sim-controller", "dpfNamespace", dpfNamespace, "phaseDwell", phaseDwell)
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "manager exited")
		os.Exit(1)
	}
}
