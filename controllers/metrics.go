/*
Copyright 2021 Wim Henderickx.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controllers

import (
	fscv1 "github.com/fsc-demo-wim/fsc-discovery-operator/api/v1"
	"github.com/prometheus/client_golang/prometheus"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

const (
	labelNetworkNodeNamespace = "namespace"
	labelNetworkNodeName      = "host"
	labelErrorType            = "error_type"
	labelPowerOnOff           = "on_off"
	labelPrevState            = "prev_state"
	labelNewState             = "new_state"
	labelNetworkNodeDataType  = "networkNode_data_type"
)

var reconcileCounters = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "srl_fsc_reconcile_total",
	Help: "The number of times hosts have been reconciled",
}, []string{labelNetworkNodeNamespace, labelNetworkNodeName})
var reconcileErrorCounter = prometheus.NewCounter(prometheus.CounterOpts{
	Name: "srl_fsc_reconcile_error_total",
	Help: "The number of times the operator has failed to reconcile a network node",
})
var credentialsMissing = prometheus.NewCounter(prometheus.CounterOpts{
	Name: "srl_fsc_credentials_missing_total",
	Help: "Number of times a host's credentials are found to be missing",
})
var credentialsInvalid = prometheus.NewCounter(prometheus.CounterOpts{
	Name: "srl_fsc_credentials_invalid_total",
	Help: "Number of times a host's credentials are found to be invalid",
})
var unhandledCredentialsError = prometheus.NewCounter(prometheus.CounterOpts{
	Name: "srl_fsc_credentials_unhandled_error_total",
	Help: "Number of times getting a host's credentials fails in an unexpected way",
})
var updatedCredentials = prometheus.NewCounter(prometheus.CounterOpts{
	Name: "srl_fsc_credentials_updated_total",
	Help: "Number of times a host's credentials change",
})
var noManagementAccess = prometheus.NewCounter(prometheus.CounterOpts{
	Name: "srl_fsc_credentials_no_management_access_total",
	Help: "Number of times a network node management interface is unavailable",
})
var networkNodeConfigDataError = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "srl_fsc_host_config_data_error_total",
	Help: "Number of times the operator has failed to retrieve network node configuration data",
}, []string{labelNetworkNodeDataType})

var slowOperationBuckets = []float64{30, 90, 180, 360, 720, 1440}

var stateTime = map[fscv1.DiscoveryState]*prometheus.HistogramVec{
	fscv1.StateInspecting: prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "srl_fsc_operation_inspect_duration_seconds",
		Help:    "Length of time per inspection per network node",
		Buckets: slowOperationBuckets,
	}, []string{labelNetworkNodeNamespace, labelNetworkNodeName}),
}

var stateChanges = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "metal3_provisioning_state_change_total",
	Help: "Number of times a state transition has occurred",
}, []string{labelPrevState, labelNewState})

var networkNodeRegistrationRequired = prometheus.NewCounter(prometheus.CounterOpts{
	Name: "srl_fsc_network_node_registration_required_total",
	Help: "Number of times a network node is found to be unregistered",
})

var deleteWithoutDeprov = prometheus.NewCounter(prometheus.CounterOpts{
	Name: "srl_fsc_delete_without_deprovisioning_total",
	Help: "Number of times a host is deleted despite deprovisioning failing",
})

func init() {
	metrics.Registry.MustRegister(
		reconcileCounters,
		reconcileErrorCounter)

	for _, collector := range stateTime {
		metrics.Registry.MustRegister(collector)
	}

	metrics.Registry.MustRegister(
		credentialsMissing,
		credentialsInvalid,
		unhandledCredentialsError,
		updatedCredentials,
		noManagementAccess,
		networkNodeConfigDataError)

}

func networkNodeMetricLabels(request ctrl.Request) prometheus.Labels {
	return prometheus.Labels{
		labelNetworkNodeNamespace: request.Namespace,
		labelNetworkNodeName:      request.Name,
	}
}
