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

package v1

import (
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

const (
	// NetworkNodeFinalizer is the name of the finalizer added to
	// network node to block delete operations until the physical node can be
	// deprovisioned.
	NetworkNodeFinalizer string = "networknode.fsc.henderiw.be"

	// PausedAnnotation is the annotation that pauses the reconciliation (triggers
	// an immediate requeue)
	PausedAnnotation = "networknode.fsc.henderiw.be/paused"

	// StatusAnnotation is the annotation that keeps a copy of the Status of Network Node
	StatusAnnotation = "networknode.fsc.henderiw.be/status"
)

// OperationalStatus represents the state of the network node
type OperationalStatus string

const (
	// OperationalStatusOK is the status value for when the network node is
	// configured correctly and is manageable.
	OperationalStatusOK OperationalStatus = "OK"

	// OperationalStatusDiscovered is the status value for when the
	// network node is only partially configured, such as when when the BMC
	// address is known but the login credentials are not.
	OperationalStatusDiscovered OperationalStatus = "discovered"

	// OperationalStatusError is the status value for when the host
	// has any sort of error.
	OperationalStatusError OperationalStatus = "error"
)

// ErrorType indicates the class of problem that has caused the Network Node resource
// to enter an error state.
type ErrorType string

const (
	// RegistrationError is an error condition occurring when the
	// controller is unable to connect to the Network Node
	RegistrationError ErrorType = "registration error"
	// InspectionError is an error condition occurring when an attempt to
	// obtain hardware details from the Host fails.
	InspectionError ErrorType = "inspection error"
	// ProvisioningError is an error condition occuring when the controller
	// fails to provision or deprovision the Host.
	ProvisioningError ErrorType = "provisioning error"
	// PowerManagementError is an error condition occurring when the
	// controller is unable to modify the power state of the Host.
)

// NetworkNodeSpec defines the desired state of NetworkNode
type NetworkNodeSpec struct {
	// Target defines how we connect to the network node
	Target TargetDetails `json:"target,omitempty"`
	// ConsumerRef can be used to store information about something
	// that is using a network Node. When it is not empty, the Network Node is
	// considered "in use".
	ConsumerRef *corev1.ObjectReference `json:"consumerRef,omitempty"`
}

// TargetDetails contains the information necessary to communicate with
// the network node.
type TargetDetails struct {
	// Protocol used to communicate to the target network node
	Protocol string `json:"protocol,omitempty"`

	// Proxy used to communicate to the target network node
	Proxy string `json:"proxy,omitempty"`

	// Address holds the IP:port for accessing the network node
	Address string `json:"address"`

	// The name of the secret containing the credentials (requires
	// keys "username" and "password").
	CredentialsName string `json:"credentialsName"`

	// The name of the secret containing the credentials (requires
	// keys "TLSCA" and "TLSCert", " TLSKey").
	TLSCredentialsName string `json:"tlsCredentialsName"`

	// SkipVerify disables verification of server certificates when using
	// HTTPS to connect to the Target. This is required when the server
	// certificate is self-signed, but is insecure because it allows a
	// man-in-the-middle to intercept the connection.
	SkipVerify bool `json:"skpVerify,omitempty"`

	// Insecure runs the grpc call in an insecure manner
	Insecure bool `json:"insecure,omitempty"`

	// Encoding
	Encoding string `json:"encoding,omitempty"`
}

// OperationMetric contains metadata about an operation (inspection,
// provisioning, etc.) used for tracking metrics.
type OperationMetric struct {
	// +nullable
	Start metav1.Time `json:"start,omitempty"`
	// +nullable
	End metav1.Time `json:"end,omitempty"`
}

// Duration returns the length of time that was spent on the
// operation. If the operation is not finished, it returns 0.
func (om OperationMetric) Duration() time.Duration {
	if om.Start.IsZero() {
		return 0
	}
	return om.End.Time.Sub(om.Start.Time)
}

// OperationHistory holds information about operations performed on a
// host.
type OperationHistory struct {
	Register    OperationMetric `json:"register,omitempty"`
	Inspect     OperationMetric `json:"inspect,omitempty"`
	Provision   OperationMetric `json:"provision,omitempty"`
	Deprovision OperationMetric `json:"deprovision,omitempty"`
}

// NetworkNodeStatus defines the observed state of NetworkNode
type NetworkNodeStatus struct {
	// OperationalStatus holds the status of the host
	// +kubebuilder:validation:Enum="";OK;discovered;error
	OperationalStatus OperationalStatus `json:"operationalStatus"`

	// ErrorType indicates the type of failure encountered when the
	// OperationalStatus is OperationalStatusError
	// +kubebuilder:validation:Enum=registration error;inspection error;provisioning error;power management error
	ErrorType ErrorType `json:"errorType,omitempty"`

	// LastUpdated identifies when this status was last observed.
	// +optional
	LastUpdated *metav1.Time `json:"lastUpdated,omitempty"`

	// The hardware discovered on the Network Node.
	HardwareDetails *HardwareDetails `json:"hardware,omitempty"`

	// Information tracked by the discoverer.
	DiscoveryStatus DiscoveryStatus `json:"discoveryStatus"`

	// the last error message reported by the provisioning subsystem
	ErrorMessage string `json:"errorMessage"`

	// OperationHistory holds information about operations performed
	// on this host.
	OperationHistory OperationHistory `json:"operationHistory"`

	// ErrorCount records how many times the host has encoutered an error since the last successful operation
	// +kubebuilder:default:=0
	ErrorCount int `json:"errorCount"`
}

// DiscoveryState defines the states the discoverer will report
// the host has having.
type DiscoveryState string

const (
	// StateNone means the state is unknown
	StateNone DiscoveryState = ""

	// StateUnmanaged means there is insufficient information available to
	// register the host
	StateUnmanaged DiscoveryState = "unmanaged"

	// StateReady means the host can be consumed
	StateReady DiscoveryState = "ready"

	// StateAvailable means the host can be consumed
	StateAvailable DiscoveryState = "available"

	// StateProvisioning means we are writing an image to the host's
	// disk(s)
	StateProvisioning DiscoveryState = "provisioning"

	// StateProvisioned means we have written an image to the host's
	// disk(s)
	StateProvisioned DiscoveryState = "provisioned"

	// StateInspecting means we are running the agent on the Network Node to
	// learn about the hardware components available there
	StateInspecting DiscoveryState = "inspecting"

	// StateDeleting means we are in the process of cleaning up the Network Node
	// ready for deletion
	StateDeleting DiscoveryState = "deleting"
)

// DiscoveryStatus holds the state information for a single target.
type DiscoveryStatus struct {
	// An indiciator for what the discoverer is doing with the host.
	State DiscoveryState `json:"state"`
}

// HardwareDetails collects all of the information about hardware
// discovered on the Network Node.
type HardwareDetails struct {
	Hostname        string `json:"hostname"`
	Kind            string `json:"kind"`
	SoftwareVersion string `json:"softwareVersion"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// NetworkNode is the Schema for the networknodes API
type NetworkNode struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   NetworkNodeSpec   `json:"spec,omitempty"`
	Status NetworkNodeStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// NetworkNodeList contains a list of NetworkNode
type NetworkNodeList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []NetworkNode `json:"items"`
}

func init() {
	SchemeBuilder.Register(&NetworkNode{}, &NetworkNodeList{})
}

// CredentialsKey returns a NamespacedName suitable for loading the
// Secret containing the credentials associated with the host.
func (nn *NetworkNode) CredentialsKey() types.NamespacedName {
	return types.NamespacedName{
		Name:      nn.Spec.Target.CredentialsName,
		Namespace: nn.ObjectMeta.Namespace,
	}
}

// NewEvent creates a new event associated with the object and ready
// to be published to the kubernetes API.
func (nn *NetworkNode) NewEvent(reason, message string) corev1.Event {
	t := metav1.Now()
	return corev1.Event{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: reason + "-",
			Namespace:    nn.ObjectMeta.Namespace,
		},
		InvolvedObject: corev1.ObjectReference{
			Kind:       "BareMetalHost",
			Namespace:  nn.Namespace,
			Name:       nn.Name,
			UID:        nn.UID,
			APIVersion: GroupVersion.String(),
		},
		Reason:  reason,
		Message: message,
		Source: corev1.EventSource{
			Component: "fsc-discovery-controller",
		},
		FirstTimestamp:      t,
		LastTimestamp:       t,
		Count:               1,
		Type:                corev1.EventTypeNormal,
		ReportingController: "fsc.henderiw.be/fsc-discovery-controller",
		Related:             nn.Spec.ConsumerRef,
	}
}

// OperationMetricForState returns a pointer to the metric for the given
// discovery state.
func (nn *NetworkNode) OperationMetricForState(operation DiscoveryState) (metric *OperationMetric) {
	history := &nn.Status.OperationHistory
	switch operation {
	case StateInspecting:
		metric = &history.Inspect
	}
	return
}
