package discoverer

import (
	"errors"
	"time"

	fscv1 "github.com/fsc-demo-wim/fsc-discovery-operator/api/v1"
)

/*
Package discoverer defines the API for talking to the discovery backend.
*/

// EventPublisher is a function type for publishing events associated
// with discovery.
type EventPublisher func(reason, message string)

// Factory is the interface for creating new Discoverer objects.
type Factory func(host fscv1.NetworkNode, publish EventPublisher) (Discoverer, error)

// NetworkNodeConfigData retrieves host configuration data
type NetworkNodeConfigData interface {
}

// Discoverer holds the state information for talking to the
// discovery backend.
type Discoverer interface {
	// Discover registers the network node with the discovery system
	// and tests the connection information for the network node to verify
	// that the credentials work.
	Discover(credentialsChanged, force bool) (result Result, provID string, err error)

	// Delete removes the network node from the discovery system.
	Delete() (result Result, err error)

	// IsReady checks if the discovery backend is available to accept
	// all the incoming requests.
	IsReady() (result bool, err error)
}

// Result holds the response from a call in the Provsioner API.
type Result struct {
	// Dirty indicates whether the host object needs to be saved.
	Dirty bool
	// RequeueAfter indicates how long to wait before making the same
	// Provisioner call again. The request should only be requeued if
	// Dirty is also true.
	RequeueAfter time.Duration
	// Any error message produced by the provisioner.
	ErrorMessage string
}

// HardwareState holds the response from an UpdateHardwareState call
type HardwareState struct {
	// PoweredOn is a pointer to a bool indicating whether the Host is currently
	// powered on. The value is nil if the power state cannot be determined.
	PoweredOn *bool
}

// ErrorNeedsRegistration variable
var ErrorNeedsRegistration = errors.New("Network Node not registered")
