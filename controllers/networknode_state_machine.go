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
	"fmt"

	fscv1 "github.com/fsc-demo-wim/fsc-discovery-operator/api/v1"
	"github.com/fsc-demo-wim/fsc-discovery-operator/pkg/discoverer"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// networkNodeStateMachine is a finite state machine that manages transitions between
// the states of a networkNode.
type networkNodeStateMachine struct {
	NetworkNode *fscv1.NetworkNode
	NextState   fscv1.DiscoveryState
	Reconciler  *NetworkNodeReconciler
	Discoverer  discoverer.Discoverer
	haveCreds   bool
}

func newNetworkNodeStateMachine(nn *fscv1.NetworkNode,
	reconciler *NetworkNodeReconciler,
	discoverer discoverer.Discoverer,
	haveCreds bool) *networkNodeStateMachine {
	currentState := nn.Status.DiscoveryStatus.State
	r := networkNodeStateMachine{
		NetworkNode: nn,
		NextState:   currentState, // Remain in current state by default
		Reconciler:  reconciler,
		Discoverer:  discoverer,
		haveCreds:   haveCreds,
	}
	return &r
}

type stateHandler func(*reconcileInfo) actionResult

func (nnsm *networkNodeStateMachine) handlers() map[fscv1.DiscoveryState]stateHandler {
	return map[fscv1.DiscoveryState]stateHandler{
		fscv1.StateNone:       nnsm.handleNone,
		fscv1.StateUnmanaged:  nnsm.handleUnmanaged,
		fscv1.StateInspecting: nnsm.handleInspecting,
		fscv1.StateAvailable:  nnsm.handleReady,
		fscv1.StateDeleting:   nnsm.handleDeleting,
	}
}

func recordStateBegin(nn *fscv1.NetworkNode, state fscv1.DiscoveryState, time metav1.Time) {
	if nextMetric := nn.OperationMetricForState(state); nextMetric != nil {
		if nextMetric.Start.IsZero() || !nextMetric.End.IsZero() {
			*nextMetric = fscv1.OperationMetric{
				Start: time,
			}
		}
	}
}

func recordStateEnd(info *reconcileInfo, nn *fscv1.NetworkNode, state fscv1.DiscoveryState, time metav1.Time) (changed bool) {
	if prevMetric := nn.OperationMetricForState(state); prevMetric != nil {
		if !prevMetric.Start.IsZero() && prevMetric.End.IsZero() {
			prevMetric.End = time
			info.postSaveCallbacks = append(info.postSaveCallbacks, func() {
				observer := stateTime[state].With(networkNodeMetricLabels(info.request))
				observer.Observe(prevMetric.Duration().Seconds())
			})
			changed = true
		}
	}
	return
}

func (nnsm *networkNodeStateMachine) updateHostStateFrom(initialState fscv1.DiscoveryState,
	info *reconcileInfo) {
	if nnsm.NextState != initialState {
		info.log.Info("changing provisioning state",
			"old", initialState,
			"new", nnsm.NextState)
		now := metav1.Now()
		recordStateEnd(info, nnsm.NetworkNode, initialState, now)
		recordStateBegin(nnsm.NetworkNode, nnsm.NextState, now)
		nnsm.NetworkNode.Status.DiscoveryStatus.State = nnsm.NextState
		// Here we assume that if we're being asked to change the
		// state, the return value of ReconcileState (our caller) is
		// set up to ensure the change in the host is written back to
		// the API. That means we can safely update any status fields
		// along with the state.
		switch nnsm.NextState {
		case fscv1.StateInspecting:
			// TODO
		}
	}
}

func (nnsm *networkNodeStateMachine) ReconcileState(info *reconcileInfo) actionResult {
	initialState := nnsm.NetworkNode.Status.DiscoveryStatus.State
	defer nnsm.updateHostStateFrom(initialState, info)

	if nnsm.checkInitiateDelete() {
		info.log.Info("Initiating host deletion")
		return actionComplete{}
	}

	if registerResult := nnsm.ensureRegistered(info); registerResult != nil {
		networkNodeRegistrationRequired.Inc()
		return registerResult
	}

	if stateHandler, found := nnsm.handlers()[initialState]; found {
		return stateHandler(info)
	}

	info.log.Info("No handler found for state", "state", initialState)
	return actionError{fmt.Errorf("No handler found for state \"%s\"", initialState)}
}

func (nnsm *networkNodeStateMachine) checkInitiateDelete() bool {
	if nnsm.NetworkNode.DeletionTimestamp.IsZero() {
		// Delete not requested
		return false
	}

	switch nnsm.NextState {
	default:
		nnsm.NextState = fscv1.StateDeleting
	case fscv1.StateDeleting:
		// Already in deleting state. Allow state machine to run.
		return false
	}
	return true
}

func (nnsm *networkNodeStateMachine) ensureRegistered(info *reconcileInfo) (result actionResult) {
	if !nnsm.haveCreds {
		// If we are in the process of deletion (which may start with
		// deprovisioning) and we have been unable to obtain any credentials,
		// don't attempt to re-register the Host as this will always fail.
		return
	}

	switch nnsm.NextState {
	case fscv1.StateNone, fscv1.StateUnmanaged:
		// We haven't yet reached the Registration state, so don't attempt
		// to register the Host.
		return
	case fscv1.StateDeleting:
		// In the deleting state the whole idea is to de-register the host
		return
	default:
	}

	return
}

func (nnsm *networkNodeStateMachine) handleNone(info *reconcileInfo) actionResult {
	return actionComplete{}
}

func (nnsm *networkNodeStateMachine) handleUnmanaged(info *reconcileInfo) actionResult {
	actResult := nnsm.Reconciler.actionUnmanaged(nnsm.Discoverer, info)
	if _, complete := actResult.(actionComplete); complete {
		nnsm.NextState = fscv1.StateProvisioning
	}
	return actResult
}

func (nnsm *networkNodeStateMachine) handleInspecting(info *reconcileInfo) actionResult {
	actResult := nnsm.Reconciler.actionInspecting(nnsm.Discoverer, info)
	if _, complete := actResult.(actionComplete); complete {
		nnsm.NextState = fscv1.StateProvisioning
		nnsm.NetworkNode.Status.ErrorCount = 0
	}
	return actResult
}

func (nnsm *networkNodeStateMachine) handleReady(info *reconcileInfo) actionResult {

	// ErrorCount is cleared when appropriate inside actionManageReady
	actResult := nnsm.Reconciler.actionManageReady(nnsm.Discoverer, info)
	if _, complete := actResult.(actionComplete); complete {
		nnsm.NextState = fscv1.StateProvisioning
	}
	return actResult
}

func (nnsm *networkNodeStateMachine) handleDeleting(info *reconcileInfo) actionResult {
	return nnsm.Reconciler.actionDeleting(nnsm.Discoverer, info)
}
