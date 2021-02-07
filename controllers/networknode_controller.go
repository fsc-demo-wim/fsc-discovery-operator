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
	"context"
	"fmt"
	"time"

	"github.com/fsc-demo-wim/fsc-discovery-operator/pkg/utils"
	"github.com/go-logr/logr"
	"github.com/pkg/errors"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	fscv1 "github.com/fsc-demo-wim/fsc-discovery-operator/api/v1"
	"github.com/fsc-demo-wim/fsc-discovery-operator/pkg/discoverer"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	nnErrorRetryDelay           = time.Second * 10
	unmanagedRetryDelay         = time.Minute * 10
	discoveryNotReadyRetryDelay = time.Second * 30
)

func init() {
}

// NetworkNodeReconciler reconciles a NetworkNode object
type NetworkNodeReconciler struct {
	client.Client
	Log               logr.Logger
	Scheme            *runtime.Scheme
	DiscovererFactory discoverer.Factory
}

// Instead of passing a zillion arguments to the action of a phase,
// hold them in a context
type reconcileInfo struct {
	log               logr.Logger
	nn                *fscv1.NetworkNode
	request           ctrl.Request
	targetCredsSecret *corev1.Secret
	events            []corev1.Event
	errorMessage      string
	postSaveCallbacks []func()
}

// match the provisioner.EventPublisher interface
func (info *reconcileInfo) publishEvent(reason, message string) {
	info.events = append(info.events, info.nn.NewEvent(reason, message))
}

// +kubebuilder:rbac:groups=fsc.henderiw.be,resources=networknodes,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=fsc.henderiw.be,resources=networknodes/status,verbs=get;update;patch

// Reconcile handles reconciliation of Network Node resources
func (r *NetworkNodeReconciler) Reconcile(req ctrl.Request) (result ctrl.Result, err error) {
	reconcileCounters.With(networkNodeMetricLabels(req)).Inc()
	defer func() {
		if err != nil {
			reconcileErrorCounter.Inc()
		}
	}()

	ctx := context.Background()
	rLogger := r.Log.WithValues("networknode", req.NamespacedName)

	nn := &fscv1.NetworkNode{}
	err = r.Get(ctx, req.NamespacedName, nn)
	if err != nil {
		if k8serrors.IsNotFound(err) {
			// Request object not found, could have been deleted after
			// reconcile request.  Owned objects are automatically
			// garbage collected. For additional cleanup logic use
			// finalizers.  Return and don't requeue
			return ctrl.Result{}, nil
		}
		// Error reading the object - requeue the request.
		return ctrl.Result{}, errors.Wrap(err, "could not load network Node data")
	}

	// If the reconciliation is paused, requeue
	annotations := nn.GetAnnotations()
	if annotations != nil {
		if _, ok := annotations[fscv1.PausedAnnotation]; ok {
			rLogger.Info("host is paused, no work to do")
			return ctrl.Result{Requeue: false}, nil
		}
	}

	// Retreive the Login details from the network node spec and validate
	// the network node details and build the credentials for talking to the
	// network node.
	var targetCreds *discoverer.Credentials
	var targetCredsSecret *corev1.Secret
	haveCreds := false
	switch nn.Status.DiscoveryStatus.State {
	case fscv1.StateNone, fscv1.StateUnmanaged:
		targetCreds = &discoverer.Credentials{}
	default:
		targetCreds, targetCredsSecret, err = r.buildAndValidateProvCredentials(req, nn)
		if err != nil || targetCreds == nil {
			if !nn.DeletionTimestamp.IsZero() {
				// If we are in the process of deletion, try with empty credentials
				targetCreds = &discoverer.Credentials{}
				targetCredsSecret = &corev1.Secret{}
			} else {
				return r.credentialsErrorResult(err, req, nn)
			}
		} else {
			haveCreds = true
		}
	}

	initialState := nn.Status.DiscoveryStatus.State
	info := &reconcileInfo{
		log:               rLogger.WithValues("DiscoverState", initialState),
		nn:                nn,
		request:           req,
		targetCredsSecret: targetCredsSecret,
	}
	disc, err := r.DiscovererFactory(*nn, info.publishEvent)
	if err != nil {
		return ctrl.Result{}, errors.Wrap(err, "failed to create provisioner")
	}

	ready, err := disc.IsReady()

	if err != nil {
		return ctrl.Result{}, errors.Wrap(err, "failed to check services availability")
	}
	if !ready {
		rLogger.Info("provisioner is not ready", "RequeueAfter:", discoveryNotReadyRetryDelay)
		return ctrl.Result{Requeue: true, RequeueAfter: discoveryNotReadyRetryDelay}, nil
	}

	stateMachine := newNetworkNodeStateMachine(nn, r, disc, haveCreds)
	actResult := stateMachine.ReconcileState(info)
	result, err = actResult.Result()

	if err != nil {
		err = errors.Wrap(err, fmt.Sprintf("action %q failed", initialState))
		return
	}

	return ctrl.Result{}, nil
}

// SetupWithManager function
func (r *NetworkNodeReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&fscv1.NetworkNode{}).
		Complete(r)
}

func (r *NetworkNodeReconciler) credentialsErrorResult(err error, request ctrl.Request, nn *fscv1.NetworkNode) (ctrl.Result, error) {
	switch err.(type) {
	// In the event a credential secret is defined, but we cannot find it
	// we requeue the network node as we will not know if they create the secret
	// at some point in the future.
	case *ResolveTargetSecretRefError:
		credentialsMissing.Inc()
		saveErr := r.setErrorCondition(request, nn, fscv1.RegistrationError, err.Error())
		if saveErr != nil {
			return ctrl.Result{Requeue: true}, saveErr
		}
		r.publishEvent(request, nn.NewEvent("TargetCredentialError", err.Error()))

		return ctrl.Result{Requeue: true, RequeueAfter: nnErrorRetryDelay}, nil
	// If a Network Node is missing a Target address or secret, or
	// we have found the secret but it is missing the required fields,
	// or the Target address is defined but malformed, we set the
	// network node into an error state but we do not Requeue it
	// as fixing the secret or the host BMC info will trigger
	// the host to be reconciled again
	case *EmptyTargetAddressError, *EmptyTargetSecretError,
		*discoverer.CredentialsValidationError:
		credentialsInvalid.Inc()
		saveErr := r.setErrorCondition(request, nn, fscv1.RegistrationError, err.Error())
		if saveErr != nil {
			return ctrl.Result{Requeue: true}, saveErr
		}
		// Only publish the event if we do not have an error
		// after saving so that we only publish one time.
		r.publishEvent(request, nn.NewEvent("TargetCredentialError", err.Error()))
		return ctrl.Result{}, nil
	default:
		unhandledCredentialsError.Inc()
		return ctrl.Result{}, errors.Wrap(err, "An unhandled failure occurred with the Target secret")
	}
}

// Make sure the credentials for the network node are valid
// This does not actually try to use the credentials.
func (r *NetworkNodeReconciler) buildAndValidateProvCredentials(request ctrl.Request, nn *fscv1.NetworkNode) (provCreds *discoverer.Credentials, provCredsSecret *corev1.Secret, err error) {
	// Retrieve the secret from Kubernetes for this network node
	provCredsSecret, err = r.getProvSecret(request, nn)
	if err != nil {
		return nil, nil, err
	}

	// Check if address is defined on the network node
	if nn.Spec.Target.Address == "" {
		return nil, nil, &EmptyTargetAddressError{message: "Missing Target connection detail 'Address'"}
	}

	// TODO we could validate the address format

	provCreds = &discoverer.Credentials{
		Username: string(provCredsSecret.Data["username"]),
		Password: string(provCredsSecret.Data["password"]),
	}

	// Verify that the secret contains the expected info.
	err = provCreds.Validate()
	if err != nil {
		return nil, provCredsSecret, err
	}

	return provCreds, provCredsSecret, nil
}

// Retrieve the secret containing the credentials for talking to the Network Node.
func (r *NetworkNodeReconciler) getProvSecret(request ctrl.Request, nn *fscv1.NetworkNode) (provCredsSecret *corev1.Secret, err error) {

	if nn.Spec.Target.CredentialsName == "" {
		return nil, &EmptyTargetSecretError{message: "The Target secret reference is empty"}
	}
	secretKey := nn.CredentialsKey()
	provCredsSecret = &corev1.Secret{}
	err = r.Get(context.TODO(), secretKey, provCredsSecret)
	if err != nil {
		if k8serrors.IsNotFound(err) {
			return nil, &ResolveTargetSecretRefError{message: fmt.Sprintf("The Target secret %s does not exist", secretKey)}
		}
		return nil, err
	}

	return provCredsSecret, nil
}

func (r *NetworkNodeReconciler) setErrorCondition(request ctrl.Request, nn *fscv1.NetworkNode, errType fscv1.ErrorType, message string) (err error) {
	rLogger := r.Log.WithValues("networknode", request.NamespacedName)

	setErrorMessage(nn, errType, message)

	rLogger.Info(
		"adding error message",
		"message", message,
	)
	err = r.saveHostStatus(nn)
	if err != nil {
		err = errors.Wrap(err, "failed to update error message")
	}

	return
}

// setErrorMessage updates the ErrorMessage in the network Node Status struct
// and increases the ErrorCount
func setErrorMessage(nn *fscv1.NetworkNode, errType fscv1.ErrorType, message string) {
	nn.Status.OperationalStatus = fscv1.OperationalStatusError
	nn.Status.ErrorType = errType
	nn.Status.ErrorMessage = message
	nn.Status.ErrorCount++
}

// Manage deletion of the host
func (r *NetworkNodeReconciler) actionDeleting(disc discoverer.Discoverer, info *reconcileInfo) actionResult {
	info.log.Info(
		"marked to be deleted",
		"timestamp", info.nn.DeletionTimestamp,
	)

	// no-op if finalizer has been removed.
	if !utils.StringInList(info.nn.Finalizers, fscv1.NetworkNodeFinalizer) {
		info.log.Info("ready to be deleted")
		return deleteComplete{}
	}

	discResult, err := disc.Delete()
	if err != nil {
		return actionError{errors.Wrap(err, "failed to delete")}
	}
	if discResult.Dirty {
		return actionContinue{discResult.RequeueAfter}
	}

	// Remove finalizer to allow deletion
	info.nn.Finalizers = utils.FilterStringFromList(
		info.nn.Finalizers, fscv1.NetworkNodeFinalizer)
	info.log.Info("cleanup is complete, removed finalizer",
		"remaining", info.nn.Finalizers)
	if err := r.Update(context.Background(), info.nn); err != nil {
		return actionError{errors.Wrap(err, "failed to remove finalizer")}
	}

	return deleteComplete{}
}

func (r *NetworkNodeReconciler) saveHostStatus(nn *fscv1.NetworkNode) error {
	t := metav1.Now()
	nn.Status.LastUpdated = &t

	return r.Status().Update(context.TODO(), nn)
}

func (r *NetworkNodeReconciler) publishEvent(request ctrl.Request, event corev1.Event) {
	rLogger := r.Log.WithValues("networknode", request.NamespacedName)
	rLogger.Info("publishing event", "reason", event.Reason, "message", event.Message)
	err := r.Create(context.TODO(), &event)
	if err != nil {
		rLogger.Info("failed to record event, ignoring",
			"reason", event.Reason, "message", event.Message, "error", err)
	}
	return
}

// A network node reaching this action handler should be ready
func (r *NetworkNodeReconciler) actionManageReady(disc discoverer.Discoverer, info *reconcileInfo) actionResult {
	info.log.Info("actionManageReady")

	return actionComplete{}
}

// Ensure we have the information about the hardware on the host.
func (r *NetworkNodeReconciler) actionInspecting(disc discoverer.Discoverer, info *reconcileInfo) actionResult {
	info.log.Info("inspecting hardware")

	return actionComplete{}
}

// Ensure we have the information about the hardware on the host.
func (r *NetworkNodeReconciler) actionUnmanaged(disc discoverer.Discoverer, info *reconcileInfo) actionResult {
	info.log.Info("actionUnmanaged ")

	return actionComplete{}
}
