package caseworkflow

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/sanskarpan/keel/internal/platform/tenancy"
	"go.temporal.io/api/enums/v1"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/worker"
	"go.temporal.io/sdk/workflow"
)

var ErrWrongWorkflowRun = errors.New("Temporal returned an unexpected workflow identity")

type SignalWithStartClient interface {
	SignalWithStartWorkflow(context.Context, string, string, any, client.StartWorkflowOptions, any, ...any) (client.WorkflowRun, error)
}

type Sender struct {
	client SignalWithStartClient
}

func NewSender(temporalClient SignalWithStartClient) (*Sender, error) {
	if temporalClient == nil {
		return nil, errors.New("Temporal client is required")
	}
	return &Sender{client: temporalClient}, nil
}

// Deliver uses SignalWithStart as an atomic start-or-signal operation. A transport
// acknowledgement can be lost after Temporal persists the signal; the dispatcher
// may safely retry because SupplierCaseWorkflow deduplicates by version and identity.
func (s *Sender) Deliver(ctx context.Context, tenant tenancy.TenantID, signal EventSignal) error {
	if s == nil || s.client == nil || ctx == nil {
		return errors.New("Temporal sender and context are required")
	}
	if _, err := tenancy.ParseTenantID(string(tenant)); err != nil {
		return err
	}
	if err := signal.Validate(); err != nil {
		return err
	}
	workflowID, err := WorkflowID(tenant, signal.CaseID)
	if err != nil {
		return err
	}
	run, err := s.client.SignalWithStartWorkflow(ctx, workflowID, SignalName, signal, client.StartWorkflowOptions{
		ID:                       workflowID,
		TaskQueue:                TaskQueue,
		WorkflowIDReusePolicy:    enums.WORKFLOW_ID_REUSE_POLICY_REJECT_DUPLICATE,
		WorkflowIDConflictPolicy: enums.WORKFLOW_ID_CONFLICT_POLICY_USE_EXISTING,
	}, SupplierCaseWorkflow, WorkflowInput{CaseID: signal.CaseID})
	if err != nil {
		return fmt.Errorf("signal supplier case workflow: %w", err)
	}
	if run == nil || run.GetID() != workflowID || strings.TrimSpace(run.GetRunID()) == "" {
		return ErrWrongWorkflowRun
	}
	return nil
}

func Register(w worker.Worker) error {
	if w == nil {
		return errors.New("Temporal worker is required")
	}
	w.RegisterWorkflowWithOptions(SupplierCaseWorkflow, workflow.RegisterOptions{Name: WorkflowName})
	return nil
}

func Dial(ctx context.Context, address, namespace string) (client.Client, error) {
	if ctx == nil || strings.TrimSpace(address) == "" || strings.TrimSpace(namespace) == "" {
		return nil, errors.New("Temporal address, namespace, and context are required")
	}
	return client.DialContext(ctx, client.Options{HostPort: strings.TrimSpace(address), Namespace: strings.TrimSpace(namespace)})
}
