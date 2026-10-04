package runtime

import (
	"context"
	"errors"
	"testing"

	"github.com/sanskarpan/keel/internal/platform/config"
)

func TestDispatchRunsRegisteredRole(t *testing.T) {
	called := false
	err := Dispatch(context.Background(), config.RoleAPI, Registry{
		config.RoleAPI: func(context.Context) error { called = true; return nil },
	})
	if err != nil || !called {
		t.Fatalf("registered role did not run: called=%v err=%v", called, err)
	}
}

func TestDispatchRejectsUnwiredRole(t *testing.T) {
	err := Dispatch(context.Background(), config.RoleAPI, Registry{})
	if !errors.Is(err, ErrRoleNotRegistered) {
		t.Fatalf("expected fail-closed error, got %v", err)
	}
}
