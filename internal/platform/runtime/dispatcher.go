// Package runtime validates role dispatch and runs only explicitly registered roles.
package runtime

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/sanskarpan/keel/internal/platform/config"
)

var ErrRoleNotRegistered = errors.New("runtime role has no implementation registered")

type Runner func(context.Context) error

type Registry map[config.Role]Runner

// Dispatch fails closed for roles that are recognized by configuration but not yet wired.
func Dispatch(ctx context.Context, role config.Role, registry Registry) error {
	runner := registry[role]
	if runner == nil {
		return fmt.Errorf("%w: %s", ErrRoleNotRegistered, role)
	}
	return runner(ctx)
}
