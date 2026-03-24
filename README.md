# semitexa/rbac

Role-based access control with roles, capability grants, and per-request decision caching.

## Purpose

Implements the `GrantResolverInterface` from Authorization. Resolves capabilities and permissions for authenticated subjects by querying role assignments and caching decisions per request.

## Role in Semitexa

Depends on `semitexa/core` and `semitexa/authorization`. Delegates to `PermissionProviderInterface` implementations (e.g., `semitexa/platform-user`) for backend storage of role assignments and permission grants.

## Key Features

- `SubjectGrantResolver` resolves grants from role assignments
- `CapabilityRegistry` with auto-discovery
- `RbacDecisionCache` for per-request caching
- `PermissionProviderInterface` delegates to backend storage
- Pluggable grant resolution chain
