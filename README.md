# Semitexa RBAC

Role-based access control with roles, capability grants, and per-request decision caching.

## Install

Included in every project created by the installer (https://semitexa.com/install.sh).

## Purpose

Implements `SubjectGrantResolverInterface` from `semitexa/authorization` (`SubjectGrantResolver`). Resolves capabilities and permissions for authenticated subjects by querying role assignments and caching decisions per request.

## Role in Semitexa

Depends on `semitexa/core` and `semitexa/authorization`. Delegates to `PermissionProviderInterface` and `CapabilityProviderInterface` implementations for the storage of role assignments and permission grants. `semitexa/platform-user` ships one: stored roles assigned with `role:create` / `role:assign` (`StoredRolePermissionProvider`); a project can add its own, and their grants add up.

## Key Features

- `SubjectGrantResolver` resolves grants from role assignments
- `CapabilityRegistry` with auto-discovery
- `RbacDecisionCache` for per-request caching
- `PermissionProviderInterface` delegates to backend storage
- Pluggable grant resolution chain

Docs: https://semitexa.com/docs/auth/rbac
