# Semitexa RBAC

Role-based access control with roles, capability grants, and per-request decision caching.

## Install

Included in every project created by the installer (https://semitexa.com/install.sh).

## Purpose

Implements `SubjectGrantResolverInterface` from `semitexa/authorization` (`SubjectGrantResolver`). Resolves capabilities and permissions for authenticated subjects by querying role assignments and caching decisions per request.

## Role in Semitexa

Depends on `semitexa/core` and `semitexa/authorization`. Delegates to `PermissionProviderInterface` and `CapabilityProviderInterface` implementations, which the application provides, for the storage of role assignments and permission grants. No Semitexa package ships a `PermissionProviderInterface` implementation.

## Key Features

- `SubjectGrantResolver` resolves grants from role assignments
- `CapabilityRegistry` with auto-discovery
- `RbacDecisionCache` for per-request caching
- `PermissionProviderInterface` delegates to backend storage
- Pluggable grant resolution chain

Docs: https://semitexa.com/docs/auth/rbac
