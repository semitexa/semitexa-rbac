<?php

declare(strict_types=1);

namespace Semitexa\Rbac\Domain\Contract;

use Semitexa\Authorization\Domain\Contract\CapabilityInterface;

/**
 * Provides capability lookup for a SERVICE-domain principal.
 *
 * Parallel to {@see CapabilityProviderInterface} but operates on the service
 * authorization domain — webhook principals, machine tokens, partner
 * integrations, internal service callers. The two providers are deliberately
 * separated so a User capability grant cannot accidentally satisfy a Service
 * route and vice versa.
 *
 * The serviceId parameter mirrors what the principal's getId() returns:
 *   - WebhookPrincipal::getId() — stable receiver name (endpointKey)
 *   - MachinePrincipal::getId() — machine credential id
 *   - any future ServicePrincipal — its own stable identifier
 *
 * The tenantId parameter is the resolved tenant for the current request
 * (from {@see \Semitexa\Core\Tenant\TenantContextStoreInterface}), or null
 * when no tenant context has been resolved (CLI tasks without
 * `tenant:run`, system-wide health checks, single-tenant deployments).
 * Multi-tenant production providers MUST scope grants by tenant — a grant
 * that authorizes service `partner-x` in tenant A must NOT authorize the
 * same `partner-x` id in tenant B. Providers that ignore the tenantId
 * parameter remain backward-compatible but are unsafe in multi-tenant
 * deployments.
 *
 * Without an installed implementation, every service principal receives an
 * empty capability grant set — every #[RequiresCapability] on an
 * #[AsServicePayload] route returns 403. This is the safe default.
 */
interface ServiceCapabilityProviderInterface
{
    /**
     * @return list<CapabilityInterface>
     */
    public function getCapabilitiesForService(string $serviceId, ?string $tenantId = null): array;
}
