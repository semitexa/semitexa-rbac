<?php

declare(strict_types=1);

namespace Semitexa\Rbac;

use Semitexa\Core\Attribute\Capability;

/**
 * What this package offers, for the capability catalog.
 *
 * Without this the package is invisible to anyone whose project has not
 * installed it - which is precisely the audience worth telling, since they are
 * the ones about to build it by hand. The convention is one `Capabilities` class
 * per package: a definite place to look, and a definite place for a guard to
 * check.
 *
 * Nothing reads this at runtime.
 */
#[Capability(
    id: 'rbac.roles',
    summary: 'Roles granting permissions and capabilities, resolved into the grant set the authorizer asks for.',
    useWhen: 'Access depends on named roles that someone administers, not on properties of the record.',
    avoidWhen: 'Grants come from somewhere else already - ownership, a plan tier, an external identity provider.',
    replaces: [
        'a roles column parsed into an array and compared by string in each check',
        'a permission matrix kept in a config file and in a database, drifting apart',
    ],
    seeAlso: 'semitexa/authorization',
)]
final class Capabilities
{
}
