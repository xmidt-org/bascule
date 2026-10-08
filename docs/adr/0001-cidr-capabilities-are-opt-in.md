---
status: accepted
---
<!--
SPDX-FileCopyrightText: 2026 Comcast Cable Communications Management, LLC
SPDX-License-Identifier: Apache-2.0
-->

# CIDR capabilities are opt-in and fail closed when malformed

`basculecaps` denies a Token that carries no endpoint capabilities, because endpoint capabilities *grant* access. CIDR capabilities only *limit* access, so the CIDR Approver does the opposite: a Token with no CIDR capabilities is **Unrestricted** unless the Approver is configured as **Required**. That lets services add network limits client by client without breaking every existing Token. A **Malformed Capability** still counts as present but matches nothing, so an issuer's typo can never silently remove a restriction. Each Approver owns its own prefix, parsing and malformed handling; bascule has no shared framework of capability kinds, because only the service enforcing a kind can see or explain its mistakes.

## Considered Options

- **Deny when there are no CIDR capabilities, like `basculecaps`.** Rejected: every current Token would break as soon as the check was turned on.
- **Ignore malformed capabilities.** Rejected: if the only CIDR capability had a typo, the Token would quietly become Unrestricted.
- **A shared capability-kind registry in bascule.** Rejected: it couples unrelated checks (CIDR, rate, TR-181 parameters) that belong in different libraries.

## Consequences

- A typo in the *prefix* still goes undetected, because the capability is just ignored. Use **Required** where a network limit must always be present.
- Turning on **Required** can be trial-run first: the Permissive Required mode warns about every Token that Required would reject, without blocking it.
- Approvers need a way to report warnings without failing the request; see `docs/caller-origin-and-cidr.md`.
