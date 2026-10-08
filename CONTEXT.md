<!--
SPDX-FileCopyrightText: 2026 Comcast Cable Communications Management, LLC
SPDX-License-Identifier: Apache-2.0
-->

# bascule

A library for authenticating requests (turning credentials into a **Token**) and authorizing them (deciding whether a **Token** may do what a request asks), with HTTP support.

## Language

### Tokens and capabilities

**Token**:
The authenticated result of a request's credentials, e.g. a verified JWT. It may carry **Capabilities**.
_Avoid_: SAT (internal jargon), credential (that's what a Token is made from)

**Capability**:
One flat string carried by a **Token** that grants or limits access. A Token's capabilities may serve many services; each **Approver** only looks at the ones its **Capability Prefix** selects.
_Avoid_: permission, scope, claim

**Capability Prefix**:
A configured string or regular expression that selects which of a **Token**'s **Capabilities** an **Approver** honors. Nothing is built in; capabilities matching no prefix are ignored silently.
_Avoid_: namespace

**Approver**:
One independent authorization check over a request and its **Token**. A request is authorized only if every Approver allows it. Each Approver owns everything about its kind of **Capability**: selecting, parsing, and handling malformed ones.

**Endpoint Capability**:
A **Capability** granting an HTTP method on a URL pattern (e.g. `{prefix}device/.*/config:get`). A **Token** with none is denied: endpoint capabilities grant access.

**CIDR Capability**:
A **Capability** naming a network range (e.g. `{prefix}10.0.0.0/8`) the **Caller Origin** must fall within. It only limits; it never grants.

### Limiting capabilities

**Unrestricted**:
The state of a **Token** that carries no **CIDR Capability**: no network limit applies, unless the CIDR check is **Required**.

**Required**:
A setting on a limiting check under which a **Token** must carry at least one of its **Capabilities**, and each must be valid; a Token carrying none fails instead of being **Unrestricted**. The opposite is **Correct If Present**.

**Correct If Present**:
The default setting on a limiting check: a **Token** carrying none of its **Capabilities** is **Unrestricted**, but any it does carry must be valid and must match.

**Malformed Capability**:
A **Capability** selected by a **Capability Prefix** whose remainder cannot be parsed. It still counts as present (so the **Token** is not **Unrestricted**) but matches nothing.

**Permissive**:
A mode in which a failing check lets the request through and reports what it would have rejected as a **Capability Warning**. The opposite is **Enforcing**. It combines with **Required** or **Correct If Present**; Permissive Required is a trial run of Required that warns on every **Token** missing the check's **Capabilities**.

**Capability Warning**:
A note for the caller describing a problem with their **Token** or request, e.g. a **Malformed Capability** or a check that failed in **Permissive** mode. Returned whether or not the request is blocked.

### Networks

**Caller Origin**:
The single address a request is taken to have come from: the nearest hop that is not a **Trusted Proxy**.
_Avoid_: client IP, remote address, source IP

**Trusted Proxy**:
A network hop the deployment operates (e.g. a load balancer) and trusts to report the address it received a request from. Always deployment configuration; never carried in a **Token**.

## Example dialogue

> **Dev:** The token has `prefix:cidr:10.0.0.0/33` and nothing else under that prefix.
> **Domain expert:** That's a **Malformed Capability**. The token isn't **Unrestricted**, because the capability still counts, but it matches no **Caller Origin**, so the CIDR **Approver** rejects the request, or lets it through with a **Capability Warning** if it's **Permissive**.
> **Dev:** And if the request came through our load balancer?
> **Domain expert:** The load balancer is a **Trusted Proxy**, so the **Caller Origin** is the address it reports, not the load balancer's own.
