import VersoManual
import Jar.Services

open Verso.Genre Manual
open Jar.Services

set_option verso.docstring.allowMissing true

#doc (Manual) "Service Invocations" =>

Service entry points that the protocol invokes via the JAVM (GP §11, Appendix B).

In jar1, service code runs inside the capability kernel. Protocol capabilities
(GAS, FETCH, STORAGE\_R, etc.) replace direct host-call numbers — the kernel
dispatches `ecalli` to the appropriate protocol cap, which exits to the host.
Nested REPLY returns results to the calling VM; the root VM terminates via the
GP halt convention — a djump to the halt address 2^32 − 2^16 (installed in
ω\[0\] at initialization), with the output read from μ\[φ7..+φ8\].
See the *Capability Kernel* chapter for the execution model.

# Storage Affordability

{docstring Jar.Services.canAffordStorage}

# Is-Authorized

The is-authorized invocation checks whether a work-package's authorization token
is accepted by the service's authorizer code.

{docstring Jar.Services.isAuthorized}

# Refinement

Refinement transforms a work item into a work result by running the service's
refine code in the JAVM.

{docstring Jar.Services.RefineContext}

{docstring Jar.Services.ImportResolver}

{docstring Jar.Services.refine}

# Work-Report Computation

Combines is-authorized and refinement to produce a complete work report
from a work package.

{docstring Jar.Services.computeWorkReport}

# Accumulation Input

{docstring Jar.Services.AccumulationInput}

Deferred transfers are integrated as accumulation inputs
(`AccumulationInput.transfer`) rather than through a separate on-transfer
entry point, matching current graypaper (Ψ\_T removed).

# Auditing

{docstring Jar.Services.auditWorkReport}

# Host-Call Interface

{docstring Jar.Services.HostCall}

