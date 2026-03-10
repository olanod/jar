import Jar.Notation
import Jar.Types
import Jar.Crypto
import Jar.PVM

/-!
# Services — §9, §12, §14

Service account model, accumulation, refinement, and the work pipeline.
References: `graypaper/text/accounts.tex`, `graypaper/text/accumulation.tex`,
            `graypaper/text/work_packages_and_reports.tex`,
            `graypaper/text/authorization.tex`.

## Structure
- §9: Service account model and minimum balance
- §8: Authorization: is-authorized Ψ_I
- §14: Refinement: work-item execution Ψ_R
- §12: Accumulation: on-chain processing Ψ_A
- §14.12: Work-report computation Ξ(p, c)
- §17: Auditing protocol
-/

namespace Jar.Services

-- ============================================================================
-- §9 — Minimum Balance
-- ============================================================================

/-- Minimum balance for a service account. GP eq (9.8).
    Accounts must maintain sufficient balance to cover their storage costs.
    min_balance(a) = B_S + B_I × |items| + B_L × |bytes|
    where items/bytes count storage and preimage entries. -/
def minimumBalance (acct : ServiceAccount) : Balance :=
  let itemCount := acct.storage.entries.length + acct.preimageInfo.entries.length
  let byteCount := acct.preimages.entries.foldl (init := 0)
    fun acc kv => acc + kv.2.size
  UInt64.ofNat (Jar.B_S + Jar.B_I * itemCount + Jar.B_L * byteCount)

-- ============================================================================
-- §8 — Authorization
-- ============================================================================

/-- Ψ_I : Is-authorized invocation. GP §8.
    Executes the authorizer code to check if a work-package is authorized
    for a given core. Returns true if the authorizer accepts.
    Input: authorizer code hash + authorization token.
    Runs in PVM with limited gas. -/
opaque isAuthorized
    (authorizerCode : ByteArray)
    (authToken : ByteArray)
    (gasLimit : Gas) : Bool × Gas :=
  (false, 0)

-- ============================================================================
-- §14 — Refinement (In-Core Computation)
-- ============================================================================

/-- Ψ_R : Refine invocation. GP §14.
    Executes a work-item's refinement code in the PVM.
    Input: service code, payload, gas limit, imported segments.
    Output: refinement result (output blob or error) + gas used. -/
opaque refine
    (serviceCode : ByteArray)
    (payload : ByteArray)
    (gasLimit : Gas)
    (imports : Array ByteArray) : WorkResult × Gas :=
  (.err .panic, 0)

/-- Ξ(p, c) : Work-report computation. GP eq (14.12).
    Given a work-package p and context c, computes the work-report
    by running authorization and then refining each work-item.
    Returns (work-report, auth-gas-used). -/
opaque computeWorkReport
    (pkg : WorkPackage)
    (context : RefinementContext) : Option (WorkReport × Gas) :=
  none

-- ============================================================================
-- §12 — Accumulation (On-Chain Processing)
-- ============================================================================

/-- Accumulation input: either an operand (from work-report) or a transfer. -/
inductive AccumulationInput where
  /-- Operand from a work-report result. -/
  | operand : WorkDigest → AccumulationInput
  /-- Deferred transfer from another service. -/
  | transfer : DeferredTransfer → AccumulationInput

/-- Ψ_A : Accumulate invocation. GP §12.
    Executes a service's accumulation code with a batch of inputs.
    Runs on-chain in the PVM with host-call support for:
    - Storage read/write (Ω_R, Ω_W)
    - Service lookup (Ω_L)
    - Balance transfers (Ω_T)
    - New service creation (Ω_N)
    - Code upgrade (Ω_U)
    Returns updated service account state. -/
opaque accumulate
    (serviceCode : ByteArray)
    (serviceId : ServiceId)
    (gasLimit : Gas)
    (inputs : Array AccumulationInput)
    (acct : ServiceAccount)
    (services : Dict ServiceId ServiceAccount) : ServiceAccount × Gas :=
  (acct, 0)

-- ============================================================================
-- §12 — On-Transfer Handler
-- ============================================================================

/-- Ψ_T : On-transfer invocation. GP §12.
    Called when a service receives a deferred transfer.
    Minimal gas budget for lightweight processing. -/
opaque onTransfer
    (serviceCode : ByteArray)
    (serviceId : ServiceId)
    (transfer : DeferredTransfer)
    (acct : ServiceAccount) : ServiceAccount :=
  acct

-- ============================================================================
-- §17 — Auditing
-- ============================================================================

/-- Check if a work-report is valid by re-executing the refinement.
    Used by auditors to verify guarantor claims. GP §17. -/
opaque auditWorkReport
    (report : WorkReport)
    (pkg : WorkPackage)
    (context : RefinementContext) : Bool :=
  false

-- ============================================================================
-- §12 — Host-Call Interface (Summary)
-- ============================================================================

/-- Host-call identifiers available during accumulation. GP §12. -/
inductive HostCall where
  | gas          -- Ω_G : Query remaining gas
  | lookup       -- Ω_L : Lookup value in service storage
  | read         -- Ω_R : Read from own storage
  | write        -- Ω_W : Write to own storage
  | info         -- Ω_I : Service info query
  | bless        -- Ω_B : Set privileged services (manager only)
  | assign       -- Ω_A : Assign core authorization
  | designate    -- Ω_D : Designate validator keys
  | checkpoint   -- Ω_C : Checkpoint gas
  | newService   -- Ω_N : Create new service
  | upgrade      -- Ω_U : Upgrade service code
  | transfer     -- Ω_T : Transfer balance
  | quit         -- Ω_Q : Remove service
  | solicit      -- Ω_S : Solicit preimage
  | forget       -- Ω_F : Forget preimage
  | historicalLookup -- Ω_H : Historical state lookup
  | fetch        -- Ω_E : Fetch preimage data
  | yield        -- Ω_Y : Yield accumulation output
  | provide      -- Ω_P : Provide preimage data
  | empower      -- Ω_M : Empower (privileged operations)
  deriving BEq

end Jar.Services
