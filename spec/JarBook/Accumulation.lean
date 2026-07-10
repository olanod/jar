import VersoManual
import Jar.Accumulation

open Verso.Genre Manual
open Jar.Accumulation

set_option verso.docstring.allowMissing true

#doc (Manual) "Accumulation" =>

The accumulation pipeline integrates refined work results into on-chain state
(GP §12). It proceeds in three stages: `accseq` orchestrates sequentially,
`accpar` parallelizes across services, and `accone` handles a single service
via JAVM execution with 28 protocol-capability host-call dispatch entries
(slots 1–28; slot 0 is the kernel IPC slot).

In jar1, accumulation runs through the capability kernel. The kernel's
`runKernel` function executes service code until a protocol cap is invoked,
at which point control returns to the host. The host handles the protocol
operation (storage read/write, transfer, etc.) and calls `resumeProtocolCall`
to continue execution. Host-call numbering in jar1 is 1-28 (protocol cap slots),
not 0-27 as in gp072. See the *Capability Kernel* chapter for the execution model.

# Data Types

{docstring Jar.Accumulation.OperandTuple}

{docstring Jar.Accumulation.AccInput}

{docstring Jar.Accumulation.PartialState}

{docstring Jar.Accumulation.PartialState.fromState}

{docstring Jar.Accumulation.AccOneOutput}

{docstring Jar.Accumulation.AccContext}

# Host Calls (§12.4)

All 28 protocol-cap host-call handlers (slots 1–28) are dispatched by
`handleHostCall`. Slot 0 is the kernel IPC slot (REPLY), handled inside the
capability kernel: nested REPLY returns to the calling VM, while root-level
REPLY is a panic — the root VM terminates via the GP halt convention (djump
to the halt address 2^32 − 2^16, with the accumulation output read from
μ\[φ7..+φ8\]). Each protocol cap costs a base gas of 10. Operations include
reading/writing service storage, transferring balance, managing preimages,
and creating or upgrading services.

{docstring Jar.Accumulation.hostCallGas}

{docstring Jar.Accumulation.handleHostCall}

# Single-Service Accumulation

{docstring Jar.Accumulation.accone}

# Pipeline

{docstring Jar.Accumulation.groupByService}

{docstring Jar.Accumulation.groupTransfersByDest}

{docstring Jar.Accumulation.accpar}

{docstring Jar.Accumulation.accseq}

# Block-Level Accumulation

{docstring Jar.Accumulation.AccumulationResult}

{docstring Jar.Accumulation.accumulate}
