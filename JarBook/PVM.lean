import VersoManual
import Jar.PVM
import Jar.PVM.Interpreter

open Verso.Genre Manual

#doc (Manual) "Polkadot Virtual Machine" =>

The PVM is a RISC-V rv64em-based virtual machine for executing service code
(Gray Paper Appendix A).

# Machine Model

{docstring Jar.PVM.Memory}

{docstring Jar.PVM.MachineState}

{docstring Jar.PVM.ExitReason}

{docstring Jar.PVM.InvocationResult}

# Program Representation

{docstring Jar.PVM.Program}

# Execution

{docstring Jar.PVM.run}
