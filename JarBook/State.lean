import VersoManual
import Jar.State

open Verso.Genre Manual

#doc (Manual) "State and Transitions" =>

The block-level state transition function `Y(sigma, B) = sigma'` (GP eq 4.1).

# State Structure

{docstring Jar.State}

{docstring Jar.RecentHistory}

{docstring Jar.RecentBlockInfo}

{docstring Jar.ActivityStatistics}

# Timekeeping

{docstring Jar.newTimeslot}

{docstring Jar.epochIndex}

{docstring Jar.isEpochChange}

# Header Validation (section 5)

{docstring Jar.validateHeader}

{docstring Jar.validateExtrinsic}

# State Transition

{docstring Jar.stateTransition}
