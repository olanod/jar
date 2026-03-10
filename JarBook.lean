import VersoManual
import Jar

import JarBook.Notation
import JarBook.Constants
import JarBook.State
import JarBook.PVM

open Verso.Genre Manual

set_option pp.rawOnError true

#doc (Manual) "JAR: JAM Axiomatic Reference" =>
%%%
authors := ["JAR Contributors"]
%%%

JAR (JAM Axiomatic Reference) is a Lean 4 formalization of the JAM blockchain
protocol as specified in the Gray Paper v0.7.2.

Each chapter corresponds to a section of the Gray Paper, presenting the
formal Lean definitions alongside explanatory prose.

{include 0 JarBook.Notation}

{include 0 JarBook.Constants}

{include 0 JarBook.State}

{include 0 JarBook.PVM}
