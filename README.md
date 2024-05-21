# ZAPDOS Source Code

This repo contains source code for [ZAPDOS](https://onrg.gitlab.io/pub/SnP2024_ZAPDOS_FinalWeb.pdf).

* Author: Chris Misa
* Last Updated: 2024-05-21
* See LICENSE for usage conditions.

# Contents

* `./simulator/` contains the Haskell implementation of our packet-level simulator of ZAPDOS.
* `./tofino/` contains the Tofino implementation of ZAPDOS including the data plane p4 program and the Haskell runtime implementation.
* `./data-generation/` contains some scripts used in our data-fusion methodology. (This directory is probably the least complete at this point.)

# Notes

This repo is currently an un-tested work in progress. If you feel like something important is missing, please contact the authors at cmisa@cs.uoregon.edu. We will happily work to add any missing files or scripts.

We use the [nix](https://nixos.org/) package manager and have tried to include definitions for the required environments. If you notice a missing definition or have to update a definition (e.g., to support more recent versions of the nix Haskell libraries which seem to break pretty quickly), please let us know and/or submit a pull request.

