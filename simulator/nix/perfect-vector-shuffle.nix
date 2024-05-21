{ lib, mkDerivation, base, fetchgit, MonadRandom, primitive, random, vector, QuickCheck, quickcheck-instances, tasty, tasty-quickcheck }:
mkDerivation {
  pname = "perfect-vector-shuffle";
  version = "0.1.1.1";
  src = fetchgit {
    url = "https://github.com/Boarders/perfect-vector-shuffle.git";
    sha256 = "0b47vqpdlvqdzzcyj82sndwalln03z3gnhv5ffb4y3gdafr4f1mn";
    # install nix-prefetch-scripts , then nix-prefetch-git ... to get sha256 for this rev (i.e., for this commit)
    rev = "501b61b4dbc189f1bb8e2080ccfd85473f2ac554";
    fetchSubmodules = true;
  };
  # postUnpack = "sourceRoot+=/perfect-vector-shuffle; echo source root reset to $sourceRoot";
  libraryHaskellDepends = [
    base MonadRandom primitive random vector
  ];
  testHaskellDepends = [
    base MonadRandom primitive random vector QuickCheck quickcheck-instances tasty tasty-quickcheck
  ];
  description = "Shuffle vectors";
  license = lib.licenses.bsd3;
}
