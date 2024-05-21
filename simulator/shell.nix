with import <nixos> {};
let
  compiler = haskell.packages.ghc8107.extend (self: super: {
    perfect-vector-shuffle = self.callPackage ./nix/perfect-vector-shuffle.nix { };
  });
  myHaskell = compiler.ghcWithPackages (pkgs: with pkgs; [
        vector
        vector-strategies
        perfect-vector-shuffle
        bitvec
        unagi-chan
        pcap
        bytestring
        binary
        hashable
        hashtables
        deepseq
        containers
        unordered-containers
        random-fu
        mersenne-random-pure64
        cassava
        mtl
        rvar
        parallel
        monad-loops
        split
      ]);
in mkShell {
  buildInputs = [
    myHaskell
  ];
  shellHook = '''';
}
