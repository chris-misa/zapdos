let
  grpc-nixpkgs = import ./gRPC-haskell/nixpkgs.nix;
  grpc-overlay = (import ./gRPC-haskell/release.nix).overlay;
  pkgs = grpc-nixpkgs { overlays = [ grpc-overlay ]; };
  haskellPackages = pkgs.haskellPackages.extend (self: super: { });
in
  haskellPackages.developPackage {
    root = ./.;
    modifier = drv:
      pkgs.haskell.lib.addBuildTools drv (with pkgs.haskellPackages;
        [ cabal-install
          grpc-haskell
        ]);
    # source-overrides = {
    #   perfect-vector-shuffle = import ./nix/perfect-vector-shuffle.nix;
    # };
    overrides = self: super: {
      perfect-vector-shuffle = self.callPackage ./nix/perfect-vector-shuffle.nix { };
    };
  }
