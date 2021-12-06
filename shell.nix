let
  nixpkgs = import <nixpkgs> {};
in
  with nixpkgs;
  stdenv.mkDerivation {
    name = "write-your-own-traceroute";
    buildInputs = [
      traceroute
    ];
  }
