{
  description = "The IP Calculator is a command-line tool written in Golang that assists in managing IPv4 addresses, subnetting, IPv6 shortening, and various networking operations.";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs";
    utils.url = "github:numtide/flake-utils";
  };

  outputs =
    inputs@{ nixpkgs
    , utils
    , ...
    }:
    utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = nixpkgs.legacyPackages.${system};

        nativeBuildInputs = with pkgs; [
          go
          gopls
        ];
        buildInputs = with pkgs; [ ];
      in
      {
        devShells.default = pkgs.mkShell { inherit nativeBuildInputs buildInputs; };

        packages.default = pkgs.buildGoModule rec {
          name = "ip-calculator";
          src = ./.;

          inherit buildInputs;

          vendorHash = null;
        };
      }
    );
}
