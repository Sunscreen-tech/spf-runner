{
  description = "FHE tools and Python client";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    crane.url = "github:ipetkov/crane";
    sunscreen-llvm = {
      url = "github:Sunscreen-tech/sunscreen-llvm/sunscreen";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, flake-utils, rust-overlay, crane, sunscreen-llvm }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ (import rust-overlay) ];
        };

        rustToolchain = pkgs.rust-bin.stable.latest.default.override {
          extensions = [ "rust-src" "rust-analyzer" ];
        };

        craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;

        # Sunscreen LLVM compiler for parasol target
        sunscreen-llvm-pkg = sunscreen-llvm.packages.${system}.default;

      in {
        packages = {
          # Build program_runner
          program-runner = craneLib.buildPackage {
            src = craneLib.cleanCargoSource ./.;
            strictDeps = true;
          };

          default = self.packages.${system}.program-runner;
        };

        devShells.default = pkgs.mkShellNoCC {
          nativeBuildInputs = [ sunscreen-llvm-pkg ];

          buildInputs = with pkgs; [
            rustToolchain
            python312
            uv
            maturin
            cargo-watch
            ruff
            pyright
          ];

          shellHook = ''
            export CLANG=${sunscreen-llvm-pkg}/bin/clang
            export CLANG_DIR=${sunscreen-llvm-pkg}/bin
            export LLVM_DIR=${sunscreen-llvm-pkg}/bin

            # Prevent uv from downloading Python binaries (use Nix-provided Python)
            export UV_PYTHON_DOWNLOADS=never

            echo "SPF Runner development environment"
            echo ""
            echo "Compilers:"
            echo "  clang (parasol target) - $CLANG"
            echo ""
            echo "Python development:"
            echo "  uv sync              - Set up Python environment"
            echo "  maturin develop      - Build and install tfhe_client locally"
            echo ""
            echo "FHE program compilation:"
            echo "  make -C fhe-programs/src  - Compile FHE programs"
          '';
        };
      }
    );
}
