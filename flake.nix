{
  description = "Proton VPN WireGuard configuration manager";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs =
    { self, nixpkgs }:
    let
      supportedSystems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems = nixpkgs.lib.genAttrs supportedSystems;
      pkgsFor = system: nixpkgs.legacyPackages.${system};
      pythonDeps =
        ps: with ps; [
          aiohttp
          distro
          proton-core
          proton-vpn-api-core
          requests
        ];
    in
    {
      packages = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
          python = pkgs.python3;
        in
        {
          default = self.packages.${system}.protonvpn-get;
          protonvpn-get = python.pkgs.buildPythonApplication {
            pname = "protonvpn-get";
            version = "0.1.0";
            src = ./.;
            format = "other";

            propagatedBuildInputs = pythonDeps python.pkgs;

            dontBuild = true;

            installPhase = ''
              runHook preInstall
              install -Dm755 __main__.py $out/bin/protonvpn-get
              install -Dm755 to_nix.py $out/bin/to_nix
              runHook postInstall
            '';
          };
        }
      );

      devShells = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
        in
        {
          default = pkgs.mkShell {
            packages = [
              (pkgs.python3.withPackages pythonDeps)
              pkgs.ruff
            ];
          };
        }
      );
    };
}
