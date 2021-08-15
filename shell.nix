let
  flake = import
    (fetchTarball {
      url = "https://github.com/edolstra/flake-compat/archive/535e7c011657b6111b706441e046d285807bc58d.tar.gz";
      sha256 = "0h0iw41nbrarz1n39f0f94xkg4gjvl2vlhlqkivmbwrib5jwspnj";
    })
    {
      src = builtins.filterSource
        (path: _: baseNameOf path != ".git"
          || baseNameOf path != "target"
          || baseNameOf path != "result") ./.;
    };
in
flake.shellNix.default
