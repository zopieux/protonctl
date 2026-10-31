#!/usr/bin/env python3

import configparser
import pathlib

PREFIX = 'protonvpn-wireguard.wg-'


def main():
    config_paths = pathlib.Path(__file__).parent.resolve().glob(f'{PREFIX}*.conf')
    print("[")
    for path in sorted(config_paths):
        conf = configparser.ConfigParser()
        conf.read(path)
        name = path.stem.replace(PREFIX, '')
        print(f"""  {{
    name = "{name}";
    wg = {{
      PrivateKey = "{conf['Interface']['PrivateKey']}";
      PublicKey = "{conf['Peer']['PublicKey']}";
      Endpoint = "{conf['Peer']['Endpoint']}";
    }};
  }}""")
    print("]")


if __name__ == "__main__":
    main()
