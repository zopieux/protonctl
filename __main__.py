#!/usr/bin/env python3

import argparse
import asyncio
import base64
import datetime
import getpass
import hashlib
import json
import os
import pathlib
import re
from dataclasses import dataclass
from typing import cast

import distro
from proton.sso import ProtonSSO
from proton.vpn.session.dataclasses import VPNCertificate
from proton.vpn.session.servers.types import (
    LogicalServer,
    PhysicalServer,
    ServerFeatureEnum,
)
from proton.vpn.session.session import VPNSession
from proton.vpn.session.utils import get_core_api_semver_version, rest_api_request

PROTONVPN_VERSION = get_core_api_semver_version()
PROTONVPN_APP_VERSION = f"linux-vpn-cli@{PROTONVPN_VERSION}"
USER_AGENT = f"ProtonVPN/{PROTONVPN_VERSION} (Linux; {distro.name()}/{distro.version()})"


@dataclass
class CertificateFeatures:
    bouncing: int
    netshield_level: int
    port_forwarding: bool
    random_nat: bool
    split_tcp: bool
    peer_ip: str
    peer_name: str
    peer_public_key: str
    platform: str

    @staticmethod
    def from_dict(dct: dict) -> 'CertificateFeatures':
        return CertificateFeatures(
            bouncing=dct.get("Bouncing", False),
            netshield_level=dct.get("NetShieldLevel", 0),
            port_forwarding=dct.get("PortForwarding", False),
            random_nat=dct.get("RandomNAT", False),
            split_tcp=dct["SplitTCP"],
            peer_ip=dct["peerIp"],
            peer_name=dct["peerName"],
            peer_public_key=dct["peerPublicKey"],
            platform=dct["platform"],
        )


@dataclass
class ExistingCertificate:
    certificate: VPNCertificate
    features: CertificateFeatures
    expiration_time: datetime.datetime

    @staticmethod
    def from_dict(dct: dict) -> 'ExistingCertificate':
        return ExistingCertificate(
            certificate=VPNCertificate.from_dict({
                "ServerPublicKeyMode": "",
                "ServerPublicKey": "",
                **dct
            }),
            features=CertificateFeatures.from_dict(dct["Features"]),
            expiration_time=datetime.datetime.fromtimestamp(dct["ExpirationTime"]),
        )


@dataclass
class InternalServer:
    logical: LogicalServer
    physical: PhysicalServer
    device_name: str


async def login():
    username = os.environ["PROTONVPN_EMAIL"]
    sso = ProtonSSO(user_agent=USER_AGENT, appversion=PROTONVPN_APP_VERSION)
    session = cast(VPNSession, sso.get_session(username, override_class=VPNSession))
    if session.authenticated:
        await session.fetch_session_data()
        return session
    password = os.environ.get("PROTONVPN_PASSWORD")
    if not password:
        password = getpass.getpass(f"Enter password for {username}: ")
    if not password:
        raise Exception("No password provided")
    login_result = await session.login(username, password)
    if not login_result.authenticated:
        raise Exception("Bad email or password")
    if login_result.twofa_required:
        twofa_code = input("Enter 2FA code for account: ")
        login_result = await session.provide_2fa_code(twofa_code)
        if login_result.twofa_required:
            raise Exception("Invalid 2FA code")
    if not login_result.success:
        raise Exception("Login failed")
    await session.fetch_session_data()
    return session


async def get_best_servers(args: argparse.Namespace, session: VPNSession) -> list[InternalServer]:
    logicals = list(session.server_list.logicals)
    # fmt: off
    logicals = (
        server
        for server in logicals
        if server.enabled
        and (server.tier <= session.server_list.user_tier)
        and (server.load <= args.load)
        and (args.freetier is None or (server.tier == 0) == args.freetier)
        and ((args.entry is None or len(args.entry) == 0) or
                (server.entry_country in args.entry))
        and ((args.exit is None or len(args.exit) == 0) or
                (server.exit_country in args.exit))
        and (args.port_forwarding is None or (ServerFeatureEnum.P2P in server.features) == args.port_forwarding)
        and (args.ipv6 is None or (ServerFeatureEnum.IPV6 in server.features) == args.ipv6)
    )
    # fmt: on
    def physicals():
        for logical in logicals:
            small_name = re.sub(r'[^A-Za-z0-9]', '', logical.name)
            for physical in logical.physical_servers:
                yield InternalServer(logical=logical, physical=physical, device_name=f"{args.prefix}{small_name}")

    servers = list(physicals())
    servers.sort(key=lambda s: (s.logical.score, -s.logical.load, s.logical.id))
    return servers


async def get_existing_certificates(session: VPNSession):
    resp = await rest_api_request(session,
                                  "/vpn/v1/certificate/all",
                                  params={
                                      "Mode": "persistent",
                                      "Offset": 0,
                                      "Limit": 51
                                  })
    for cert in resp["Certificates"]:
        yield ExistingCertificate.from_dict(cert)


def private_to_X25519(private):
    hash__ = hashlib.sha512(base64.b64decode(private)[-32:]).digest()
    hash_ = list(hash__)[:32]
    hash_[0] &= 0xf8
    hash_[31] &= 0x7f
    hash_[31] |= 0x40
    return base64.b64encode(bytes(hash_)).decode()


async def get_key_pair(session: VPNSession) -> tuple[str, str]:
    response = await session.async_api_request("/api/vpn/v1/certificate/key/EC")
    public = response["PublicKey"].split("\n")[1]
    private = response["PrivateKey"].split("\n")[1]
    private = private_to_X25519(private)
    return public, private


async def register_config(session: VPNSession, server: InternalServer, key_pair: tuple[str, str],
                          args: argparse.Namespace):
    public, _ = key_pair
    one_year_from_now = datetime.datetime.now() + datetime.timedelta(days=365)
    body = {
        "ClientPublicKey": public,
        "DeviceName": server.device_name,
        "Features": {
            "peerName": server.logical.name,
            "peerIp": server.physical.entry_ip,
            "peerPublicKey": server.physical.x25519_pk,
            "platform": "Linux",
            "SafeMode": False,
            "SplitTCP": args.accelerator,
            "PortForwarding": args.port_forwarding,
            "RandomNAT": not args.moderate_nat,
            "NetShieldLevel": args.netshield,
        },
        "Mode": "persistent",
        "ExpirationTime": int(one_year_from_now.timestamp()),
    }
    response = await session.async_api_request("/api/vpn/v1/certificate", jsondata=body)
    with open(f"/tmp/{server.device_name}.api_response.json", "w") as f:
        json.dump(response, f, indent=2)
    return response["SerialNumber"]


def write_config(server: LogicalServer, key_pair: tuple[str, str], serial_number: str, args: argparse.Namespace):
    _, private = key_pair
    path: pathlib.Path = pathlib.Path(__file__).parent.resolve() / f"protonvpn-wireguard.{server.device_name}.conf"
    body = f"""[Interface]
# Key for {server.device_name} Proton VPN
# Session only = false
# Serial Number = {serial_number}
# Non-standard ports = false
# NetShield = {args.netshield}
# Moderate NAT = {args.moderate_nat}
# NAT-PMP (Port Forwarding) = {args.port_forwarding}
# VPN Accelerator (Split TCP) = {args.accelerator}
PrivateKey = {private}
Address = 10.2.0.2/32
DNS = 10.2.0.1

[Peer]
# {server.logical.name}
PublicKey = {server.physical.x25519_pk}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = {server.physical.entry_ip}:51820
"""
    path.write_text(body, encoding="utf-8")
    print(f"Wrote config to {path}")


async def create_config(session: VPNSession, server: LogicalServer, args: argparse.Namespace):
    key_pair = await get_key_pair(session)
    serial_number = await register_config(session, server, key_pair, args)
    write_config(server, key_pair, serial_number, args)
    await asyncio.sleep(15)


async def renew_certificates(session: VPNSession, existing_certificates: list[ExistingCertificate], args: argparse.Namespace):
    targets = existing_certificates
    if args.renew:
        targets = [
            c for c in targets
            if c.features.peer_name in args.renew or (c.certificate.DeviceName and c.certificate.DeviceName in args.renew)
        ]
    elif args.entry or args.exit:
        countries = set((args.entry or []) + (args.exit or []))
        targets = [
            c for c in targets
            if any(c.features.peer_name.startswith(country) for country in countries)
        ]

    if not targets:
        print("No matching certificates found to renew.")
        return

    print(f"Renewing {len(targets)} certificate(s) for {args.days} day(s)...")
    for cert in targets:
        expiration_time = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=args.days)
        body = {
            "ClientPublicKey": cert.certificate.ClientKey,
            "DeviceName": cert.certificate.DeviceName or "",
            "Features": {
                "peerName": cert.features.peer_name,
                "peerIp": cert.features.peer_ip,
                "peerPublicKey": cert.features.peer_public_key,
                "platform": cert.features.platform or "Linux",
                "SafeMode": False,
                "SplitTCP": cert.features.split_tcp,
                "PortForwarding": cert.features.port_forwarding,
                "RandomNAT": cert.features.random_nat,
                "NetShieldLevel": cert.features.netshield_level,
                "Bouncing": cert.features.bouncing,
            },
            "Mode": "persistent",
            "Renew": True,
            "ExpirationTime": int(expiration_time.timestamp()),
        }
        resp = await session.async_api_request("/api/vpn/v1/certificate", jsondata=body)
        new_exp = datetime.datetime.fromtimestamp(resp["ExpirationTime"], tz=datetime.timezone.utc)
        print(f"Extended {cert.features.peer_name} ({cert.certificate.DeviceName or 'no device name'}) until {new_exp.isoformat()} (Serial: {resp.get('SerialNumber')})")


async def create_new_configs(args: argparse.Namespace):
    session = await login()
    existing_certificates = [c async for c in get_existing_certificates(session)]
    if args.list:
        print(f"\nFound {len(existing_certificates)} certificate(s):\n")
        for i, cert in enumerate(existing_certificates, 1):
            print(f"[{i}] Peer: {cert.features.peer_name}")
            print(f"    Device Name:     {cert.certificate.DeviceName}")
            print(f"    Peer IP:         {cert.features.peer_ip}")
            print(f"    Peer Public Key: {cert.features.peer_public_key}")
            print(f"    Expires:         {cert.expiration_time.isoformat()}")
            print(f"    Serial:          {cert.certificate.SerialNumber}")
            print()
        return

    if args.renew is not None:
        await renew_certificates(session, existing_certificates, args)
        return

    existing_names = {c.features.peer_name for c in existing_certificates}
    print(f"We already have {len(existing_names)} servers: {existing_names}")
    servers = list(await get_best_servers(args, session))
    if len(servers) == 0:
        raise Exception("No servers found")
    servers = [s for s in servers if s.logical.name not in existing_names]
    print(f"There are {len(servers)} new servers available for creation")
    to_create = servers[:args.amount]
    if len(to_create) != args.amount:
        print(f"Only {len(to_create)} (of {args.amount} requested) servers were available for creation")
    for server in to_create:
        await create_config(session, server, args)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--freetier",
                        action=argparse.BooleanOptionalAction,
                        help="Limit to only free tier servers if true, or only non-free if false")
    parser.add_argument("--load", type=int, default=100, help="Limit to servers with a load below this value (0-100)")
    parser.add_argument("--entry", nargs='+', help="Limit to servers with entry country in list")
    parser.add_argument("--exit", nargs='+', help="Limit to servers with exit country in list")
    parser.add_argument("--prefix", type=str, default="wg-", help="Prefix for config files")

    parser.add_argument("--netshield", type=int, default=0, help="Netshield level: 0 (disabled), 1, 2")
    parser.add_argument("--port-forwarding",
                        action=argparse.BooleanOptionalAction,
                        help="Limit to servers that support port forwarding")
    parser.add_argument("--ipv6", action=argparse.BooleanOptionalAction, help="Limit to servers that support IPv6")
    parser.add_argument("--accelerator",
                        action=argparse.BooleanOptionalAction,
                        default=True,
                        help="Enable accelerator aka split TCP")
    parser.add_argument("--moderate-nat",
                        action=argparse.BooleanOptionalAction,
                        default=False,
                        help="Enable moderate NAT")
    parser.add_argument("--amount", type=int, default=1, help="Number of servers to create configs for")
    parser.add_argument("--list", action="store_true", help="List existing certificates and exit without creating keys")
    parser.add_argument("--renew",
                        nargs="*",
                        metavar="PEER",
                        help="Renew existing certificates (optionally specify peer names like CH#621, or all matching if none given)")
    parser.add_argument("--days",
                        type=int,
                        default=365,
                        help="Number of days to extend certificate for (default: 365, max: 365)")
    args = parser.parse_args()
    asyncio.run(create_new_configs(args))
