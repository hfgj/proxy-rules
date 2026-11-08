#!/usr/bin/env python3
from __future__ import annotations

import ipaddress
import json
import urllib.request
from pathlib import Path

UPSTREAM = "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/BlockHttpDNS/BlockHttpDNS.list"
ROOT = Path(__file__).resolve().parents[2]
DNS_DIR = ROOT / "dns"
REWRITE_DIR = ROOT / "rewrites"
FIREWALL_DIR = ROOT / "firewall"
TOOL_DIR = Path(__file__).resolve().parent
UA = "proxy-rules/block-httpdns"

EXACT = {"DOMAIN", "HOST"}
SUFFIX = {"DOMAIN-SUFFIX", "HOST-SUFFIX"}
V4 = {"IP-CIDR"}
V6 = {"IP-CIDR6", "IP6-CIDR"}


def fetch(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read().decode("utf-8")


def norm(domain: str) -> str:
    return domain.strip().lower().rstrip(".")


def agh(domain: str) -> str:
    return f"||{domain}^"


def qx_escape_domain(domain: str) -> str:
    return domain.replace(".", r"\.")


def qx_exact(domain: str) -> str:
    return rf"^https?:\/\/{qx_escape_domain(domain)}(?::\d+)?(?:\/|$) url reject"


def qx_suffix(domain: str) -> str:
    return rf"^https?:\/\/(?:[^.\/]+\.)*{qx_escape_domain(domain)}(?::\d+)?(?:\/|$) url reject"


def main() -> None:
    for directory in (DNS_DIR, REWRITE_DIR, FIREWALL_DIR, TOOL_DIR):
        directory.mkdir(parents=True, exist_ok=True)

    src = fetch(UPSTREAM)
    agh_rules: set[str] = set()
    mosdns: set[str] = set()
    v4: set[ipaddress.IPv4Network] = set()
    v6: set[ipaddress.IPv6Network] = set()
    unsupported: list[str] = []
    exact_domains: set[str] = set()
    suffix_domains: set[str] = set()

    for raw in src.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue

        parts = [item.strip() for item in line.split(",")]
        if len(parts) < 2:
            unsupported.append(line)
            continue

        rule_type, value = parts[0].upper(), parts[1]
        if rule_type in EXACT:
            domain = norm(value)
            exact_domains.add(domain)
            agh_rules.add(agh(domain))
            mosdns.add(f"full:{domain}")
        elif rule_type in SUFFIX:
            domain = norm(value)
            suffix_domains.add(domain)
            agh_rules.add(agh(domain))
            mosdns.add(f"domain:{domain}")
        elif rule_type in V4:
            try:
                network = ipaddress.ip_network(value, strict=False)
                if network.version != 4:
                    raise ValueError
                v4.add(network)
            except ValueError:
                unsupported.append(line)
        elif rule_type in V6:
            try:
                network = ipaddress.ip_network(value, strict=False)
                if network.version != 6:
                    raise ValueError
                v6.add(network)
            except ValueError:
                unsupported.append(line)
        else:
            unsupported.append(line)

    if "httpdns.bilivideo.com" not in exact_domains | suffix_domains:
        raise RuntimeError("Bilibili HTTPDNS rule disappeared upstream; aborting.")

    agh_rules = sorted(agh_rules)
    mosdns = sorted(mosdns)
    qx_rules = (
        [qx_exact(domain) for domain in sorted(exact_domains)]
        + [qx_suffix(domain) for domain in sorted(suffix_domains)]
    )
    v4 = sorted(v4, key=lambda network: (int(network.network_address), network.prefixlen))
    v6 = sorted(v6, key=lambda network: (int(network.network_address), network.prefixlen))
    unsupported = sorted(set(unsupported))

    (DNS_DIR / "block-httpdns-adguardhome.generated.txt").write_text(
        "! Title: BM7 BlockHTTPDNS for AdGuard Home\n"
        "! Source: BlackMatrix7 ios_rule_script / BlockHttpDNS\n"
        f"! Upstream: {UPSTREAM}\n"
        "! Generated automatically by GitHub Actions.\n"
        "! Note: ||domain^ blocks the domain and its subdomains.\n\n"
        + "\n".join(agh_rules)
        + "\n",
        encoding="utf-8",
    )

    (DNS_DIR / "block-httpdns-mosdns.generated.txt").write_text(
        "# Title: BM7 BlockHTTPDNS for MosDNS v5\n"
        "# DOMAIN/HOST -> full:\n"
        "# DOMAIN-SUFFIX/HOST-SUFFIX -> domain:\n\n"
        + "\n".join(mosdns)
        + "\n",
        encoding="utf-8",
    )

    (REWRITE_DIR / "block-httpdns-quantumultx.generated.conf").write_text(
        "# Title: BM7 BlockHTTPDNS domain rules for Quantumult X Rewrite\n"
        "# Source: BlackMatrix7 ios_rule_script / BlockHttpDNS\n"
        f"# Upstream: {UPSTREAM}\n"
        "# Generated automatically by GitHub Actions.\n"
        "# Scope: DOMAIN/HOST and DOMAIN-SUFFIX/HOST-SUFFIX are projected to HTTP(S) URL reject rules.\n"
        "# Important: IP-CIDR/IP-CIDR6 are intentionally NOT converted here; URL Rewrite is not equivalent to L3/L4 CIDR blocking.\n"
        "# Use firewall/block-httpdns-ipv4.generated.txt, firewall/block-httpdns-ipv6.generated.txt and firewall/block-httpdns-nftables.generated.nft for fixed-IP HTTPDNS blocking.\n"
        "# No MITM hostname list is generated by this file.\n\n"
        + "\n".join(qx_rules)
        + "\n",
        encoding="utf-8",
    )

    v4_elements = ",\n            ".join(str(network) for network in v4)
    v6_elements = ",\n            ".join(str(network) for network in v6)
    nft = """# BM7 BlockHTTPDNS nftables IP sets
# Creates sets only; no DROP/REJECT rules are installed.

table inet bm7_httpdns {
    set httpdns_v4 {
        type ipv4_addr
        flags interval
        elements = {
            %s
        }
    }

    set httpdns_v6 {
        type ipv6_addr
        flags interval
        elements = {
            %s
        }
    }
}
""" % (v4_elements, v6_elements)

    (FIREWALL_DIR / "block-httpdns-nftables.generated.nft").write_text(nft, encoding="utf-8")
    (FIREWALL_DIR / "block-httpdns-ipv4.generated.txt").write_text(
        "\n".join(str(network) for network in v4) + ("\n" if v4 else ""),
        encoding="utf-8",
    )
    (FIREWALL_DIR / "block-httpdns-ipv6.generated.txt").write_text(
        "\n".join(str(network) for network in v6) + ("\n" if v6 else ""),
        encoding="utf-8",
    )

    unsupported_path = TOOL_DIR / "unsupported.generated.txt"
    if unsupported:
        unsupported_path.write_text(
            "# Rules not converted automatically:\n\n" + "\n".join(unsupported) + "\n",
            encoding="utf-8",
        )
    elif unsupported_path.exists():
        unsupported_path.unlink()

    metadata = {
        "upstream": UPSTREAM,
        "adguardhome_rule_count": len(agh_rules),
        "mosdns_rule_count": len(mosdns),
        "quantumultx_rewrite_rule_count": len(qx_rules),
        "exact_domain_count": len(exact_domains),
        "suffix_domain_count": len(suffix_domains),
        "ipv4_network_count": len(v4),
        "ipv6_network_count": len(v6),
        "unsupported_count": len(unsupported),
    }
    (TOOL_DIR / "metadata.generated.json").write_text(
        json.dumps(metadata, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(metadata, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
