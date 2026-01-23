"""CLI for OSINT Agent operations."""

import argparse
import sys
from pathlib import Path

from .keymanager import delete_api_key, print_key_status, set_api_key, KEYS


def cmd_keys(args: argparse.Namespace) -> int:
    """Handle key management commands."""
    if args.keys_action == "list":
        print("API Key Status:")
        print("-" * 40)
        print_key_status()
        return 0

    elif args.keys_action == "set":
        if not args.key_name:
            print("Error: key_name required for 'set' action")
            return 1
        if args.key_name not in KEYS:
            print(f"Error: Unknown key '{args.key_name}'")
            print(f"Valid keys: {', '.join(KEYS.keys())}")
            return 1

        # Read value from stdin or prompt
        if args.value:
            value = args.value
        else:
            import getpass
            value = getpass.getpass(f"Enter value for {args.key_name}: ")

        if set_api_key(args.key_name, value):
            return 0
        return 1

    elif args.keys_action == "delete":
        if not args.key_name:
            print("Error: key_name required for 'delete' action")
            return 1
        if delete_api_key(args.key_name):
            return 0
        print(f"Key {args.key_name} not found or could not be deleted")
        return 1

    return 0


def cmd_extract(args: argparse.Namespace) -> int:
    """Extract IOCs from file or stdin."""
    from .extractors import extract_iocs
    import json

    if args.file:
        content = Path(args.file).read_text()
    else:
        content = sys.stdin.read()

    iocs = extract_iocs(content)

    if args.format == "json":
        print(json.dumps(iocs, indent=2))
    elif args.format == "stix":
        from .stix_export import iocs_to_stix_bundle
        bundle = iocs_to_stix_bundle(iocs, labels=args.labels or [])
        print(bundle.to_json())
    else:
        # Plain text format
        for ioc_type, values in iocs.items():
            print(f"\n{ioc_type.upper()}:")
            for value in values:
                print(f"  {value}")

    return 0


def cmd_lookup(args: argparse.Namespace) -> int:
    """Look up CVE details."""
    from .clients import NVDClient, CISAKEVClient
    import json

    nvd = NVDClient()
    kev = CISAKEVClient()

    cve_data = nvd.lookup(args.cve_id)

    if "error" in cve_data:
        print(f"Error: {cve_data['error']}")
        return 1

    # Check KEV status
    kev_entry = kev.lookup(args.cve_id)
    cve_data["in_kev"] = kev_entry is not None
    if kev_entry:
        cve_data["kev_details"] = kev_entry

    if args.format == "json":
        print(json.dumps(cve_data, indent=2))
    elif args.format == "stix":
        from .stix_export import cve_to_stix, STIXBundle
        bundle = STIXBundle()
        bundle.add(cve_to_stix(cve_data))
        print(bundle.to_json())
    else:
        print(f"CVE: {cve_data['id']}")
        print(f"CVSS: {cve_data.get('cvss_v3_score', 'N/A')}")
        print(f"In KEV: {'Yes' if cve_data['in_kev'] else 'No'}")
        print(f"\nDescription:\n{cve_data.get('description', 'N/A')[:500]}")

    return 0


def main() -> int:
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="osint",
        description="OSINT Agent - Cyber security intelligence tools",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Keys management
    keys_parser = subparsers.add_parser("keys", help="Manage API keys")
    keys_parser.add_argument(
        "keys_action",
        choices=["list", "set", "delete"],
        help="Key action",
    )
    keys_parser.add_argument("key_name", nargs="?", help="API key name")
    keys_parser.add_argument("--value", help="Key value (or use stdin)")
    keys_parser.set_defaults(func=cmd_keys)

    # Extract IOCs
    extract_parser = subparsers.add_parser("extract", help="Extract IOCs from text")
    extract_parser.add_argument("-f", "--file", help="Input file (or use stdin)")
    extract_parser.add_argument(
        "--format",
        choices=["text", "json", "stix"],
        default="text",
        help="Output format",
    )
    extract_parser.add_argument(
        "--labels",
        nargs="+",
        help="Labels to apply (for STIX output)",
    )
    extract_parser.set_defaults(func=cmd_extract)

    # CVE lookup
    lookup_parser = subparsers.add_parser("lookup", help="Look up CVE details")
    lookup_parser.add_argument("cve_id", help="CVE ID (e.g., CVE-2024-1234)")
    lookup_parser.add_argument(
        "--format",
        choices=["text", "json", "stix"],
        default="text",
        help="Output format",
    )
    lookup_parser.set_defaults(func=cmd_lookup)

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 0

    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
