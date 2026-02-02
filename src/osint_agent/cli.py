"""CLI for OSINT Agent operations."""

from __future__ import annotations

import argparse
import sqlite3
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .keymanager import delete_api_key, print_key_status, set_api_key, KEYS

PROJECT_ROOT = Path(__file__).parent.parent.parent
IOC_DB_PATH = PROJECT_ROOT / "data" / "iocs.db"
DEFAULT_QUERY_LIMIT = 50
DEFAULT_RECENT_LIMIT = 20


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


def cmd_iocs(args: argparse.Namespace) -> int:
    """Query the local IOC database."""
    import json

    if not IOC_DB_PATH.exists():
        print("IOC database not found. Run setup.sh to initialize.")
        return 1

    try:
        conn = sqlite3.connect(IOC_DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
    except sqlite3.Error as e:
        print(f"Error opening IOC database: {e}")
        return 1

    action = args.iocs_action
    query = args.query

    try:
        if action == "stats":
            cursor.execute("SELECT COUNT(*) FROM iocs")
            total = cursor.fetchone()[0]
            cursor.execute("SELECT type, COUNT(*) as cnt FROM iocs GROUP BY type ORDER BY cnt DESC")
            by_type = cursor.fetchall()
            yesterday = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
            cursor.execute("SELECT COUNT(*) FROM iocs WHERE first_seen > ?", (yesterday,))
            recent = cursor.fetchone()[0]

            if args.format == "json":
                print(json.dumps({
                    "total": total,
                    "recent_24h": recent,
                    "by_type": {row["type"]: row["cnt"] for row in by_type},
                }, indent=2))
            else:
                print(f"Total IOCs: {total}")
                print(f"Added (24h): {recent}")
                if by_type:
                    print("\nBy Type:")
                    for row in by_type:
                        print(f"  {row['type']:10s} {row['cnt']}")
                else:
                    print("\nNo IOCs in database.")

        elif action == "search":
            if not query:
                print("Error: search requires a query argument")
                return 1
            cursor.execute(
                "SELECT * FROM iocs WHERE value LIKE ? OR source LIKE ? ORDER BY last_seen DESC LIMIT ?",
                (f"%{query}%", f"%{query}%", DEFAULT_QUERY_LIMIT),
            )
            rows = cursor.fetchall()
            if args.format == "json":
                print(json.dumps([dict(r) for r in rows], indent=2))
            else:
                if not rows:
                    print(f"No IOCs found matching '{query}'.")
                else:
                    print(f"{'TYPE':10s} {'VALUE':45s} {'SOURCE':20s} {'LAST SEEN':20s} {'HITS':5s}")
                    print("-" * 102)
                    for r in rows:
                        print(f"{r['type']:10s} {r['value'][:45]:45s} {(r['source'] or '')[:20]:20s} {r['last_seen'][:20]:20s} {r['hit_count']}")

        elif action == "recent":
            limit = DEFAULT_RECENT_LIMIT
            cursor.execute("SELECT * FROM iocs ORDER BY last_seen DESC LIMIT ?", (limit,))
            rows = cursor.fetchall()
            if args.format == "json":
                print(json.dumps([dict(r) for r in rows], indent=2))
            else:
                if not rows:
                    print("No IOCs in database.")
                else:
                    print(f"{'TYPE':10s} {'VALUE':45s} {'SOURCE':20s} {'LAST SEEN':20s} {'HITS':5s}")
                    print("-" * 102)
                    for r in rows:
                        print(f"{r['type']:10s} {r['value'][:45]:45s} {(r['source'] or '')[:20]:20s} {r['last_seen'][:20]:20s} {r['hit_count']}")

        elif action == "filter":
            if not query:
                print("Error: filter requires a type argument (e.g., ipv4, domain, sha256)")
                return 1
            valid_types = ("ipv4", "ipv6", "domain", "md5", "sha1", "sha256", "url", "email", "cve")
            if query not in valid_types:
                print(f"Error: Unknown IOC type '{query}'")
                print(f"Valid types: {', '.join(valid_types)}")
                return 1
            cursor.execute("SELECT * FROM iocs WHERE type = ? ORDER BY last_seen DESC LIMIT ?", (query, DEFAULT_QUERY_LIMIT))
            rows = cursor.fetchall()
            if args.format == "json":
                print(json.dumps([dict(r) for r in rows], indent=2))
            else:
                if not rows:
                    print(f"No IOCs of type '{query}'.")
                else:
                    print(f"{'VALUE':50s} {'SOURCE':20s} {'LAST SEEN':20s} {'HITS':5s}")
                    print("-" * 97)
                    for r in rows:
                        print(f"{r['value'][:50]:50s} {(r['source'] or '')[:20]:20s} {r['last_seen'][:20]:20s} {r['hit_count']}")

    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return 1
    finally:
        conn.close()

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
    keys_parser.set_defaults(func=cmd_keys)

    # IOC database queries
    iocs_parser = subparsers.add_parser("iocs", help="Query the local IOC database")
    iocs_parser.add_argument(
        "iocs_action",
        choices=["stats", "search", "recent", "filter"],
        help="Action to perform",
    )
    iocs_parser.add_argument("query", nargs="?", help="Search query or IOC type")
    iocs_parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format",
    )
    iocs_parser.set_defaults(func=cmd_iocs)

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

    result: int = args.func(args)
    return result


if __name__ == "__main__":
    sys.exit(main())
