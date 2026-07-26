"""Local manifest artifact inspection, installation, and TCB promotion."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from paths import PLUGIN_ARTIFACTS, PLUGIN_TRUST_STORE
from security.activation import ArtifactStore
from security.artifacts import build_artifact
from security.trust import TCB_ACKNOWLEDGEMENT, TrustStore


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)

    inspect = sub.add_parser("inspect")
    inspect.add_argument("path", type=Path)

    install = sub.add_parser("install")
    install.add_argument("path", type=Path)
    install.add_argument("--store", type=Path, default=PLUGIN_ARTIFACTS)

    promote = sub.add_parser("promote")
    promote.add_argument("path", type=Path)
    promote.add_argument("--approved-by", required=True)
    promote.add_argument("--trust-store", type=Path, default=PLUGIN_TRUST_STORE)

    revoke = sub.add_parser("revoke")
    revoke.add_argument("plugin_id")
    revoke.add_argument("--trust-store", type=Path, default=PLUGIN_TRUST_STORE)

    args = parser.parse_args(argv)
    if args.command == "inspect":
        artifact = build_artifact(args.path)
        print(json.dumps(_summary(artifact), indent=2, sort_keys=True))
        return 0
    if args.command == "install":
        artifact = ArtifactStore(args.store).import_staged(args.path)
        print(json.dumps(_summary(artifact), indent=2, sort_keys=True))
        return 0
    if args.command == "promote":
        artifact = build_artifact(args.path)
        print("TCB promotion disables containment for this exact artifact:")
        print(json.dumps(_summary(artifact), indent=2, sort_keys=True))
        print(f"\nType exactly:\n{TCB_ACKNOWLEDGEMENT}\n")
        acknowledgement = input("> ")
        record = TrustStore(args.trust_store).promote(
            artifact.identity,
            approved_by=args.approved_by,
            acknowledgement=acknowledgement,
        )
        print(json.dumps(asdict(record), indent=2, sort_keys=True))
        print("Promotion is recorded and takes effect after restart.")
        return 0
    if args.command == "revoke":
        changed = TrustStore(args.trust_store).revoke(args.plugin_id)
        print("revoked; restart required" if changed else "no matching record")
        return 0 if changed else 1
    return 2


def _summary(artifact):
    return {
        "plugin_id": artifact.identity.plugin_id,
        "digest": artifact.identity.digest,
        "root": str(artifact.root),
        "files": len(artifact.files),
        "total_bytes": artifact.total_bytes,
        "handlers": [
            {"kind": item.kind, "name": item.name,
             "entrypoint": item.entrypoint}
            for item in artifact.manifest.handlers
        ],
        "capabilities": [
            {"right": item.right, "resource": item.resource,
             "destinations": list(item.destinations)}
            for item in artifact.manifest.capabilities
        ],
    }


if __name__ == "__main__":
    raise SystemExit(main())
