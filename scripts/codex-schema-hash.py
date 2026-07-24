#!/usr/bin/env python3
"""Print a stable semantic SHA-256 for a generated Codex JSON schema tree."""

import hashlib
import json
import pathlib
import sys


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: codex-schema-hash.py <schema-directory>", file=sys.stderr)
        return 2
    root = pathlib.Path(sys.argv[1])
    if not root.is_dir():
        print(f"schema directory does not exist: {root}", file=sys.stderr)
        return 2
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*.json")):
        relative = path.relative_to(root).as_posix().encode()
        document = json.loads(path.read_text(encoding="utf-8"))
        canonical = json.dumps(
            document,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        digest.update(relative)
        digest.update(b"\0")
        digest.update(canonical)
        digest.update(b"\0")
    print(digest.hexdigest())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
