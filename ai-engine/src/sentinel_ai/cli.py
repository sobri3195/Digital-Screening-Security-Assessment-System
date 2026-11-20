from argparse import ArgumentParser
import asyncio
from hashlib import sha256
import json
from pathlib import Path
import secrets

import uvicorn

from .runtime import directory_digest
from .schemas import CORE_SCOPES


def main(argv=None):
    parser = ArgumentParser(prog="sentinel-ai")
    commands = parser.add_subparsers(dest="command", required=True)
    serve = commands.add_parser("serve")
    serve.add_argument("--port", type=int, default=8766)
    commands.add_parser("generate-web-key")
    digest = commands.add_parser("embedding-digest")
    digest.add_argument("path", type=Path)
    token = commands.add_parser("workstation-token")
    token.add_argument("id")
    token.add_argument("scopes", nargs="+", choices=sorted(CORE_SCOPES))
    evaluate = commands.add_parser("evaluate")
    evaluate.add_argument("suite", type=Path)
    evaluate.add_argument("--model", action="append", required=True)
    evaluate.add_argument("--internal", action="store_true")
    args = parser.parse_args(argv)
    if args.command == "serve":
        uvicorn.run(
            "sentinel_ai.gateway:create_app",
            factory=True,
            host="127.0.0.1",
            port=args.port,
            workers=1,
            access_log=False,
            server_header=False,
        )
    elif args.command == "generate-web-key":
        print(secrets.token_hex(32))
    elif args.command == "embedding-digest":
        print(directory_digest(args.path))
    elif args.command == "evaluate":
        from .evaluation import run

        try:
            result = asyncio.run(run(args.suite, args.model, args.internal))
        except (OSError, ValueError):
            parser.error("Suite, model yang disetujui, atau konfigurasi evaluasi tidak valid.")
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        value = secrets.token_hex(32)
        print(
            json.dumps(
                {
                    "deliver_once": value,
                    "registry_entry": {
                        "id": args.id,
                        "sha256": sha256(value.encode()).hexdigest(),
                        "scopes": args.scopes,
                    },
                }
            )
        )


if __name__ == "__main__":
    main()
