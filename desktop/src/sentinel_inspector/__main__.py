from argparse import ArgumentParser
from getpass import getpass
import json
import os
from pathlib import Path
import sys
from threading import Event

from pydantic import ValidationError

from . import __version__, backup, intelligence, reporting
from .database import Database, InspectorError
from .models import Asset, Authorization, MobileCheck, Product
from .workflow import Selection, run


def default_path() -> Path:
    base = Path(os.environ.get("LOCALAPPDATA", Path.home() / ".local" / "share"))
    return base / "PuskesauSentinel" / "inspector.sqlite3"


def _read(path: Path):
    with path.open("rb") as handle:
        data = handle.read(1024 * 1024 + 1)
    if len(data) > 1024 * 1024:
        raise InspectorError("Permintaan JSON melebihi 1 MiB.")
    return json.loads(data)


def main(argv=None):
    parser = ArgumentParser(prog="sentinel-inspector")
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument("--db", type=Path, default=default_path())
    sub = parser.add_subparsers(dest="action")
    for action in ("asset-add", "inspect", "intel-import"):
        sub.add_parser(action).add_argument("file", type=Path)
    sub.add_parser("show").add_argument("session")
    sub.add_parser("lookup").add_argument("indicator")
    sub.add_parser("summary")
    sub.add_parser("verify-audit")
    sub.add_parser("retain-usb").add_argument("days", type=int)
    report = sub.add_parser("report")
    report.add_argument("session")
    report.add_argument("kind", choices=reporting.KINDS)
    report.add_argument("output", type=Path)
    report.add_argument("--revision", type=int)
    close = sub.add_parser("close")
    close.add_argument("session")
    close.add_argument("reviewer")
    sub.add_parser("backup").add_argument("output", type=Path)
    restore = sub.add_parser("restore")
    restore.add_argument("input", type=Path)
    restore.add_argument("output", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.action is None:
            from .gui import launch

            return launch(args.db)
        if args.action == "restore":
            result = {
                "sha256": backup.restore(
                    args.input.absolute(), args.output.absolute(), getpass("Frasa sandi cadangan: ")
                )
            }
        else:
            db = Database(args.db)
            result = _dispatch(db, args)
        print(json.dumps(result, ensure_ascii=False, default=str))
        return 0
    except ValidationError:
        print("Input gagal divalidasi. Periksa format data dan panjang kolom.", file=sys.stderr)
    except (InspectorError, ValueError, OSError) as error:
        print(
            str(error) if isinstance(error, InspectorError) else "Data input atau lokasi file tidak valid.",
            file=sys.stderr,
        )
    except ImportError:
        print("Dependensi aplikasi belum terpasang. Gunakan petunjuk instalasi.", file=sys.stderr)
    return 2


def _dispatch(db: Database, args):
    if args.action == "asset-add":
        return {"asset_id": db.add_asset(Asset.model_validate(_read(args.file)))}
    if args.action == "inspect":
        data = _read(args.file)
        if not isinstance(data, dict):
            raise InspectorError("Permintaan sesi harus berupa objek JSON.")
        request = Authorization.model_validate(data.get("authorization"))
        selection = Selection(
            set(request.modules),
            tuple(Path(file) for file in data.get("files", [])),
            tuple(MobileCheck.model_validate(row) for row in data.get("checks", [])),
            tuple(data.get("indicators", [])),
            tuple(Product.model_validate(row) for row in data.get("products", [])),
            set(data.get("engines", [])),
        )
        session = db.create(request)
        run(db, session, selection, Event())
        return {"session_id": session, "state": db.session(session)["status"]}
    if args.action == "show":
        return db.session(args.session)
    if args.action == "lookup":
        return intelligence.lookup(db, args.indicator).payload
    if args.action == "intel-import":
        return intelligence.load_package(db, args.file.absolute())
    if args.action == "summary":
        return db.counts()
    if args.action == "verify-audit":
        return {"integrity": db.verify_audit()}
    if args.action == "retain-usb":
        return {"deleted": db.retain_usb(args.days)}
    if args.action == "report":
        return {"sha256": reporting.export(db, args.session, args.kind, args.output.absolute(), args.revision)}
    if args.action == "close":
        from .models import Code
        from pydantic import TypeAdapter

        db.close(args.session, TypeAdapter(Code).validate_python(args.reviewer))
        return {"status": "closed"}
    if args.action == "backup":
        return {"sha256": backup.create(db, args.output.absolute(), getpass("Frasa sandi cadangan: "))}
    raise InspectorError("Perintah tidak dikenali.")


if __name__ == "__main__":
    raise SystemExit(main())
