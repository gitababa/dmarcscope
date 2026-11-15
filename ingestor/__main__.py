"""Command line entry point: python -m ingestor <command>."""

from __future__ import annotations

import argparse
import json
import logging
import sys

from . import __version__
from .config import ConfigError, load_settings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m ingestor", description="DMARCscope ingest worker")
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("run", help="fetch new reports from the IMAP mailbox and store them")
    imp = sub.add_parser("import", help="load report files (.xml, .gz, .zip, .eml) or directories of them")
    imp.add_argument("paths", nargs="+")
    sub.add_parser("enrich", help="backfill reverse DNS for sending IPs")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )
    # parsedmarc logs every parsed message at INFO.
    logging.getLogger("parsedmarc").setLevel(logging.DEBUG if args.verbose else logging.WARNING)

    try:
        settings = load_settings()
        # Imported late so that --help works without the parser's dependencies.
        from . import runner

        if args.command == "run":
            stats = runner.run_ingest(settings)
        elif args.command == "import":
            stats = runner.import_files(settings, args.paths)
        else:
            stats = runner.run_enrich(settings)
    except ConfigError as e:
        print(f"Configuration error: {e}", file=sys.stderr)
        return 2
    except Exception as e:  # noqa: BLE001
        logging.getLogger("ingestor").exception("run failed")
        print(json.dumps({"ok": False, "error": f"{type(e).__name__}: {e}"}))
        return 1

    print(json.dumps({"ok": True, **stats}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
