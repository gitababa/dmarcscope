"""Command line entry point: python -m ingestor <command>."""

from __future__ import annotations

import argparse
import json
import logging
import signal
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
    sub.add_parser("serve", help="keep running: read the mailboxes configured in the panel on their schedule")
    sub.add_parser(
        "pass",
        help="one bounded pass, for a scheduler (Cloud Run job, ECS scheduled task): the IMAP_* mailbox, "
        "waiting panel requests, then panel mailboxes that are due",
    )
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )
    # parsedmarc logs every parsed message at INFO.
    logging.getLogger("parsedmarc").setLevel(logging.DEBUG if args.verbose else logging.WARNING)

    # Schedulers stop a job with SIGTERM (Kubernetes, Cloud Run, docker stop).
    # Turn it into a normal exit so the run is closed and connections are
    # released on the way out, instead of the row staying "in progress".
    def _terminate(signum, frame):  # noqa: ARG001
        raise SystemExit(143)

    # serve installs its own handlers (stop after the current message).
    if args.command != "serve":
        try:
            signal.signal(signal.SIGTERM, _terminate)
        except ValueError:
            pass  # not the main thread (embedded use); nothing to install

    try:
        settings = load_settings()
        if args.command == "serve":
            from . import serve

            return serve.serve(settings)
        if args.command == "pass":
            from . import oneshot

            summary = oneshot.scheduled_pass(settings)
            # Counts on stdout; the reasons are in the pass record.
            problems = summary.get("problems", [])
            print(json.dumps({"ok": not problems, **summary, "problems": len(problems)}))
            return 0
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

    # `run` leaves failed messages unread for the next run to retry, so they do
    # not fail the job. `import` was pointed at specific files: any that could
    # not be loaded (or finding none at all) is a failure of the command.
    ok = not (args.command == "import" and stats["errors"])
    print(json.dumps({"ok": ok, **stats}))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
