import argparse
import json
import sys
from .core import Client, ConfigError, load_config, run, save_report
from .lab import configuration, lab


def main():
    p = argparse.ArgumentParser(description="Test configured JSON API authorization boundaries")
    sub = p.add_subparsers(dest="command", required=True)
    sub.add_parser("validate", help="Check configuration without making requests").add_argument("config")
    demo = sub.add_parser("demo", help="Test a temporary loopback API with known vulnerabilities")
    demo.add_argument("--out", default="reports/demo")
    scan = sub.add_parser("run", help="Run an explicit authorization test plan")
    scan.add_argument("config")
    scan.add_argument("--out", default="reports/latest")
    scan.add_argument("--timeout", type=float, default=5.)
    scan.add_argument("--interval", type=float, default=.1)
    scan.add_argument("--max-bytes", type=int, default=1024*1024)
    args = p.parse_args()
    try:
        if args.command == "validate":
            load_config(args.config)
            print("Configuration valid; no requests sent.")
            return 0
        if args.command == "demo":
            with lab() as origin:
                report = run(configuration(origin), client=Client(origin, interval=0),
                             env={"ALICE_TOKEN": "lab-alice-token", "BOB_TOKEN": "lab-bob-token"})
        else:
            config = load_config(args.config)
            report = run(config, client=Client(config["origin"], timeout=args.timeout,
                         interval=args.interval, max_bytes=args.max_bytes))
        save_report(report, args.out)
        print(json.dumps(report["summary"], indent=2))
        print("Reports saved to " + args.out)
        if report["summary"]["exposure"]:
            return 1
        if report["summary"]["inconclusive"] or report["summary"]["review"]:
            return 2
        return 0
    except ConfigError as exc:
        print("Configuration error: " + str(exc), file=sys.stderr)
        return 2
    except (OSError, ValueError):
        print("Operation failed. Check file access and configuration.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
