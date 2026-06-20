"""CLI entry point: python -m apsrai [--demo | --simulate | --verify | --tamper-test]"""

import argparse

from .config import AUDIT_LOG
from .orchestrator import run
from .audit import verify_chain, tamper_test


def main():
    p = argparse.ArgumentParser(prog="apsrai", description="APSRAI simulation")
    p.add_argument("--demo", action="store_true",
                   help="Deterministic run exercising all six behaviours")
    p.add_argument("--simulate", action="store_true",
                   help="Unattended run with randomised operator decisions")
    p.add_argument("--verify", action="store_true",
                   help="Verify the existing audit-log hash chain and exit")
    p.add_argument("--tamper-test", action="store_true",
                   help="Flip one entry and show the chain detects it")
    args = p.parse_args()

    if args.verify:
        print(verify_chain(AUDIT_LOG)[1])
    elif args.tamper_test:
        tamper_test(AUDIT_LOG)
    elif args.demo:
        run(demo=True)
    else:
        run(simulate=args.simulate)


if __name__ == "__main__":
    main()
