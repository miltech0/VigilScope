"""VigilScope application entry point."""

from __future__ import annotations

import argparse
import json
import sys

from system_info.app import SystemInfoApp
from system_info.metrics import collect_system_snapshot
from system_info.product import PRODUCT_DESCRIPTION_EN, PRODUCT_NAME, PRODUCT_VERSION


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=f"{PRODUCT_NAME}: {PRODUCT_DESCRIPTION_EN}"
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"{PRODUCT_NAME} {PRODUCT_VERSION}",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Collect local system data and print JSON without opening the GUI.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.check:
        snapshot = collect_system_snapshot()
        if sys.stdout is not None:
            print(json.dumps(snapshot, ensure_ascii=False, indent=2))
        return

    app = SystemInfoApp()
    app.mainloop()


if __name__ == "__main__":
    main()
