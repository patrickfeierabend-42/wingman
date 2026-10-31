"""Run GuardDog extraction helpers from a trusted working directory (aus afhOS, scripts/supply_chain)."""

from __future__ import annotations

import sys
from collections.abc import Callable
from typing import Any


def _extract_with_trusted_cwd(
    extract_archive: Callable[[str, str], None],
    nono_module: Any,
    archive_path: str,
    target_path: str,
) -> None:
    original_exec = nono_module.sandboxed_exec

    def trusted_exec(*args: Any, **kwargs: Any) -> Any:
        kwargs["cwd"] = sys.prefix
        return original_exec(*args, **kwargs)

    nono_module.sandboxed_exec = trusted_exec
    try:
        extract_archive(archive_path, target_path)
    finally:
        nono_module.sandboxed_exec = original_exec


def main() -> int:
    import nono_py
    from guarddog import cli as cli_module
    from guarddog.sandbox import extract_sandboxed

    cli_module.extract_sandboxed = lambda archive, target: _extract_with_trusted_cwd(
        extract_sandboxed, nono_py, archive, target
    )
    return cli_module.cli()


if __name__ == "__main__":
    raise SystemExit(main())
