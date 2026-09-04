#!/usr/bin/env python3
"""Atheris child process for the bounded python-eval case adapter."""

from __future__ import annotations

import argparse
import builtins
import contextlib
import os
from pathlib import Path
import runpy
import sys

import atheris


TRIGGER = Path("/case/trigger")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("target")
    parser.add_argument("function")
    parser.add_argument("mode", choices=["input", "argument"])
    parser.add_argument("atheris_args", nargs=argparse.REMAINDER)
    args = parser.parse_args()

    target_path = Path(args.target)

    def test_one_input(data: bytes) -> None:
        value = data.decode("utf-8", errors="ignore")
        TRIGGER.unlink(missing_ok=True)
        original_input = builtins.input
        try:
            builtins.input = lambda *_args, **_kwargs: value
            with open(os.devnull, "w", encoding="utf-8") as sink:
                with contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink):
                    namespace = runpy.run_path(str(target_path), run_name="apollyon_fuzz_target")
                    function = namespace.get(args.function)
                    if not callable(function):
                        raise RuntimeError("recorded function is no longer callable")
                    try:
                        function() if args.mode == "input" else function(value)
                    except Exception:
                        # This adapter measures only the recorded marker side effect.
                        # Ordinary target exceptions are outside that bounded property.
                        pass
        finally:
            builtins.input = original_input
        if TRIGGER.is_file():
            raise RuntimeError("Apollyon marker side effect reached")

    atheris.Setup([sys.argv[0], *args.atheris_args], test_one_input)
    atheris.Fuzz()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
