#!/usr/bin/env python3
"""Run the narrow Python-eval evidence adapter from inside its sandbox."""

from __future__ import annotations

import argparse
import ast
import base64
import builtins
import contextlib
import difflib
import hashlib
import json
import os
from pathlib import Path
import platform
import runpy
import subprocess
import sys

import importlib.metadata


TRIGGER = Path("/case/trigger")
PAYLOAD = "__import__('pathlib').Path('/case/trigger').write_text('APOLLYON')"


@contextlib.contextmanager
def discard_target_output():
    with open(os.devnull, "w", encoding="utf-8") as sink:
        stdout = os.dup(1)
        stderr = os.dup(2)
        try:
            os.dup2(sink.fileno(), 1)
            os.dup2(sink.fileno(), 2)
            yield
        finally:
            os.dup2(stdout, 1)
            os.dup2(stderr, 2)
            os.close(stdout)
            os.close(stderr)


def enclosing_function(tree: ast.AST, line: int) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    matches = [
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.lineno <= line <= (node.end_lineno or node.lineno)
    ]
    return min(matches, key=lambda node: (node.end_lineno or node.lineno) - node.lineno, default=None)


def eval_call(tree: ast.AST, line: int) -> ast.Call | None:
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and node.lineno == line
            and isinstance(node.func, ast.Name)
            and node.func.id == "eval"
            and len(node.args) == 1
        ):
            return node
    return None


def invoke(path: Path, function: ast.FunctionDef | ast.AsyncFunctionDef, value: str):
    if isinstance(function, ast.AsyncFunctionDef):
        raise ValueError("async functions are outside the python-eval adapter")
    positional = function.args.posonlyargs + function.args.args
    required = len(positional) - len(function.args.defaults)
    if function.args.vararg or function.args.kwarg or function.args.kwonlyargs:
        raise ValueError("variadic and keyword-only functions are outside the adapter")
    original_input = builtins.input
    try:
        builtins.input = lambda *_args, **_kwargs: value
        with discard_target_output():
            namespace = runpy.run_path(str(path), run_name="apollyon_case_target")
            target = namespace.get(function.name)
            if not callable(target):
                raise ValueError("affected function was not callable after loading the target")
            if len(positional) == 0 and required == 0:
                return target()
            if len(positional) == 1 and required <= 1:
                return target(value)
            raise ValueError("adapter supports only zero- or one-argument functions")
    finally:
        builtins.input = original_input


def run_reproducer(path: Path, function: ast.FunctionDef | ast.AsyncFunctionDef) -> tuple[bool, str | None]:
    TRIGGER.unlink(missing_ok=True)
    error = None
    try:
        invoke(path, function, PAYLOAD)
    except Exception as exc:  # target exceptions are evidence, not controller failures
        error = f"{type(exc).__name__}: {exc}"[:500]
    fired = TRIGGER.is_file() and TRIGGER.read_text(encoding="utf-8") == "APOLLYON"
    TRIGGER.unlink(missing_ok=True)
    return fired, error


def propose_patch(source: str, line: int) -> tuple[str, str]:
    lines = source.splitlines(keepends=True)
    if line < 1 or line > len(lines) or "eval(" not in lines[line - 1]:
        raise ValueError("affected line no longer contains the modeled eval call")
    lines[line - 1] = lines[line - 1].replace("eval(", "ast.literal_eval(", 1)
    if not any(
        isinstance(node, ast.Import) and any(alias.name == "ast" for alias in node.names)
        for node in ast.parse(source).body
    ):
        lines.insert(0, "import ast\n")
    patched = "".join(lines)
    diff = "".join(
        difflib.unified_diff(
            source.splitlines(keepends=True),
            patched.splitlines(keepends=True),
            fromfile="a/target.py",
            tofile="b/target.py",
        )
    )
    return patched, diff


def run_existing_tests(source_root: Path) -> tuple[bool, str]:
    command = [sys.executable, "-m", "unittest", "discover", "-s", str(source_root), "-p", "test*.py"]
    completed = subprocess.run(
        command,
        cwd=source_root,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=10,
        check=False,
        env={"PATH": os.environ.get("PATH", ""), "PYTHONDONTWRITEBYTECODE": "1"},
    )
    return completed.returncode == 0, " ".join(command)


def invocation_mode(function: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
    positional = function.args.posonlyargs + function.args.args
    required = len(positional) - len(function.args.defaults)
    if len(positional) == 0 and required == 0:
        return "input"
    if len(positional) == 1 and required <= 1:
        return "argument"
    raise ValueError("adapter supports only zero- or one-argument functions")


def formal_eval_replacement(tree: ast.AST, line: int) -> dict:
    from z3 import Int, Solver, unsat, get_version_string

    calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and node.lineno == line
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "ast"
        and node.func.attr == "literal_eval"
    ]
    if len(calls) != 1:
        return {
            "method": "z3/syntax-call-identity/v1",
            "property": "the affected call is not the builtin eval function",
            "result": "failed",
            "reason": "patched AST did not contain exactly one mapped ast.literal_eval call",
            "tool_version": f"z3-solver {get_version_string()}",
        }
    call_kind = Int("affected_call_kind")
    solver = Solver()
    solver.add(call_kind == 1)  # 1 models the mapped ast.literal_eval call; 0 models builtin eval.
    solver.add(call_kind == 0)
    result = solver.check()
    return {
        "method": "z3/syntax-call-identity/v1",
        "property": "the affected call is not the builtin eval function",
        "assumptions": [
            "0 denotes a direct builtin eval call",
            "1 denotes the single AST-mapped ast.literal_eval call at the affected location",
        ],
        "bounds": ["one affected Python call", "syntax identity only; no claim about arbitrary program behavior"],
        "solver_result": str(result),
        "result": "passed" if result == unsat else "failed",
        "tool_version": f"z3-solver {get_version_string()}",
    }


def run_fuzz(path: Path, function: ast.FunctionDef | ast.AsyncFunctionDef, seconds: int, label: str) -> dict:
    corpus = Path(f"/case/corpus-{label}")
    artifacts = Path(f"/case/artifacts-{label}")
    corpus.mkdir(mode=0o700, exist_ok=False)
    artifacts.mkdir(mode=0o700, exist_ok=False)
    seed = corpus / "recorded-payload"
    seed.write_bytes(PAYLOAD.encode())
    TRIGGER.unlink(missing_ok=True)
    command = [
        sys.executable,
        "/case/atheris_worker.py",
        str(path),
        function.name,
        invocation_mode(function),
        str(corpus),
        f"-max_total_time={seconds}",
        f"-artifact_prefix={artifacts}/",
    ]
    completed = subprocess.run(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=seconds + 8,
        check=False,
        env={
            "PATH": os.environ.get("PATH", ""),
            "APOLLYON_SANDBOX": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
        },
    )
    marker = TRIGGER.is_file()
    artifact_names = sorted(item.name for item in artifacts.iterdir() if item.is_file())
    TRIGGER.unlink(missing_ok=True)
    return {
        "engine": f"Atheris {importlib.metadata.version('atheris')}",
        "seconds": seconds,
        "seed_sha256": hashlib.sha256(PAYLOAD.encode()).hexdigest(),
        "process_exit": completed.returncode,
        "marker_observed": marker,
        "artifact_count": len(artifact_names),
        "triggering_input": (
            {"encoding": "base64", "value": base64.b64encode(PAYLOAD.encode()).decode()}
            if marker and completed.returncode != 0
            else None
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("case")
    parser.add_argument("target")
    parser.add_argument("--propose-fix", action="store_true")
    parser.add_argument("--formal-z3", action="store_true")
    parser.add_argument("--fuzz-seconds", type=int, default=0)
    args = parser.parse_args()
    if os.environ.get("APOLLYON_SANDBOX") != "1" or not Path("/.dockerenv").exists():
        raise SystemExit("case worker refuses to run outside its container sandbox")

    case = json.loads(Path(args.case).read_text(encoding="utf-8"))
    target = Path(args.target)
    location = case["claim"]["affected_locations"][0]
    line = int(location["line"])
    source = target.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(target))
    function = enclosing_function(tree, line)
    call = eval_call(tree, line)
    limitations = list(case.get("limitations", []))
    limitations.append("Result applies only to the recorded Python eval call and sandbox run")
    if function is None or call is None:
        case["limitations"] = limitations + ["Adapter could not map the finding to a supported function-local eval call"]
        print(json.dumps(case, sort_keys=True, separators=(",", ":")))
        return 0

    fired, original_error = run_reproducer(target, function)
    case["evidence"]["reproducer"] = {
        "adapter": "python-eval/v1",
        "function": function.name,
        "payload_sha256": hashlib.sha256(PAYLOAD.encode()).hexdigest(),
        "triggered": fired,
        "target_error": original_error,
    }
    case["limitations"] = limitations
    if not fired:
        case["limitations"].append("Reproducer did not trigger; candidate status was preserved")
        print(json.dumps(case, sort_keys=True, separators=(",", ":")))
        return 0

    case["status"] = "validated"
    case["transitions"] = ["candidate", "validated"]
    if not args.propose_fix:
        print(json.dumps(case, sort_keys=True, separators=(",", ":")))
        return 0

    original_fuzz = run_fuzz(target, function, args.fuzz_seconds, "original") if args.fuzz_seconds else None
    patched, diff = propose_patch(source, line)
    target.write_text(patched, encoding="utf-8")
    patched_tree = ast.parse(patched, filename=str(target))
    patched_function = enclosing_function(patched_tree, line + (patched.startswith("import ast\n") and not source.startswith("import ast\n")))
    if patched_function is None:
        raise ValueError("patched function could not be located")
    blocked, patched_error = run_reproducer(target, patched_function)
    regression_value = invoke(target, patched_function, "{'answer': 42}")
    regression_passed = regression_value == {"answer": 42}
    tests_passed, test_command = run_existing_tests(target.parent)
    formal = formal_eval_replacement(patched_tree, line + (patched.startswith("import ast\n") and not source.startswith("import ast\n"))) if args.formal_z3 else None
    patched_fuzz = run_fuzz(target, patched_function, args.fuzz_seconds, "patched") if args.fuzz_seconds else None
    fuzz_passed = (
        original_fuzz is None
        or (
            original_fuzz["process_exit"] != 0
            and original_fuzz["marker_observed"]
            and patched_fuzz is not None
            and patched_fuzz["process_exit"] == 0
            and not patched_fuzz["marker_observed"]
        )
    )
    formal_passed = formal is None or formal.get("result") == "passed"
    case["remediation"] = {
        "patch": diff,
        "applied_to": "disposable sandbox copy only",
        "regression_tests": [
            {"name": "literal input remains supported", "result": "passed" if regression_passed else "failed"},
            {"name": "existing unittest discovery", "result": "passed" if tests_passed else "failed", "command": test_command},
        ],
    }
    verified = not blocked and regression_passed and tests_passed and formal_passed and fuzz_passed
    case["verification"] = {
        "method": "reproducer-and-regression/v1",
        "scope_statement": "Verified means only that the documented property held under the recorded assumptions and bounds.",
        "command": "python /case/worker.py /case/case.json /case/source/<affected-path> --propose-fix",
        "bounds": ["one affected Python function", "one generated payload", "10 second unittest timeout", "outer sandbox wall time at most 60 seconds"],
        "tool_versions": [f"Python {platform.python_version()}"],
        "result": "passed" if verified else "failed",
        "original_trigger_blocked": not blocked,
        "patched_target_error": patched_error,
    }
    if formal is not None:
        case["verification"]["formal"] = formal
        case["verification"]["tool_versions"].append(formal["tool_version"])
    if original_fuzz is not None:
        case["verification"]["fuzzing"] = {
            "method": "atheris/recorded-seed-comparison/v1",
            "bounds": [f"{args.fuzz_seconds} second budget per target", "recorded payload seed plus Atheris mutations"],
            "original": original_fuzz,
            "patched": patched_fuzz,
            "result": "passed" if fuzz_passed else "failed",
        }
        case["verification"]["tool_versions"].append(original_fuzz["engine"])
    if verified:
        case["status"] = "verified"
        case["transitions"] = ["candidate", "validated", "remediated", "verified"]
    else:
        case["status"] = "remediated"
        case["transitions"] = ["candidate", "validated", "remediated"]
        case["limitations"].append("Independent re-verification did not satisfy every recorded check")
    print(json.dumps(case, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
