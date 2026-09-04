# Phase 3 sandbox boundary

Static `apollyon scan` never executes target code. Candidate case generation is
also static and requires `--authorized` so the resulting case records the
authorization scope. Dynamic validation is a separate, explicit command:

```sh
python3 scripts/run_case_sandbox.py \
  --case case-output/APO-....json \
  --source-root /authorized/project \
  --output verified-case.json \
  --adapter python-eval \
  --propose-fix \
  --formal-z3 \
  --fuzz-seconds 1
```

The controller refuses an existing output, a non-candidate case, a case without
`scope.authorized: true`, a non-tainted/non-APO004 discovery record, paths that
escape the selected root, symbolic links, non-Python targets, and source trees
larger than 128 files or 8 MiB. Concurrent mutation of the selected tree is
outside this pre-alpha controller's guarantees; use an immutable checkout.

The controller uses the trusted Docker CLI and a locally prepared tools image.
It never pulls or installs anything during case execution. Build the image as
a separate trusted step:

```sh
docker build --tag apollyon-phase3-tools:1 docker/phase3-tools
docker image inspect apollyon-phase3-tools:1
```

The Dockerfile pins the Python base digest, top-level Debian packages, Atheris
3.0.0, and z3-solver 4.15.3.0. The controller validates image labels, resolves
the tag to its local content-addressed image ID, executes that ID, and records
both it and the base digest in the case. Rebuilding can produce a different
content ID as Debian transitive packages change; the recorded ID is the exact
runtime for that case.

Before copying case or target bytes, the controller starts and inspects a
container with all of these properties:

- no network;
- read-only root filesystem;
- no host bind mounts or volumes;
- numeric unprivileged user `65534:65534`;
- every Linux capability dropped and `no-new-privileges` enabled;
- one CPU, 256 MiB memory with no additional swap, and 64 processes;
- a 16 MiB `noexec`, `nosuid`, `nodev` tmpfs as the only writable case area;
- a caller-selected 1–60 second wall-time bound (30 seconds by default).

Any inspection mismatch fails closed before target bytes enter the container.
Only the case record, bounded source snapshot, and repository-owned worker are
streamed over `docker exec`; there is no host mount and no host environment or
secret forwarding. The container is removed after success, failure, or timeout.

The Python worker refuses direct non-container execution. The controller is the
security boundary: calling the worker by itself is unsupported. Target imports,
the generated reproducer, proposed patch, and test discovery all run inside the
same disposable sandbox. The proposed diff is returned for human review and is
never applied to the selected host source or committed.

`--formal-z3` proves only that the single AST-mapped replacement call cannot
simultaneously be the direct builtin `eval` call under the adapter's two-value
syntax model. `--fuzz-seconds N` runs Atheris for 1–5 seconds each against the
original and patched disposable copies, starting from the recorded payload; it
records the crash input, exit state, artifact count, and time bound. Neither
check reasons about arbitrary program behavior.

A passing case is scoped to the fixed reproducer, affected function, generated
patch, test command, local tools-image ID, and recorded bounds. It is not a
claim about other inputs, calls, or the rest of the program.
