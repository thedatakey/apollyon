FROM python@sha256:5f55cdf0c5d9dc1a415637a5ccc4a9e18663ad203673173b8cda8f8dcacef689

RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
      build-essential=12.12 \
      clang=1:19.0-63 \
      libclang-rt-19-dev=1:19.1.7-3+b1 \
    && rm -rf /var/lib/apt/lists/*

RUN python -m pip install --no-cache-dir \
      atheris==3.0.0 \
      z3-solver==4.15.3.0 \
    && python - <<'PY'
import importlib.metadata
assert importlib.metadata.version("atheris") == "3.0.0"
assert importlib.metadata.version("z3-solver") == "4.15.3.0"
PY

LABEL org.opencontainers.image.title="Apollyon Phase 3 bounded evidence tools" \
      org.opencontainers.image.source="https://github.com/thedatakey/apollyon" \
      org.opencontainers.image.version="1" \
      io.apollyon.atheris="3.0.0" \
      io.apollyon.z3-solver="4.15.3.0"
