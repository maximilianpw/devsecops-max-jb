# syntax=docker/dockerfile:1.27.1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e

# cgr.dev/chainguard/python:latest-dev — Python 3.15.0, publiée le 2026-10-25
FROM cgr.dev/chainguard/python@sha256:dde1a2549dd62864f0263dae8e877680837b4e738a7ecc85c671c55c069848ac AS builder

WORKDIR /app

COPY requirements.txt /app/requirements.txt

ENV PIP_CACHE_DIR=/home/nonroot/.cache/pip

# Les montages appartiennent au nonroot du builder et ne deviennent pas des couches.
# Le jeton factice simule l'accès à un dépôt privé sans être imprimé ni conservé.
RUN --mount=type=cache,target=/home/nonroot/.cache/pip,uid=65532,gid=65532,sharing=locked \
    --mount=type=secret,id=package_token,required=true,uid=65532,gid=65532,mode=0400 \
    python -c "from pathlib import Path; import sys; sys.exit(0 if Path('/run/secrets/package_token').read_bytes() else 'Build secret package_token must not be empty')" \
    && test -w "${PIP_CACHE_DIR}" \
    && python -m venv --without-pip /app/venv \
    && pip --python /app/venv/bin/python install -r /app/requirements.txt

# cgr.dev/chainguard/python:latest — Python 3.15.0, publiée le 2026-10-25
FROM cgr.dev/chainguard/python@sha256:49fd266eb8a1331194c318b742087c7a2939cc5794fa64f17feb9e17e12703e2

ENV PATH="/app/venv/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Sans --chown, COPY --from conserve l'UID nonroot du builder et l'application pourrait
# réécrire ses dépendances. WORKDIR vient après les COPY, sinon il créerait /app au nom
# de nonroot, utilisateur par défaut de l'image.
COPY --from=builder --chown=0:0 /app/venv /app/venv
COPY app.py /app/app.py

WORKDIR /app

USER 65532:65532

EXPOSE 5000

ENTRYPOINT ["/app/venv/bin/python", "-m", "gunicorn"]
CMD ["--bind", "0.0.0.0:5000", "--workers", "2", "--worker-tmp-dir", "/dev/shm", "--no-control-socket", "--access-logfile", "-", "app:app"]
