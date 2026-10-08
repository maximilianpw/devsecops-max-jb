# cgr.dev/chainguard/python:latest-dev — Python 3.14.8, publiée le 2026-10-08
FROM cgr.dev/chainguard/python@sha256:894aed3297d91283e1fc4c542f5374a4b5f3726134fda7c94eaa539342be1e05 AS builder

WORKDIR /app

COPY requirements.txt /app/requirements.txt

# Venv créé sans pip et alimenté par le pip du builder : aucun gestionnaire de paquets
# n'est copié dans le runtime.
RUN python -m venv --without-pip /app/venv \
    && pip --python /app/venv/bin/python install --no-cache-dir -r /app/requirements.txt

# cgr.dev/chainguard/python:latest — Python 3.14.8, publiée le 2026-10-08
FROM cgr.dev/chainguard/python@sha256:b6248c85ba9b97e1e61b30197f309cc4d21661f889fefa5268f0a7bc530dad46

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
