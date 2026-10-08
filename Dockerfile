FROM cgr.dev/chainguard/python@sha256:894aed3297d91283e1fc4c542f5374a4b5f3726134fda7c94eaa539342be1e05 AS builder
WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN python -m venv --without-pip /app/venv \
    && pip --python /app/venv/bin/python install --no-cache-dir -r /app/requirements.txt

FROM cgr.dev/chainguard/python@sha256:b6248c85ba9b97e1e61b30197f309cc4d21661f889fefa5268f0a7bc530dad46
WORKDIR /app
COPY --from=builder /app/venv /app/venv
COPY app.py /app/app.py
USER 65532:65532
EXPOSE 5000
ENTRYPOINT ["/app/venv/bin/python", "/app/app.py"]
