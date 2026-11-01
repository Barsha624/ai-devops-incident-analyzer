# syntax=docker/dockerfile:1

# ---- build stage: turn the source into a wheel -------------------------------------------------
FROM python:3.15-slim AS build
WORKDIR /src
RUN pip install --no-cache-dir build
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN python -m build --wheel --outdir /dist

# ---- runtime stage: small image, no compilers, no build tools, non-root -------------------------
FROM python:3.15-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Set to "true" to include boto3 for the CloudWatch source:
#   docker build --build-arg WITH_AWS=true -t incident-analyzer:aws .
ARG WITH_AWS=false

COPY --from=build /dist/*.whl /tmp/wheels/
RUN pip install /tmp/wheels/*.whl \
    && if [ "$WITH_AWS" = "true" ]; then pip install "boto3>=1.34"; fi \
    && rm -rf /tmp/wheels

# Synthetic demo data so `docker run IMAGE analyze /opt/samples` works with no volume mounts.
COPY samples /opt/samples

# Never run as root inside the container.
RUN useradd --create-home --uid 10001 analyzer
USER analyzer
WORKDIR /data

# API keys are NOT baked in. Pass them at run time (-e ANTHROPIC_API_KEY) and only if you opt in.
ENTRYPOINT ["incident-analyzer"]
CMD ["--help"]
