# Single-stage build: this project has no compiled frontend assets and
# no build step beyond `pip install`, so a multi-stage build would only
# add complexity without shrinking the final image meaningfully.
FROM python:3.12-slim

# libpq5 is the runtime half of what psycopg2-binary needs (the -binary
# wheel bundles its own libpq at install time, but some slim base images
# still benefit from having the shared lib present for TLS/locale bits).
# Kept minimal on purpose -- this image runs an API server, not a build
# toolchain, so no gcc/build-essential here.
RUN apt-get update \
    && apt-get install -y --no-install-recommends libpq5 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy only the manifest first so Docker's layer cache is reused across
# rebuilds that only change application code, not dependencies.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Runs as a non-root user -- if this container is ever compromised via
# an application-level bug, the attacker doesn't also get root inside
# the container for free.
RUN useradd --create-home --shell /bin/false appuser
USER appuser

EXPOSE 8000

# --workers 2 is a conservative default for a small service; tune via
# the WEB_CONCURRENCY env var (gunicorn reads it automatically) rather
# than rebuilding the image to change worker count.
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "wsgi:app"]
