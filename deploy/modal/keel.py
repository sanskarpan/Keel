"""Modal deployment scaffold for Keel (UNQUALIFIED).

Defines the Keel roles as Modal functions without provisioning anything: run
``modal deploy keel.py`` only after creating the ``keel-operator`` and
``keel-webhook`` secrets and pointing them at an external managed PostgreSQL
database. See README.md in this directory. Nothing here has run against Modal;
the local Compose profile remains the only qualified runtime.
"""

import os
import subprocess

import modal

app = modal.App("keel")

# Builder image pinned 2026-11-01 (index digest for golang:1.27-bookworm).
# Re-check the digest together with Go security support windows before production use.
GO_BUILDER = "golang@sha256:d9b6a1beb9474adc2a1ce842573639b44b2a0dd49b6669f51d3821baf9ec37c9"

keel_image = (
    modal.Image.from_registry(GO_BUILDER)
    .env({"GOTOOLCHAIN": "local", "CGO_ENABLED": "0"})
    # Only what the build needs: the git object store and local caches are irrelevant
    # remotely and would slow every image build.
    .add_local_dir(
        "../..",
        remote_path="/repo",
        ignore=[
            ".git",
            ".env",
            ".env.*",
            "**/__pycache__",
            "**/*.pyc",
            "deploy/modal",
            "docs",
            "research",
        ],
    )
    .run_commands("cd /repo && go build -o /keel ./cmd/keel")
)

operator_secret = modal.Secret.from_name("keel-operator")
webhook_secret = modal.Secret.from_name("keel-webhook")


@app.function(
    image=keel_image,
    secrets=[operator_secret],
    env={"KEEL_ROLE": "operator-api"},
)
@modal.web_server(port=8080, startup_timeout=60)
def serve_operator_api():
    """Serve the operator API (bearer-authenticated routes plus health endpoints)."""
    os.execv("/keel", ["keel"])


@app.function(
    image=keel_image,
    secrets=[webhook_secret],
    env={"KEEL_ROLE": "webhook-worker"},
    min_containers=1,
    timeout=12 * 3600,
)
def run_webhook_worker():
    """Run the webhook delivery worker loop.

    The loop is persistent, not scheduled: lease epochs and the epoch fence make
    container restarts safe by design, so the timeout here only sets the restart
    cadence, not correctness.
    """
    os.execv("/keel", ["keel"])


@app.function(image=keel_image)
def migrate_db():
    """Apply the embedded migration bundle once against the managed database."""
    subprocess.run(["/keel", "migrate"], check=True)


@app.local_entrypoint()
def main():
    migrate_db.remote()
