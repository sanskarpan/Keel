"""Modal deployment scaffold for Keel (UNQUALIFIED).

Defines the Keel roles as Modal functions without provisioning anything: run
``modal deploy keel.py`` only after creating the ``keel-operator`` and
``keel-webhook`` secrets and pointing them at an external managed PostgreSQL
database. See README.md in this directory. Nothing here has run against Modal;
the local Compose profile remains the only qualified runtime.
"""

import os
import pathlib
import socket
import subprocess

import modal

app = modal.App("keel")

_HERE = pathlib.Path(__file__).resolve().parent
_REPO = _HERE.parent.parent

# Go toolchain pinned to the repository baseline version and linux/amd64 checksum.
# Re-check the checksum together with Go security support windows before production use.
GO_VERSION = "1.27.1"
GO_SHA256 = "63d339f0da5ab53635a56f2490a7984dfe12dfcff22ad749f63edaf590168445"

keel_image = (
    modal.Image.debian_slim(python_version="3.12")
    .apt_install("ca-certificates", "curl")
    .run_commands(
        f"curl -fsSLo /tmp/go.tgz https://go.dev/dl/go{GO_VERSION}.linux-amd64.tar.gz",
        f"echo '{GO_SHA256}  /tmp/go.tgz' | sha256sum -c -",
        "tar -C /usr/local -xzf /tmp/go.tgz",
    )
    .env({"GOTOOLCHAIN": "local", "CGO_ENABLED": "0"})
    # Public Supabase pooler CA bundle (not a secret). Pinned so staging DSNs can use
    # sslmode=verify-full against the pooler's private CA.
    .add_local_file(
        str(_HERE / "supabase-ca-2021.pem"), "/etc/keel/supabase-ca.pem", copy=True
    )
    # copy=True because the Go build is a later build step; the git store, local secrets,
    # caches and non-build docs are excluded so every image build stays small.
    .add_local_dir(
        str(_REPO),
        remote_path="/repo",
        copy=True,
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
    .run_commands("cd /repo && /usr/local/go/bin/go build -o /keel ./cmd/keel")
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
    """Serve the operator API (bearer-authenticated routes plus health endpoints).

    The server runs as a child process and this function returns: Modal owns the port
    tunnel, so replacing the Python process with ``execv`` would break it. Startup is
    idempotent because the function can be invoked more than once per container.
    """
    if _listening(8080):
        return
    subprocess.Popen(["/keel"])


def _listening(port: int) -> bool:
    """True when something already serves the port (idempotent web_server startup)."""
    probe = socket.socket()
    probe.settimeout(0.2)
    try:
        return probe.connect_ex(("127.0.0.1", port)) == 0
    finally:
        probe.close()


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
    subprocess.run(["/keel"], check=False)


@app.function(image=keel_image)
def migrate_db():
    """Apply the embedded migration bundle once against the managed database."""
    subprocess.run(["/keel", "migrate"], check=True)


@app.local_entrypoint()
def main():
    migrate_db.remote()
