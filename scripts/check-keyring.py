"""Exercise the native Linux adapter in an owned, disposable Secret Service."""

import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import tempfile


def run_session(binary):
    daemon = subprocess.Popen(
        ["gnome-keyring-daemon", "--foreground", "--unlock", "--components=secrets",
         "--control-directory", os.environ["GNOME_KEYRING_CONTROL"]],
        stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        daemon.stdin.write(secrets.token_hex(32).encode() + b"\n")
        daemon.stdin.close()
        subprocess.run(
            ["gdbus", "wait", "--session", "--timeout", "10", "org.freedesktop.secrets"],
            check=True, timeout=15,
        )
        subprocess.run(
            [binary, "--ignored", "--exact", "native_duplicate_preserves_existing_key_and_secret"],
            env={**os.environ, "NDS_KEYRING_TEST_MODE": "available"}, check=True, timeout=30,
        )
    finally:
        daemon.terminate()
        try:
            daemon.wait(timeout=10)
        except subprocess.TimeoutExpired:
            daemon.kill()
            daemon.wait(timeout=5)


def main():
    for command in ["cargo", "dbus-run-session", "gnome-keyring-daemon", "gdbus"]:
        if shutil.which(command) is None:
            raise SystemExit(f"Missing native acceptance dependency: {command}")
    repo = Path(__file__).resolve().parents[1]
    build = subprocess.run(
        ["cargo", "test", "--locked", "-p", "nddev-device-sync-adapters-keyring",
         "--test", "native", "--no-run", "--message-format=json"],
        cwd=repo, capture_output=True, text=True, check=True, timeout=300,
    )
    artifacts = [json.loads(line) for line in build.stdout.splitlines()]
    binary = next(item["executable"] for item in artifacts
                  if item.get("executable") and item.get("target", {}).get("name") == "native")
    with tempfile.TemporaryDirectory(prefix="nds-native-keyring-") as temporary:
        root = Path(temporary)
        for name in ["data", "runtime", "control"]:
            (root / name).mkdir(mode=0o700)
        env = {**os.environ, "XDG_DATA_HOME": str(root / "data"),
               "XDG_RUNTIME_DIR": str(root / "runtime"),
               "GNOME_KEYRING_CONTROL": str(root / "control")}
        subprocess.run(
            ["dbus-run-session", "--", sys.executable, str(Path(__file__).resolve()),
             "--session", binary], env=env, check=True, timeout=60,
        )
        subprocess.run(
            [binary, "--ignored", "--exact", "unavailable_native_store_removes_pending_reservation"],
            env={**env, "DBUS_SESSION_BUS_ADDRESS": f"unix:path={root}/absent-bus",
                 "NDS_KEYRING_TEST_MODE": "unavailable"}, check=True, timeout=30,
        )
    print("Native Secret Service acceptance passed; only owned temporary resources removed.")


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--session":
        run_session(sys.argv[2])
    else:
        main()
