"""Minimal bitcoind (Core / Knots) process management for the reference checks."""

from __future__ import annotations

import base64
import json
import shutil
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path


class RPCError(Exception):
    def __init__(self, code: int, message: str):
        super().__init__(f"RPC error {code}: {message}")
        self.code = code
        self.message = message


class Daemon:
    """A regtest bitcoind with no wallet and no networking, reachable over JSON-RPC."""

    def __init__(self, bindir: Path, datadir: Path, rpcport: int, name: str = "bitcoind", chain: str = "regtest"):
        self.bitcoind = Path(bindir) / "bitcoind"
        self.datadir = Path(datadir)
        self.rpcport = rpcport
        self.name = name
        self.chain = chain
        self.proc: subprocess.Popen | None = None
        self.auth = base64.b64encode(b"refcheck:refcheck").decode()

    def version(self) -> str:
        out = subprocess.run([str(self.bitcoind), "--version"], capture_output=True, text=True, check=False)
        return out.stdout.splitlines()[0] if out.stdout else out.stderr.strip()

    def start(self, timeout: float = 90.0) -> "Daemon":
        if self.datadir.exists():
            shutil.rmtree(self.datadir)
        self.datadir.mkdir(parents=True)
        args = [
            str(self.bitcoind), f"-chain={self.chain}", f"-datadir={self.datadir}", f"-rpcport={self.rpcport}",
            "-rpcbind=127.0.0.1", "-rpcallowip=127.0.0.1", "-rpcuser=refcheck", "-rpcpassword=refcheck",
            "-server=1", "-listen=0", "-connect=0", "-dnsseed=0", "-disablewallet=1", "-printtoconsole=0",
        ]
        self.proc = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError(f"{self.name} exited early with code {self.proc.returncode}; see {self.datadir}/regtest/debug.log")
            try:
                self.rpc("getblockchaininfo")
                return self
            except (RPCError, OSError, ValueError):
                time.sleep(0.25)
        raise RuntimeError(f"{self.name} did not become ready within {timeout}s")

    def rpc(self, method: str, *params):
        body = json.dumps({"jsonrpc": "1.0", "id": "refcheck", "method": method, "params": list(params)}).encode()
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.rpcport}/", data=body,
            headers={"Authorization": f"Basic {self.auth}", "Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                payload = json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            payload = json.loads(exc.read())
        if payload.get("error"):
            raise RPCError(payload["error"]["code"], payload["error"]["message"])
        return payload["result"]

    def stop(self) -> None:
        if self.proc is None:
            return
        try:
            self.rpc("stop")
        except Exception:  # noqa: BLE001
            pass
        try:
            self.proc.wait(timeout=30)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
        self.proc = None

    def __enter__(self) -> "Daemon":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()
