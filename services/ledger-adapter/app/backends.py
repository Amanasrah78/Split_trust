import asyncio
import json
import os
from dataclasses import dataclass
from typing import Any, Awaitable, Callable

import httpx

from shared.splittrust.observability import monotonic_ns

CommandRunner = Callable[[list[str], float], Awaitable[str]]


@dataclass(frozen=True)
class LedgerResult:
    identifier: str
    submit_latency_ns: int
    confirmation_latency_ns: int
    lookup_status: str


class IotaConfirmationError(RuntimeError):
    def __init__(
        self,
        message: str,
        confirmation_latency_ns: int,
        lookup_status: str,
    ):
        super().__init__(message)
        self.confirmation_latency_ns = confirmation_latency_ns
        self.lookup_status = lookup_status


async def run_command(argv: list[str], timeout_seconds: float) -> str:
    process = await asyncio.create_subprocess_exec(
        *argv,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(
            process.communicate(), timeout=timeout_seconds
        )
    except TimeoutError:
        process.kill()
        await process.wait()
        raise RuntimeError("IOTA submission command timed out") from None

    if process.returncode != 0:
        detail = stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(
            f"IOTA submission command failed ({process.returncode}): {detail}"
        )
    return stdout.decode("utf-8")


def find_transaction_digest(value: Any) -> str | None:
    if isinstance(value, dict):
        for key in ("digest", "transactionDigest", "transaction_digest"):
            candidate = value.get(key)
            if isinstance(candidate, str) and candidate:
                return candidate
        for child in value.values():
            found = find_transaction_digest(child)
            if found:
                return found
    elif isinstance(value, list):
        for child in value:
            found = find_transaction_digest(child)
            if found:
                return found
    return None


class IotaBackend:
    """Submit a Move transaction with the current IOTA CLI and poll JSON-RPC."""

    def __init__(
        self,
        *,
        rpc_url: str,
        package_id: str,
        cli_path: str = "iota",
        module: str = "commitment_registry",
        function: str = "submit",
        gas_budget: int = 10_000_000,
        tag_hex: str = "73706c69742d74727573742d76310000",
        poll_interval_seconds: float = 1.0,
        confirmation_timeout_seconds: float = 60.0,
        submit_timeout_seconds: float = 60.0,
        command_runner: CommandRunner = run_command,
        client: httpx.AsyncClient | None = None,
    ):
        if not package_id:
            raise RuntimeError("IOTA_PACKAGE_ID is required in iota mode")
        tag = bytes.fromhex(tag_hex)
        if len(tag) != 16:
            raise RuntimeError("IOTA_COMMITMENT_TAG_HEX must encode 16 bytes")

        self.rpc_url = rpc_url
        self.package_id = package_id
        self.cli_path = cli_path
        self.module = module
        self.function = function
        self.gas_budget = gas_budget
        self.tag_hex = tag_hex
        self.poll_interval_seconds = poll_interval_seconds
        self.confirmation_timeout_seconds = confirmation_timeout_seconds
        self.submit_timeout_seconds = submit_timeout_seconds
        self.command_runner = command_runner
        self.client = client

    @classmethod
    def from_environment(cls) -> "IotaBackend":
        return cls(
            rpc_url=os.getenv(
                "IOTA_RPC_URL", "https://api.testnet.iota.cafe"
            ),
            package_id=os.getenv("IOTA_PACKAGE_ID", ""),
            cli_path=os.getenv("IOTA_CLI_PATH", "iota"),
            module=os.getenv("IOTA_MOVE_MODULE", "commitment_registry"),
            function=os.getenv("IOTA_MOVE_FUNCTION", "submit"),
            gas_budget=int(os.getenv("IOTA_GAS_BUDGET", "10000000")),
            tag_hex=os.getenv(
                "IOTA_COMMITMENT_TAG_HEX",
                "73706c69742d74727573742d76310000",
            ),
            poll_interval_seconds=float(
                os.getenv("IOTA_POLL_INTERVAL_SECONDS", "1")
            ),
            confirmation_timeout_seconds=float(
                os.getenv("IOTA_CONFIRMATION_TIMEOUT_SECONDS", "60")
            ),
            submit_timeout_seconds=float(
                os.getenv("IOTA_SUBMIT_TIMEOUT_SECONDS", "60")
            ),
        )

    def submission_command(
        self,
        commitment: bytes,
        session_id: str,
        tag_hex: str | None = None,
    ) -> list[str]:
        if len(commitment) != 32:
            raise ValueError("IOTA commitment must contain 32 bytes")

        session_bytes = session_id.encode("ascii")
        if len(session_bytes) != 32:
            raise ValueError(
                "Session identifier must contain 32 ASCII bytes"
            )

        selected_tag_hex = tag_hex or self.tag_hex
        selected_tag = bytes.fromhex(selected_tag_hex)

        if len(selected_tag) != 16:
            raise ValueError("IOTA tag must encode 16 bytes")

        return [
            self.cli_path,
            "client",
            "call",
            "--package",
            self.package_id,
            "--module",
            self.module,
            "--function",
            self.function,
            "--args",
            f"0x{selected_tag_hex}",
            f"0x{commitment.hex()}",
            f"0x{session_bytes.hex()}",
            "--gas-budget",
            str(self.gas_budget),
            "--json",
        ]

    async def submit(
        self,
        commitment: bytes,
        session_id: str,
        on_submitted: Callable[[str, int], None] | None = None,
        tag_hex: str | None = None,
    ) -> LedgerResult:
        started = monotonic_ns()
        output = await self.command_runner(
            self.submission_command(
                commitment,
                session_id,
                tag_hex=tag_hex,
            ),
            self.submit_timeout_seconds,
        )
        submit_latency_ns = monotonic_ns() - started

        try:
            response = json.loads(output)
        except json.JSONDecodeError as exc:
            raise RuntimeError("IOTA CLI returned invalid JSON") from exc
        identifier = find_transaction_digest(response)
        if not identifier:
            raise RuntimeError("IOTA CLI response contains no transaction digest")
        if on_submitted is not None:
            on_submitted(identifier, submit_latency_ns)

        lookup_started = monotonic_ns()
        lookup_status = await self.wait_for_confirmation(identifier)
        return LedgerResult(
            identifier=identifier,
            submit_latency_ns=submit_latency_ns,
            confirmation_latency_ns=monotonic_ns() - lookup_started,
            lookup_status=lookup_status,
        )

    async def wait_for_confirmation(self, identifier: str) -> str:
        lookup_started = monotonic_ns()
        deadline = asyncio.get_running_loop().time() + (
            self.confirmation_timeout_seconds
        )
        owns_client = self.client is None
        client = self.client or httpx.AsyncClient(timeout=10.0)
        last_status = "not_found"
        try:
            while asyncio.get_running_loop().time() < deadline:
                response = await client.post(
                    self.rpc_url,
                    json={
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "iota_getTransactionBlock",
                        "params": [
                            identifier,
                            {
                                "showEffects": True,
                                "showEvents": True,
                                "showObjectChanges": True,
                            },
                        ],
                    },
                )
                response.raise_for_status()
                payload = response.json()
                result = payload.get("result")
                if isinstance(result, dict):
                    effects_status = (
                        result.get("effects", {}).get("status", {})
                    )
                    status = effects_status.get("status", "unknown")
                    checkpoint = result.get("checkpoint")
                    last_status = (
                        f"{status}:checkpoint={checkpoint}"
                        if checkpoint is not None
                        else str(status)
                    )
                    if status == "failure":
                        error = effects_status.get("error", "unknown error")
                        raise IotaConfirmationError(
                            f"IOTA transaction failed: {error}",
                            monotonic_ns() - lookup_started,
                            last_status,
                        )
                    if status == "success" and checkpoint is not None:
                        return last_status
                await asyncio.sleep(self.poll_interval_seconds)
        finally:
            if owns_client:
                await client.aclose()
        raise IotaConfirmationError(
            "IOTA confirmation timed out; last lookup status: " + last_status,
            monotonic_ns() - lookup_started,
            last_status,
        )
