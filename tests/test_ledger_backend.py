import json
import sys
from pathlib import Path

import httpx
import pytest

sys.path.insert(
    0, str(Path(__file__).resolve().parents[1] / "services/ledger-adapter")
)

from app.backends import IotaBackend, IotaConfirmationError


def make_backend(**overrides):
    values = {
        "rpc_url": "https://testnet.invalid",
        "package_id": "0x1234",
        "poll_interval_seconds": 0,
        "confirmation_timeout_seconds": 1,
    }
    values.update(overrides)
    return IotaBackend(**values)


def test_iota_command_contains_fixed_size_payloads():
    command = make_backend().submission_command(b"c" * 32, "s" * 32)

    args_index = command.index("--args")
    tag, commitment, session_id = command[args_index + 1 : args_index + 4]
    assert len(bytes.fromhex(tag.removeprefix("0x"))) == 16
    assert len(bytes.fromhex(commitment.removeprefix("0x"))) == 32
    assert len(bytes.fromhex(session_id.removeprefix("0x"))) == 32


@pytest.mark.asyncio
async def test_iota_submission_records_digest_and_confirmation():
    calls = []

    async def runner(argv, timeout):
        calls.append((argv, timeout))
        return json.dumps({"digest": "transaction-digest"})

    def handler(request):
        body = json.loads(request.content)
        assert body["method"] == "iota_getTransactionBlock"
        assert body["params"][0] == "transaction-digest"
        return httpx.Response(
            200,
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "checkpoint": "42",
                    "effects": {"status": {"status": "success"}},
                },
            },
        )

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(handler)
    ) as client:
        backend = make_backend(command_runner=runner, client=client)
        result = await backend.submit(b"c" * 32, "s" * 32)

    assert calls
    assert result.identifier == "transaction-digest"
    assert result.lookup_status == "success:checkpoint=42"
    assert result.submit_latency_ns >= 0
    assert result.confirmation_latency_ns >= 0


@pytest.mark.asyncio
async def test_iota_failed_effect_is_reported():
    def handler(_request):
        return httpx.Response(
            200,
            json={
                "result": {
                    "checkpoint": "9",
                    "effects": {
                        "status": {
                            "status": "failure",
                            "error": "Move abort",
                        }
                    },
                }
            },
        )

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(handler)
    ) as client:
        backend = make_backend(client=client)
        with pytest.raises(IotaConfirmationError, match="Move abort") as error:
            await backend.wait_for_confirmation("failed-digest")
    assert error.value.lookup_status == "failure:checkpoint=9"
    assert error.value.confirmation_latency_ns >= 0
