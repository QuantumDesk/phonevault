#!/usr/bin/env python3
"""Minimal Android Open Accessory host for the Phone Vault prototype."""

import argparse
import json
import os
import re
import sys
import time
import uuid

import usb.core
import usb.util

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parent))
import evm_verify  # noqa: E402  (pure-Python keccak / RLP / secp256k1 recovery)


GOOGLE_VENDOR_ID = 0x18D1
# Phone Vault permits plain accessory mode and accessory+ADB on userdebug.
# Audio-accessory composite product IDs are deliberately excluded.
AOA_ACCESSORY_PRODUCTS = {0x2D00, 0x2D01}
MAX_RESPONSE_BYTES = 65_536
AOA_GET_PROTOCOL = 51
AOA_SEND_IDENT = 52
AOA_START = 53
IDENTITY = (
    "PhoneVault",
    "EVM Signer",
    "User-confirmed offline EVM signing prototype",
    "1.0",
    "https://example.invalid/phone-vault",
    "prototype",
)


def find_android_device():
    devices = [
        device for device in usb.core.find(find_all=True)
        if device.idVendor == GOOGLE_VENDOR_ID
    ]
    if not devices:
        raise RuntimeError("No Google Android USB device found")
    if len(devices) != 1:
        raise RuntimeError(
            f"Expected exactly one Google Android USB device, found {len(devices)}"
        )
    return devices[0]


def switch_to_accessory(device):
    if device.idProduct in AOA_ACCESSORY_PRODUCTS:
        return device
    protocol = device.ctrl_transfer(0xC0, AOA_GET_PROTOCOL, 0, 0, 2)
    version = int(protocol[0]) | (int(protocol[1]) << 8)
    if version < 1:
        raise RuntimeError(f"Unsupported Android Open Accessory protocol {version}")
    for index, value in enumerate(IDENTITY):
        device.ctrl_transfer(0x40, AOA_SEND_IDENT, 0, index, value.encode("utf-8") + b"\0")
    device.ctrl_transfer(0x40, AOA_START, 0, 0, None)

    deadline = time.monotonic() + 12
    while time.monotonic() < deadline:
        time.sleep(0.4)
        accessories = [
            item for item in usb.core.find(find_all=True)
            if item.idVendor == GOOGLE_VENDOR_ID
            and item.idProduct in AOA_ACCESSORY_PRODUCTS
        ]
        if len(accessories) > 1:
            raise RuntimeError(
                f"Expected one Phone Vault accessory, found {len(accessories)}"
            )
        if accessories:
            return accessories[0]
    raise RuntimeError("Phone did not re-enumerate in accessory mode")


def open_endpoints(device):
    if device.idVendor != GOOGLE_VENDOR_ID or device.idProduct not in AOA_ACCESSORY_PRODUCTS:
        raise RuntimeError("USB device is not an allowed Android Open Accessory product")
    device.set_configuration()
    interface = device.get_active_configuration()[(0, 0)]
    if (interface.bInterfaceClass, interface.bInterfaceSubClass,
            interface.bInterfaceProtocol) != (0xFF, 0xFF, 0x00):
        raise RuntimeError("Accessory interface has an unexpected USB class")
    endpoints = list(interface)
    if len(endpoints) != 2 or any(
        usb.util.endpoint_type(endpoint.bmAttributes) != usb.util.ENDPOINT_TYPE_BULK
        for endpoint in endpoints
    ):
        raise RuntimeError("Accessory interface must expose exactly two bulk endpoints")
    incoming = [
        endpoint for endpoint in endpoints
        if usb.util.endpoint_direction(endpoint.bEndpointAddress) == usb.util.ENDPOINT_IN
    ]
    outgoing = [
        endpoint for endpoint in endpoints
        if usb.util.endpoint_direction(endpoint.bEndpointAddress) == usb.util.ENDPOINT_OUT
    ]
    if len(incoming) != 1 or len(outgoing) != 1:
        raise RuntimeError("Accessory bulk endpoint directions are ambiguous")
    endpoint_in = incoming[0]
    endpoint_out = outgoing[0]
    return endpoint_in, endpoint_out


def _rlp_length(data, offset, prefix, short_base, long_base):
    if prefix <= short_base + 55:
        return prefix - short_base, offset
    length_bytes_count = prefix - long_base
    if offset + length_bytes_count > len(data):
        raise ValueError("Truncated RLP length")
    length_bytes = data[offset:offset + length_bytes_count]
    if not length_bytes or length_bytes[0] == 0:
        raise ValueError("Non-canonical RLP length")
    length = int.from_bytes(length_bytes, "big")
    if length <= 55:
        raise ValueError("Non-canonical long RLP value")
    return length, offset + length_bytes_count


def _decode_rlp(data, offset=0):
    if offset >= len(data):
        raise ValueError("Truncated RLP value")
    prefix = data[offset]
    offset += 1
    if prefix <= 0x7F:
        return bytes([prefix]), offset
    if prefix <= 0xBF:
        length, payload_offset = _rlp_length(data, offset, prefix, 0x80, 0xB7)
        end = payload_offset + length
        if end > len(data):
            raise ValueError("Truncated RLP string")
        value = data[payload_offset:end]
        if length == 1 and value[0] <= 0x7F:
            raise ValueError("Non-canonical single-byte RLP string")
        return value, end
    length, payload_offset = _rlp_length(data, offset, prefix, 0xC0, 0xF7)
    end = payload_offset + length
    if end > len(data):
        raise ValueError("Truncated RLP list")
    values = []
    while payload_offset < end:
        value, payload_offset = _decode_rlp(data, payload_offset)
        values.append(value)
    if payload_offset != end:
        raise ValueError("RLP list length does not match payload")
    return values, end


def _rlp_integer(value, label):
    if not isinstance(value, bytes):
        raise ValueError(f"{label} is not an RLP byte string")
    if value.startswith(b"\0"):
        raise ValueError(f"{label} is a non-canonical RLP integer")
    return int.from_bytes(value, "big")


def decode_signed_eip1559(value):
    if not isinstance(value, str) or not re.fullmatch(r"0x02[0-9a-fA-F]+", value):
        raise ValueError("signedTransaction is not a typed EIP-1559 hex payload")
    if len(value) % 2:
        raise ValueError("signedTransaction has odd-length hex")
    encoded = bytes.fromhex(value[4:])
    decoded, end = _decode_rlp(encoded)
    if end != len(encoded) or not isinstance(decoded, list) or len(decoded) != 12:
        raise ValueError("signedTransaction has an invalid EIP-1559 RLP envelope")
    if decoded[8] != []:
        raise ValueError("signedTransaction unexpectedly contains an access list")
    destination = decoded[5]
    data = decoded[7]
    if not isinstance(destination, bytes) or len(destination) != 20:
        raise ValueError("signedTransaction destination is not 20 bytes")
    if not isinstance(data, bytes):
        raise ValueError("signedTransaction data is not an RLP byte string")
    fields = {
        "chainId": _rlp_integer(decoded[0], "chainId"),
        "nonce": _rlp_integer(decoded[1], "nonce"),
        "maxPriorityFeePerGas": _rlp_integer(decoded[2], "maxPriorityFeePerGas"),
        "maxFeePerGas": _rlp_integer(decoded[3], "maxFeePerGas"),
        "gasLimit": _rlp_integer(decoded[4], "gasLimit"),
        "to": "0x" + destination.hex(),
        "value": _rlp_integer(decoded[6], "value"),
        "data": "0x" + data.hex(),
        "yParity": _rlp_integer(decoded[9], "yParity"),
        "r": _rlp_integer(decoded[10], "r"),
        "s": _rlp_integer(decoded[11], "s"),
    }
    curve_order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    if fields["yParity"] not in (0, 1):
        raise ValueError("signedTransaction has invalid signature parity")
    if not (0 < fields["r"] < curve_order and 0 < fields["s"] <= curve_order // 2):
        raise ValueError("signedTransaction has a non-canonical signature")
    return fields


def _quantity(value, label):
    if not isinstance(value, str) or not re.fullmatch(r"0x(?:0|[1-9a-fA-F][0-9a-fA-F]*)", value):
        raise ValueError(f"request {label} is not a canonical hex quantity")
    return int(value, 16)


DEFAULT_PAIRING_FILE = os.path.join(
    os.path.expanduser("~"), ".config", "phone-vault", "paired-signer.json")
ADDRESS_PATTERN = r"0x[0-9a-fA-F]{40}"


def load_paired_signer(path):
    """The signer address pinned at pairing time, or None if this host has never paired."""
    try:
        with open(path, "r", encoding="utf-8") as handle:
            record = json.load(handle)
    except FileNotFoundError:
        return None
    address = record.get("address") if isinstance(record, dict) else None
    if not isinstance(address, str) or not re.fullmatch(ADDRESS_PATTERN, address):
        raise ValueError(f"pairing file is malformed: {path}")
    return address.lower()


def save_paired_signer(path, address):
    if not isinstance(address, str) or not re.fullmatch(ADDRESS_PATTERN, address):
        raise ValueError("refusing to pin an invalid signer address")
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    record = {"address": address.lower(), "pairedAt": time.strftime("%Y-%m-%dT%H:%M:%S%z")}
    payload = json.dumps(record, indent=2) + "\n"
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(payload)


def address_fingerprint(address):
    """Short tag for reading an address aloud / eyeballing; the phone shows the full address."""
    return evm_verify.keccak256(bytes.fromhex(address[2:]))[:4].hex()


def validate_response(request, response, expected_signer=None):
    """Validate a phone response against the request WITHOUT trusting the phone's own claims:
    every signed field is decoded and compared, `transactionHash` is recomputed from the signed
    bytes, and the signer is recovered from the signature and compared with `address`.

    For a signature the host MUST also supply `expected_signer` — the address pinned at pairing
    time after the user compared it with the phone's own display. Without it, validation would
    only prove that a response is self-consistent: any device could return its own valid
    signature together with its own matching address."""
    if not isinstance(response, dict) or response.get("id") != request.get("id"):
        raise ValueError("Phone response does not correlate to the request")
    status = response.get("status")
    if status == "error":
        if set(response) != {"id", "status", "error"} or not isinstance(response["error"], str):
            raise ValueError("Phone returned a malformed error response")
        return
    if request.get("method") == "getAddress":
        if set(response) != {"id", "status", "address"} or status != "ok":
            raise ValueError("Phone returned a malformed address response")
        if not isinstance(response["address"], str) or not re.fullmatch(
                r"0x[0-9a-fA-F]{40}", response["address"]):
            raise ValueError("Phone returned an invalid signer address")
        return
    if request.get("method") != "signEip1559":
        raise ValueError("Cannot validate response for an unsupported request method")
    if status == "rejected":
        if set(response) != {"id", "status"}:
            raise ValueError("Rejected response contains unexpected fields")
        return
    expected_fields = {
        "id", "status", "address", "signedTransaction", "transactionHash"
    }
    if status != "approved" or set(response) != expected_fields:
        raise ValueError("Phone returned a malformed approved response")
    if not isinstance(response["address"], str) or not re.fullmatch(
            r"0x[0-9a-fA-F]{40}", response["address"]):
        raise ValueError("Approved response contains an invalid signer address")
    if not isinstance(response["transactionHash"], str) or not re.fullmatch(
            r"0x[0-9a-fA-F]{64}", response["transactionHash"]):
        raise ValueError("Approved response contains an invalid transaction hash")
    signed = decode_signed_eip1559(response["signedTransaction"])
    comparisons = {
        "chainId": _quantity(request.get("chainId"), "chainId"),
        "nonce": _quantity(request.get("nonce"), "nonce"),
        "maxPriorityFeePerGas": _quantity(
            request.get("maxPriorityFeePerGas"), "maxPriorityFeePerGas"
        ),
        "maxFeePerGas": _quantity(request.get("maxFeePerGas"), "maxFeePerGas"),
        "gasLimit": _quantity(request.get("gasLimit"), "gasLimit"),
        "to": request.get("to", "").lower(),
        "value": _quantity(request.get("value"), "value"),
        "data": request.get("data", "").lower(),
    }
    for field, expected in comparisons.items():
        if signed[field] != expected:
            raise ValueError(
                f"signedTransaction {field} does not match request: "
                f"{signed[field]} != {expected}"
            )
    # Recompute the transaction hash from the signed bytes; never trust the phone's value.
    raw = bytes.fromhex(response["signedTransaction"][2:])
    computed_hash = "0x" + evm_verify.eip1559_transaction_hash(raw).hex()
    if response["transactionHash"].lower() != computed_hash:
        raise ValueError(
            f"transactionHash does not match the signed bytes: "
            f"{response['transactionHash']} != {computed_hash}"
        )
    # Recover the signer from the signature over the EIP-1559 signing payload and compare it
    # with the address the phone claims (and with the address the host fetched earlier).
    signing_hash = evm_verify.eip1559_signing_hash({
        "chainId": signed["chainId"],
        "nonce": signed["nonce"],
        "maxPriorityFeePerGas": signed["maxPriorityFeePerGas"],
        "maxFeePerGas": signed["maxFeePerGas"],
        "gasLimit": signed["gasLimit"],
        "to": bytes.fromhex(signed["to"][2:]),
        "value": signed["value"],
        "data": bytes.fromhex(signed["data"][2:]),
    })
    recovered = evm_verify.recover_address(
        signing_hash, signed["r"], signed["s"], signed["yParity"])
    if recovered != response["address"].lower():
        raise ValueError(
            f"signature was not produced by the claimed address: "
            f"recovered {recovered}, response says {response['address']}"
        )
    if expected_signer is None:
        raise ValueError(
            "no pinned signer: run `pair` (and compare the address with the phone screen) "
            "or pass --expect-address; a signature cannot be accepted on its own say-so"
        )
    if not isinstance(expected_signer, str) or not re.fullmatch(ADDRESS_PATTERN, expected_signer):
        raise ValueError("expected signer is not a valid address")
    if recovered != expected_signer.lower():
        raise ValueError(
            f"signature was not produced by the expected signer: "
            f"recovered {recovered}, expected {expected_signer}"
        )


def exchange(endpoint_in, endpoint_out, request, timeout_ms=120_000):
    request_id = request.get("id")
    if not isinstance(request_id, str) or not request_id:
        raise ValueError("USB request must contain a non-empty string id")
    payload = json.dumps(request, separators=(",", ":")).encode("utf-8") + b"\n"
    endpoint_out.write(payload, timeout=5_000)
    received = bytearray()
    deadline = time.monotonic() + timeout_ms / 1000
    while time.monotonic() < deadline:
        try:
            received.extend(endpoint_in.read(16_384, timeout=1_000))
        except usb.core.USBTimeoutError:
            continue
        if len(received) > MAX_RESPONSE_BYTES:
            raise ValueError("Phone response exceeds 64 KiB")
        if b"\n" in received:
            line, trailing = received.split(b"\n", 1)
            if trailing:
                raise ValueError("Phone returned more than one framed response")
            response = json.loads(line.decode("utf-8"))
            if not isinstance(response, dict):
                raise ValueError("Phone response must be a JSON object")
            if response.get("id") != request_id:
                raise ValueError("Phone response id does not match the request")
            return response
    raise TimeoutError("Timed out waiting for on-device approval")


def request_for(args):
    request_id = str(uuid.uuid4())
    if args.command in ("address", "pair"):
        return {"id": request_id, "method": "getAddress"}
    return {
        "id": request_id,
        "method": "signEip1559",
        "chainId": args.chain_id,
        "nonce": args.nonce,
        "maxPriorityFeePerGas": args.priority_fee,
        "maxFeePerGas": args.max_fee,
        "gasLimit": args.gas_limit,
        "to": args.to,
        "value": args.value,
        "data": args.data,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--pairing-file", default=DEFAULT_PAIRING_FILE,
        help="Where the paired signer address is pinned (default: %(default)s)",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("address", help="Read the public signer address (informational only)")
    subparsers.add_parser(
        "pair",
        help="Fetch the signer address, have you compare it with the phone's screen, then pin it",
    )
    sign = subparsers.add_parser("sign-test", help="Request a disposable Sepolia EIP-1559 signature")
    sign.add_argument("--chain-id", default="0xaa36a7")
    sign.add_argument("--nonce", default="0x0")
    sign.add_argument("--priority-fee", default="0x3b9aca00")
    sign.add_argument("--max-fee", default="0x77359400")
    sign.add_argument("--gas-limit", default="0x5208")
    sign.add_argument("--to", default="0x1111111111111111111111111111111111111111")
    sign.add_argument("--value", default="0x0")
    sign.add_argument("--data", default="0x")
    sign.add_argument(
        "--expect-address", default=None,
        help="Override the pinned signer for this call (the recovered signer must match it)",
    )
    args = parser.parse_args()

    try:
        expected_signer = None
        if args.command == "sign-test":
            expected_signer = args.expect_address or load_paired_signer(args.pairing_file)
            if expected_signer is None:
                raise ValueError(
                    f"no paired signer in {args.pairing_file}: run `pair` first "
                    "(or pass --expect-address)"
                )
        device = switch_to_accessory(find_android_device())
        endpoint_in, endpoint_out = open_endpoints(device)
        request = request_for(args)
        response = exchange(endpoint_in, endpoint_out, request)
        validate_response(request, response, expected_signer=expected_signer)
        print(json.dumps(response, indent=2))
        if response.get("status") in {"rejected", "error"}:
            return 2
        if args.command == "pair":
            address = response["address"]
            print(
                f"\nSigner address reported over USB: {address}\n"
                f"Fingerprint: {address_fingerprint(address)}\n"
                "Compare it with the SIGNING ADDRESS shown on the phone itself (the phone's "
                "display is the trusted side; USB is not).",
                file=sys.stderr,
            )
            answer = input("Does the phone show exactly this address? [yes/NO] ").strip().lower()
            if answer != "yes":
                print("phone-vault: not paired (address not confirmed on the phone)", file=sys.stderr)
                return 3
            save_paired_signer(args.pairing_file, address)
            print(f"phone-vault: paired signer pinned in {args.pairing_file}", file=sys.stderr)
    except Exception as exception:
        print(f"phone-vault: {exception}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
