"""Payloads and parsers for the one-time factory-reset pairing handshake.

This is a *different* handshake from `session.py`'s CHECK_USER_TIME /
CHECK_ADMIN flow. Those authenticate an already-paired lock using a key
issued by the cloud. The commands here run once, against a lock in
pairing mode (freshly factory-reset, woken by a keypad touch), to make
the lock generate a brand-new AES key and admin credentials that have
never been seen by the TTLock cloud at all.

Sequence (mirrors `TTLockApi.initLock` in kind3r/ttlock-sdk-js, itself a
port of `com.ttlock.bl.sdk.did.TTLockClient` in the vendor Android SDK):

    1. CMD_INITIALIZATION  -- empty, unencrypted "are you awake" ping
    2. CMD_GET_AES_KEY     -- vendor token, encrypted under the shared
                              DEFAULT_AES_KEY; the lock replies with a
                              fresh random 16-byte key, also encrypted
                              under DEFAULT_AES_KEY
    3. CMD_ADD_ADMIN       -- random adminPs/unlockKey, encrypted under
                              the new key from step 2 (all commands from
                              here on use it)
    4. CMD_SEARCH_DEVICE_FEATURE, CMD_TIME_CALIBRATE, CMD_GET_ADMIN_CODE /
       CMD_SET_ADMIN_KEYBOARD_PWD, CMD_OPERATE_FINISHED -- as needed

The vendor token in step 2 is the ASCII literal `"SCIENER"`. Note this
package already has an unrelated, currently-unused `payload_get_aes_key()`
in `session.py` with a *different* token (`VENDOR` there is a 32-char hex
string) -- that stub was never wired into `TTLockClient` and is not the
value used here. `"SCIENER"` is what kind3r/ttlock-sdk-js sends and what
this module has actually been exercised against; if pairing fails on a
particular firmware revision, that mismatch is the first thing to check.
"""

from __future__ import annotations

import secrets

from .envelope import RESPONSE_SUCCESS, parse_response_status

VENDOR_TOKEN = b"SCIENER"

_FEATURE_HEADER_LEN = 5  # [battery(1)][features u32 BE(4)]


def payload_get_aes_key() -> bytes:
    """CMD_GET_AES_KEY request body -- the vendor handshake token.

    Encrypt this under `crypto.DEFAULT_AES_KEY`, not the lock's real key
    (which doesn't exist yet).
    """
    return VENDOR_TOKEN


def parse_aes_key_response(plaintext: bytes) -> bytes:
    """Extract the lock-generated 16-byte AES key from a CMD_GET_AES_KEY reply.

    Wire layout: `[cmd_echo=0x19][status][aesKey 16 bytes]`. Decrypt the
    raw frame data under `crypto.DEFAULT_AES_KEY` before calling this.
    """
    _cmd_echo, status, data = parse_response_status(plaintext)
    if status != RESPONSE_SUCCESS:
        raise RuntimeError(f"getAESKey FAILED: status={status:#x} err={data.hex()}")
    if len(data) < 16:
        raise ValueError(f"getAESKey payload too short: {plaintext.hex()}")
    return data[:16]


def generate_credential() -> int:
    """Generate a random 8-digit-ish positive int, matching `AddAdminCommand.generateNumber()`."""
    return secrets.randbelow(100_000_000)


def payload_add_admin(admin_ps: int, unlock_key: int) -> bytes:
    """CMD_ADD_ADMIN request body -- registers this app as the lock's admin.

    Wire layout (15 bytes): `[adminPs u32 BE][unlockKey u32 BE]["SCIENER"]`.
    Both values should come from `generate_credential()`; encrypt the
    frame under the key returned by `parse_aes_key_response`.
    """
    out = bytearray(8)
    out[0:4] = int(admin_ps).to_bytes(4, "big")
    out[4:8] = int(unlock_key).to_bytes(4, "big")
    return bytes(out) + VENDOR_TOKEN


def payload_search_device_feature() -> bytes:
    """CMD_SEARCH_DEVICE_FEATURE request body -- empty."""
    return b""


def parse_device_features_response(plaintext: bytes) -> tuple[int, int]:
    """Decode `(battery_percent, feature_bitmask)` from the response.

    Wire layout: `[cmd_echo][status][battery(1)][features u32 BE(4)][...]`.
    `feature_bitmask` bit N set means `FeatureValue` N is supported
    (mirrors `DeviceFeaturesCommand.processFeatures` in ttlock-sdk-js);
    this module doesn't enumerate the individual `FeatureValue` bits
    since `init_lock()` only needs a couple of them (see `pairing.py`).
    """
    _cmd_echo, status, data = parse_response_status(plaintext)
    if status != RESPONSE_SUCCESS:
        raise RuntimeError(f"searchDeviceFeature FAILED: status={status:#x} err={data.hex()}")
    if len(data) < _FEATURE_HEADER_LEN:
        raise ValueError(f"searchDeviceFeature payload too short: {plaintext.hex()}")
    battery = data[0]
    features = int.from_bytes(data[1:5], "big")
    return battery, features


def payload_get_admin_code() -> bytes:
    """CMD_GET_ADMIN_CODE request body -- empty."""
    return b""


def parse_admin_code_response(plaintext: bytes) -> str:
    """Decode the admin keypad passcode from a CMD_GET_ADMIN_CODE reply.

    Wire layout: `[cmd_echo][status][len(1)][passcode digits][???(2)]`.
    Ported as-is from `GetAdminCodeCommand.processData()` in
    ttlock-sdk-js, including its own belt-and-braces length check --
    that upstream code logs a warning rather than raising when `len`
    doesn't match the remaining buffer, which suggests the exact
    trailing-byte layout was never fully pinned down against every
    firmware revision. Returns `""` when the lock hasn't set one yet
    (call `payload_set_admin_keyboard_pwd` in that case).
    """
    _cmd_echo, status, data = parse_response_status(plaintext)
    if status != RESPONSE_SUCCESS:
        raise RuntimeError(f"getAdminCode FAILED: status={status:#x} err={data.hex()}")
    if len(data) < 2:
        return ""
    declared_len = data[1]
    if declared_len == 0:
        return ""
    return data[2 : len(data) - 2].decode("ascii", errors="replace")


def payload_set_admin_keyboard_pwd(admin_passcode: str) -> bytes:
    """CMD_SET_ADMIN_KEYBOARD_PWD request body.

    Each output byte is the *digit value* (0-9), not its ASCII code --
    e.g. passcode "482" encodes as `bytes([4, 8, 2])`. Mirrors
    `SetAdminKeyboardPwdCommand.build()`. Pass a lock-generated or
    caller-chosen numeric string; leave the digit count up to the lock's
    own keypad-length requirement (typically 6-9 digits).
    """
    if not admin_passcode.isdigit():
        raise ValueError(f"admin passcode must be all digits, got {admin_passcode!r}")
    return bytes(int(ch) for ch in admin_passcode)


def payload_operate_finished() -> bytes:
    """CMD_OPERATE_FINISHED request body -- empty. Closes out the pairing sequence."""
    return b""
