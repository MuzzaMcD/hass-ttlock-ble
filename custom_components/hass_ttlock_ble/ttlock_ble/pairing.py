"""Cloud-free factory pairing: turn a freshly-reset lock into usable credentials.

This is the local-only equivalent of `examples/init.js` in
kind3r/ttlock-sdk-js. It never talks to the TTLock cloud — everything
comes from the lock itself over BLE, so it works entirely offline and the
resulting `PairedLock` is not tied to any TTLock account.

Run once per lock, right after a factory reset:

    from ttlock_ble import discover_pairing_lock, init_lock

    found = await discover_pairing_lock(scan_timeout=20)
    if found is None:
        raise SystemExit("no lock in pairing mode found")
    device, advertisement = found
    paired = await init_lock(device, advertisement)
    paired.save(Path("lockData.json"))

`PairedLock.to_virtual_key()` converts the result into a `VirtualKey` so
it plugs directly into the existing `TTLockClient` — no cloud sync
needed. The CLI wraps this as `ttlock init`, which does exactly the
above and appends the result to the same key store `ttlock unlock` /
`ttlock lock` / `ttlock state` already read from.

Only run this against a lock you intend to take ownership of: `init_lock`
overwrites whatever admin/AES credentials the lock currently holds. A
lock that has already been paired (by this SDK, the official app, or
anything else) will not be in pairing mode and `discover_pairing_lock`
will not find it — factory-reset it first (physical reset button on the
lock body) and wake it by touching the keypad.
"""

from __future__ import annotations

import dataclasses
import datetime as dt
import json
import logging
from typing import TYPE_CHECKING

from . import commands as cmd
from .ble import BleTransport, find_pairing_lock_device
from .crypto import DEFAULT_AES_KEY, aes_decrypt
from .exceptions import TTLockError
from .models import LockVersion, VirtualKey
from .protocol import ENCRYPT_PLAIN, Frame

if TYPE_CHECKING:
    from pathlib import Path

    from bleak.backends.device import BLEDevice

    from .models import LockAdvertisement

log: logging.Logger = logging.getLogger("ttlock_ble.client")

_DEFAULT_SCAN_TIMEOUT = 20.0
_DEFAULT_ADMIN_PASSCODE_LEN = 6

# FeatureValue bit positions this module cares about (from the vendor
# SDK's `FeatureValue` enum — the full list is much longer; init_lock()
# only needs to know whether to bother reading/setting an admin passcode).
_FEATURE_GET_ADMIN_CODE = 26


LEGACY_V2_PROTOCOL_TYPE = 3


def _group_org_for(protocol_type: int) -> tuple[int, int]:
    """groupId/orgId for a lock family, mirroring `LockVersion.getLockVersion`.

    These are NOT carried in the BLE advertisement (`LockAdvertisement`
    only decodes protocol_type/protocol_version/scene). The vendor SDK
    hardcodes them per lock family instead; every current V3-and-later
    family uses (1, 1), legacy V2 (protocol_type == 3) uses (0, 0).
    """
    if protocol_type == LEGACY_V2_PROTOCOL_TYPE:
        return (0, 0)
    return (1, 1)


@dataclasses.dataclass(slots=True)
class PairedLock:
    """Everything obtained from a fresh `init_lock()` run.

    Field names deliberately echo `lockData.json` from
    kind3r/ttlock-sdk-js (`mac`, `aesKey`, `adminPs`/`adminPassword`,
    `unlockKey`) so the two are easy to cross-reference, with
    `lock_version` added since this SDK (unlike the JS one) needs the
    protocol header explicitly rather than re-deriving it from a live
    BLE connection every time.
    """

    lock_mac: str
    aes_key: bytes
    admin_ps: int
    unlock_key: int
    lock_version: LockVersion
    admin_passcode: str = ""
    lock_alias: str = ""
    battery: int | None = None

    def to_virtual_key(self, *, lock_id: int = 0, key_id: int = 0) -> VirtualKey:
        """Build a `VirtualKey` so this plugs straight into `TTLockClient`.

        `lock_id`/`key_id` only matter if you keep multiple entries in
        the same cloud-shaped key store and want stable identifiers;
        BLE operations themselves never look at them.
        """
        return VirtualKey(
            keyId=key_id,
            lockId=lock_id,
            lockMac=self.lock_mac,
            lockAlias=self.lock_alias or self.lock_mac,
            lockName=self.lock_alias or self.lock_mac,
            lockVersion=self.lock_version,
            aesKeyStr=self.aes_key.hex(),
            unlockKey=str(self.unlock_key),
            lockFlagPos=0,
            timezoneRawOffSet=0,
            adminPs=str(self.admin_ps),
        )

    def to_dict(self) -> dict[str, object]:
        """Serialise to plain JSON-able types (the `lockData.json`-style shape)."""
        return {
            "mac": self.lock_mac,
            "aesKey": self.aes_key.hex(),
            "adminPs": self.admin_ps,
            "unlockKey": self.unlock_key,
            "adminPasscode": self.admin_passcode,
            "lockAlias": self.lock_alias,
            "battery": self.battery,
            "lockVersion": dataclasses.asdict(self.lock_version),
            "pairedAt": dt.datetime.now(dt.UTC).isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> PairedLock:
        """Reverse of `to_dict()`."""
        lock_version_raw = data["lockVersion"]
        if not isinstance(lock_version_raw, dict):
            raise TypeError(f"Expected 'lockVersion' to be a dict, got {type(lock_version_raw)!r}")
        return cls(
            lock_mac=str(data["mac"]),
            aes_key=bytes.fromhex(str(data["aesKey"])),
            admin_ps=int(str(data["adminPs"])),
            unlock_key=int(str(data["unlockKey"])),
            lock_version=LockVersion(
                protocolType=int(str(lock_version_raw["protocolType"])),
                protocolVersion=int(str(lock_version_raw["protocolVersion"])),
                scene=int(str(lock_version_raw["scene"])),
                groupId=int(str(lock_version_raw["groupId"])),
                orgId=int(str(lock_version_raw["orgId"])),
            ),
            admin_passcode=str(data.get("adminPasscode", "")),
            lock_alias=str(data.get("lockAlias", "")),
            battery=data.get("battery"),  # type: ignore[arg-type]
        )

    def save(self, path: Path) -> None:
        """Write this lock's credentials to `path` as pretty-printed JSON."""
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), indent=2))

    @classmethod
    def load(cls, path: Path) -> PairedLock:
        """Load a single-lock file written by `save()`."""
        return cls.from_dict(json.loads(path.read_text()))


async def discover_pairing_lock(
    scan_timeout: float = _DEFAULT_SCAN_TIMEOUT,
) -> tuple[BLEDevice, LockAdvertisement] | None:
    """Scan for a nearby lock broadcasting pairing mode.

    Factory-reset the lock and touch its keypad to wake it *before*
    calling this — pairing mode only lasts 10-15s per touch. Returns
    `None` on timeout rather than raising, since "nothing found yet" is
    the expected outcome of a plain scan and callers may want to retry.
    """
    return await find_pairing_lock_device(scan_timeout)


class _PairingSession:
    """Bundles the transport plus the build/decrypt helpers `init_lock` needs.

    Exists purely to shrink `init_lock`'s statement count into
    separate, independently readable steps — no state here outlives a
    single `init_lock()` call.

    Response matching during pairing can't rely on the frame-header
    command byte the way `TTLockClient._answers` does for authenticated
    commands: that method's own docstring notes every *authenticated*
    reply carries `CMD_RESPONSE` (0x54) in the header regardless of what
    it's answering, with the real echo living in the decrypted payload.
    Pairing-mode replies don't follow that convention consistently —
    observed against real hardware, the CMD_INITIALIZATION ack uses
    0x54 in the header, but the CMD_GET_AES_KEY reply echoes the
    request opcode (0x19) directly in the header instead. `_is_response`
    therefore accepts either header convention, and additionally
    verifies via the decrypted plaintext echo byte whenever a key is
    available — matching `_answers`'s more robust approach rather than
    trusting the header alone.
    """

    def __init__(
        self,
        *,
        address: str,
        display_name: str,
        device: BLEDevice,
        lock_version: LockVersion,
    ) -> None:
        self.lock_version = lock_version
        self._current_key: bytes | None = None
        self.transport = BleTransport(
            address=address,
            display_name=display_name,
            on_push_frame=self._on_unmatched_frame,
            is_response=self._is_response,
            device=device,
        )

    @staticmethod
    def _on_unmatched_frame(frame: Frame) -> None:
        log.debug(
            "Unmatched frame during pairing: cmd=0x%02x len=%d", frame.command, len(frame.data)
        )

    def _is_response(self, candidate: Frame, expected: int) -> bool:
        if candidate.command not in (cmd.CMD_RESPONSE, expected):
            return False
        if not candidate.data or self._current_key is None:
            # Nothing to decrypt (e.g. the empty-payload INIT ack) —
            # the header match above is all we can check.
            return True
        try:
            plain = aes_decrypt(candidate.data, self._current_key)
        except ValueError:
            return False
        return bool(plain) and plain[0] == expected

    def build(self, command: int, payload: bytes, key: bytes | None) -> Frame:
        frame = Frame.for_lock(self.lock_version, command, payload)
        if not payload:
            # Zero-length payloads travel unencrypted on the wire (mirrors
            # AESUtil.aesEncrypt's early-return in ttlock-sdk-js) — running
            # them through Frame.encrypt_data() would PKCS7-pad an empty
            # buffer into a spurious 16-byte block the lock doesn't expect.
            return dataclasses.replace(frame, encrypt=ENCRYPT_PLAIN)
        if key is None:
            raise ValueError(f"Command 0x{command:02x} has a non-empty payload but no key")
        return frame.encrypt_data(key)

    @staticmethod
    def decrypt(frame: Frame, key: bytes, label: str) -> bytes:
        try:
            return aes_decrypt(frame.data, key)
        except ValueError as error:
            raise TTLockError(f"Failed to decrypt {label} response: {error}") from error

    async def exchange(self, command: int, payload: bytes, key: bytes | None, label: str) -> bytes:
        """Send one command and return its decrypted response payload.

        `key=None` is only valid for the empty-payload `CMD_INITIALIZATION`
        ping, whose reply is never decrypted or inspected.
        """
        self._current_key = key
        resp = await self.transport.exchange(self.build(command, payload, key))
        if key is None:
            return b""
        return self.decrypt(resp, key, label)


async def _ensure_admin_passcode(session: _PairingSession, aes_key: bytes, features: int) -> str:
    """Read the lock's admin keypad passcode, generating and setting one if it has none."""
    if not (features >> _FEATURE_GET_ADMIN_CODE) & 1:
        return ""
    log.info("Pairing: reading admin passcode")
    plain = await session.exchange(
        cmd.CMD_GET_ADMIN_CODE, cmd.payload_get_admin_code(), aes_key, "get_admin_code"
    )
    admin_passcode = cmd.parse_admin_code_response(plain)
    if admin_passcode:
        return admin_passcode

    admin_passcode = str(cmd.generate_credential())[:_DEFAULT_ADMIN_PASSCODE_LEN]
    log.info("Pairing: setting admin passcode")
    plain = await session.exchange(
        cmd.CMD_SET_ADMIN_KEYBOARD_PWD,
        cmd.payload_set_admin_keyboard_pwd(admin_passcode),
        aes_key,
        "set_admin_keyboard_pwd",
    )
    _require_success(plain, "set_admin_keyboard_pwd")
    return admin_passcode


async def init_lock(
    device: BLEDevice,
    advertisement: LockAdvertisement,
    *,
    lock_alias: str = "",
    set_admin_passcode: bool = True,
) -> PairedLock:
    """Run the factory pairing handshake and return the new credentials.

    `device`/`advertisement` should come from `discover_pairing_lock()`.
    Connects, generates a fresh AES key and admin credentials *on the
    lock*, then disconnects. Nothing here touches the TTLock cloud.

    Raises `TTLockError` if the lock isn't reachable, isn't actually in
    pairing mode by the time we connect (someone else paired it first,
    or the 10-15s window closed), or rejects any step of the sequence.
    """
    protocol_type, protocol_version = advertisement.protocol_type, advertisement.protocol_version
    group_id, org_id = _group_org_for(protocol_type)
    lock_version = LockVersion(
        protocolType=protocol_type,
        protocolVersion=protocol_version,
        scene=advertisement.scene,
        groupId=group_id,
        orgId=org_id,
    )

    session = _PairingSession(
        address=advertisement.lock_mac,
        display_name=lock_alias or advertisement.lock_mac,
        device=device,
        lock_version=lock_version,
    )

    await session.transport.connect()
    try:
        log.info("Pairing: sending init ping")
        await session.exchange(cmd.CMD_INITIALIZATION, b"", None, "init")

        log.info("Pairing: requesting AES key")
        plain = await session.exchange(
            cmd.CMD_GET_AES_KEY, cmd.payload_get_aes_key_pairing(), DEFAULT_AES_KEY, "get_aes_key"
        )
        aes_key = cmd.parse_aes_key_response(plain)
        log.info("Pairing: got AES key")

        admin_ps = cmd.generate_credential()
        unlock_key = cmd.generate_credential()
        log.info("Pairing: adding admin (adminPs=%d, unlockKey=%d)", admin_ps, unlock_key)
        plain = await session.exchange(
            cmd.CMD_ADD_ADMIN, cmd.payload_add_admin(admin_ps, unlock_key), aes_key, "add_admin"
        )
        _require_success(plain, "add_admin")

        log.info("Pairing: calibrating time")
        try:
            plain = await session.exchange(
                cmd.CMD_TIME_CALIBRATE,
                cmd.payload_time_calibrate(dt.datetime.now()),  # noqa: DTZ005 -- local, matches the lock's naive RTC
                aes_key,
                "calibrate_time",
            )
            _require_success(plain, "calibrate_time")
        except TTLockError:
            # Known to fail on some firmware revisions even in the JS SDK;
            # non-fatal, the lock's RTC can be corrected later.
            log.warning("Time calibration failed during pairing; continuing", exc_info=True)

        log.info("Pairing: reading device features")
        plain = await session.exchange(
            cmd.CMD_SEARCH_DEVICE_FEATURE,
            cmd.payload_search_device_feature(),
            aes_key,
            "search_device_feature",
        )
        battery, features = cmd.parse_device_features_response(plain)

        admin_passcode = ""
        if set_admin_passcode:
            admin_passcode = await _ensure_admin_passcode(session, aes_key, features)

        log.info("Pairing: finishing up")
        await session.exchange(
            cmd.CMD_OPERATE_FINISHED, cmd.payload_operate_finished(), aes_key, "operate_finished"
        )
    finally:
        await session.transport.disconnect()

    return PairedLock(
        lock_mac=advertisement.lock_mac,
        aes_key=aes_key,
        admin_ps=admin_ps,
        unlock_key=unlock_key,
        lock_version=lock_version,
        admin_passcode=admin_passcode,
        lock_alias=lock_alias,
        battery=battery,
    )


def _require_success(plain: bytes, label: str) -> None:
    echo, status, data = cmd.parse_response_status(plain)
    log.info("%s response: cmd_echo=0x%02x status=%d data=%s", label, echo, status, data.hex())
    if status != cmd.RESPONSE_SUCCESS:
        raise TTLockError(
            f"Failed to {label}: lock rejected with status={status:#x}, data={data.hex()}"
        )


__all__ = ["PairedLock", "discover_pairing_lock", "init_lock"]
