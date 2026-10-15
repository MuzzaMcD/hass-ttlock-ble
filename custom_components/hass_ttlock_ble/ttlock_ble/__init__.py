"""ttlock_ble: Python SDK for DLock-XP / TTLock smart locks over Bluetooth.

Public API:
    TTLockClient      — async BLE client for an already-paired lock
    TTLockCloud       — async HTTP client for the TTLock cloud (key bootstrap)
    VirtualKey        — per-(user, lock) credential bundle
    LockVersion       — firmware identifiers used in the V3 frame header
    SiteInfo          — regional API endpoints (siteId, country, base URL)
    LockAdvertisement — bolt state + battery decoded from a BLE advertisement
    LockEvent      — push notification surfaced by the BLE client
    LogEntry       — one row from the lock's on-device operation log
    DeviceInfo     — standard BLE Device Information Service (0x180A) fields
    AutoLockLimits — the lock's own min/max allowed auto-lock delay
    LockSound      — beep on/off and volume as read back from the lock
    DeviceFeatures — the capability bits the lock itself reports (see LockFeature)
    DeviceProperties — confirmed TTLock-proprietary device properties
    FingerprintEntry — one enrolled fingerprint
    PasscodeEntry  — one keypad passcode
    CyclicSchedule — the day-of-week/time-window rule behind a CIRCLE passcode
    TTLockError    — raised by `TTLockClient` on BLE / protocol failure
    CloudError     — raised by `TTLockCloud` on a non-success HTTP response
    PairedLock     — credentials from a cloud-free `init_lock()` pairing run
    discover_pairing_lock — scan for a lock broadcasting pairing mode
    init_lock      — run the factory pairing handshake, no cloud involved

IntEnums:
    AutoLockOperate, KeyboardPwdType, LockFeature, LockState, LockVolume, LogOperate,
    PwdOperateType
"""

from __future__ import annotations

from .client import TTLockClient
from .cloud import TTLockCloud
from .constants import (
    AutoLockOperate,
    KeyboardPwdType,
    LockFeature,
    LockState,
    LockVolume,
    LogOperate,
    PwdOperateType,
)
from .exceptions import CloudError, TTLockError
from .models import (
    AutoLockLimits,
    CyclicSchedule,
    DeviceFeatures,
    DeviceInfo,
    DeviceProperties,
    FingerprintEntry,
    LockAdvertisement,
    LockEvent,
    LockSound,
    LockVersion,
    LogEntry,
    PasscodeEntry,
    SiteInfo,
    VirtualKey,
)
from .pairing import PairedLock, discover_pairing_lock, init_lock

__all__ = [
    "AutoLockLimits",
    "AutoLockOperate",
    "CloudError",
    "CyclicSchedule",
    "DeviceFeatures",
    "DeviceInfo",
    "DeviceProperties",
    "FingerprintEntry",
    "KeyboardPwdType",
    "LockAdvertisement",
    "LockEvent",
    "LockFeature",
    "LockSound",
    "LockState",
    "LockVersion",
    "LockVolume",
    "LogEntry",
    "LogOperate",
    "PairedLock",
    "PasscodeEntry",
    "PwdOperateType",
    "SiteInfo",
    "TTLockClient",
    "TTLockCloud",
    "TTLockError",
    "VirtualKey",
    "discover_pairing_lock",
    "init_lock",
]
