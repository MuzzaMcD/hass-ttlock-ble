"""Active BLE scan that resolves a lock's MAC to a `BLEDevice`."""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

from bleak import BleakScanner

from ..models import LockAdvertisement

if TYPE_CHECKING:
    from bleak.backends.device import BLEDevice
    from bleak.backends.scanner import AdvertisementData

# The BLE layer keeps logging under `ttlock_ble.client`: the logger name is
# what downstream users scope log levels with, and splitting the module out
# must not silently move their filters.
log: logging.Logger = logging.getLogger("ttlock_ble.client")

_SCAN_POLL_INTERVAL = 0.5


async def find_lock_device(mac: str, scan_timeout: float) -> BLEDevice | None:
    """Locate the lock in a way that works on macOS (which hides MACs).

    Match priority:
      1. exact MAC (works on Linux/Windows), then
      2. the last 3 octets of the MAC appearing as a hex suffix in the
         device's advertised name (`S534_1d22bd` for `…22:1D`).

    Falls back to `None` rather than connecting to a neighbour's lock.
    """
    target = mac.upper()
    suffix_bytes = bytes.fromhex(target.replace(":", ""))[-3:][::-1].hex()
    log.info("Scanning %.0fs for %s (MAC suffix '%s')…", scan_timeout, target, suffix_bytes)
    match: list[BLEDevice] = []
    loop = asyncio.get_running_loop()
    deadline = loop.time() + scan_timeout

    # bleak types AdvertisementData.platform_data as tuple[Any, ...], so the
    # callback signature carries an Any this side cannot annotate away.
    def _on_detection(  # type: ignore[explicit-any]
        dev: BLEDevice,
        adv: AdvertisementData,
    ) -> None:
        name = dev.name or adv.local_name or ""
        mac_match = dev.address.upper() == target or suffix_bytes in name.lower()
        if mac_match and not match:
            log.info("Lock found: %s rssi=%d", name or dev.address, adv.rssi)
            match.append(dev)

    async with BleakScanner(detection_callback=_on_detection):
        # Polling-with-sleep on purpose: we want to break as soon as
        # `_on_detection` fires, but bleak's scanner doesn't expose an
        # asyncio.Event for that — the callback runs synchronously.
        while not match and loop.time() < deadline:  # noqa: ASYNC110
            await asyncio.sleep(_SCAN_POLL_INTERVAL)
    return match[0] if match else None


async def find_pairing_lock_device(
    scan_timeout: float,
) -> tuple[BLEDevice, LockAdvertisement] | None:
    """Find a nearby lock that is broadcasting "setting mode" (pairing mode).

    Unlike `find_lock_device`, this doesn't take a target MAC — pairing
    is the one operation that runs *before* you know the lock's
    identity. The lock only sets the setting-mode flag for 10-15s after
    a factory reset once its keypad is touched, so scan promptly after
    waking it.

    Returns the first matching `(BLEDevice, LockAdvertisement)`, or
    `None` if nothing in pairing mode was seen before `scan_timeout`.
    If multiple locks are in pairing mode simultaneously this returns
    whichever advertises first — do one lock at a time.
    """
    log.info("Scanning %.0fs for a lock in pairing mode…", scan_timeout)
    match: list[tuple[BLEDevice, LockAdvertisement]] = []
    loop = asyncio.get_running_loop()
    deadline = loop.time() + scan_timeout

    def _on_detection(  # type: ignore[explicit-any]
        dev: BLEDevice,
        adv: AdvertisementData,
    ) -> None:
        if match:
            return
        for company_id, payload in adv.manufacturer_data.items():
            state = LockAdvertisement.from_manufacturer_data(company_id, payload)
            if state is not None and state.is_setting_mode:
                log.info(
                    "Pairing-mode lock found: %s mac=%s rssi=%d",
                    dev.name or dev.address,
                    state.lock_mac,
                    adv.rssi,
                )
                match.append((dev, state))
                return

    async with BleakScanner(detection_callback=_on_detection):
        while not match and loop.time() < deadline:  # noqa: ASYNC110
            await asyncio.sleep(_SCAN_POLL_INTERVAL)
    return match[0] if match else None
