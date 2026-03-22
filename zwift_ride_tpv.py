#!/usr/bin/env python3
"""
Zwift → TrainingPeaks Virtual Bridge (Universal)
=================================================
Connects to Zwift Play, Zwift Ride, or Zwift Click controllers via BLE
and sends keyboard shortcuts to TrainingPeaks Virtual.

Supports:
  • Zwift Ride  — plaintext protobuf (no encryption)
  • Zwift Play  — ECDH + AES-CCM encrypted protobuf
  • Zwift Click  — same encryption as Play

No middleman apps. No QZ, no BikeControl. Free.

Protocol based on Makinolo's reverse engineering:
  Play: https://www.makinolo.com/blog/2023/10/08/connecting-to-zwift-play-controllers/
  Ride: https://www.makinolo.com/blog/2024/07/26/zwift-ride-protocol/

Author: Seb Denes / Warriors Racing
License: MIT
"""

import asyncio
import json
import os
import signal
import struct
import sys
import time
import platform
from dataclasses import dataclass, field
from enum import IntEnum, IntFlag
from pathlib import Path
from typing import Optional

from bleak import BleakClient, BleakScanner
from bleak.backends.device import BLEDevice

# Encryption imports
from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDH, EllipticCurvePrivateKey, EllipticCurvePublicKey,
    SECP256R1, generate_private_key,
)
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat,
)
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.backends import default_backend

APP_NAME = "Zwift → TPV Bridge"
APP_VERSION = "2.0.0"

# ─────────────────────────────────────────────────────────────────
# BLE Protocol Constants
# ─────────────────────────────────────────────────────────────────

ZWIFT_SERVICE_UUID_LEGACY = "00000001-19ca-4651-86e5-fa29dcdd09d1"
ZWIFT_SERVICE_UUID_NEW    = "0000fc82-0000-1000-8000-00805f9b34fb"

# Characteristics (same UUIDs across Play/Ride/Click, different roles)
# For Ride:  002=Write(handshake), 003=Indicate(response), 004=Notify(buttons)
# For Play:  002=Async/Notify(buttons), 003=SyncTX/Indicate(responses), 004=SyncRX/Write(commands)
# NOTE: Play swaps write/notify vs Ride!
CHAR_UUID_002 = "00000002-19ca-4651-86e5-fa29dcdd09d1"
CHAR_UUID_003 = "00000003-19ca-4651-86e5-fa29dcdd09d1"
CHAR_UUID_004 = "00000004-19ca-4651-86e5-fa29dcdd09d1"

RIDEON_HANDSHAKE = b"RideOn"
ZWIFT_MANUFACTURER_ID = 0x094A

# Message IDs
MSG_ID_RIDE_KEYPAD = 0x23
MSG_ID_PLAY_KEYPAD = 0x07
MSG_ID_IDLE = 0x15


class DeviceType(IntEnum):
    PLAY_RIGHT = 2
    PLAY_LEFT  = 3
    RIDE_RIGHT = 7
    RIDE_LEFT  = 8
    CLICK      = 9


# ─────────────────────────────────────────────────────────────────
# Zwift Play Encryption (ECDH + HKDF + AES-CCM)
# ─────────────────────────────────────────────────────────────────

class ZwiftPlayCrypto:
    """
    Handles the Zwift Play encrypted BLE protocol.

    Handshake:
      1. Generate ECDH key pair (secp256r1 / P-256)
      2. Send "RideOn" + 0x01 0x02 + our_public_key (64 bytes) to SyncRX
      3. Receive "RideOn" + 0x00 0x09 + device_public_key from SyncTX
      4. Derive shared secret via ECDH
      5. Derive 36-byte key via HKDF-SHA256
         salt = device_pubkey_raw + our_pubkey_raw
      6. key[0:32] = AES key, key[32:36] = nonce prefix

    Messages:
      [counter(4 LE)] [encrypted_payload] [MIC/TAG(4)]
      Nonce = nonce_prefix(4) + counter(4) = 8 bytes
    """

    def __init__(self):
        self._private_key: Optional[EllipticCurvePrivateKey] = None
        self._aes_key: Optional[bytes] = None
        self._nonce_prefix: Optional[bytes] = None
        self._recv_counter = -1
        self._send_counter = 0
        self.ready = False

    def generate_handshake(self) -> bytes:
        """Generate ECDH key pair and return the handshake payload to send."""
        self._private_key = generate_private_key(SECP256R1(), default_backend())
        pub_raw = self._get_raw_pubkey(self._private_key.public_key())
        # "RideOn" + 0x01 0x02 + 64-byte public key
        return RIDEON_HANDSHAKE + bytes([0x01, 0x02]) + pub_raw

    def process_handshake_response(self, data: bytes) -> bool:
        """
        Process the device's handshake response and derive the shared key.
        Returns True if successful.
        """
        # Expect: "RideOn" + 2 bytes + 64-byte device public key
        if len(data) < 72 or data[:6] != RIDEON_HANDSHAKE:
            return False

        device_pub_raw = data[8:]  # Skip "RideOn" + 2 flag bytes
        if len(device_pub_raw) < 64:
            return False
        device_pub_raw = device_pub_raw[:64]

        try:
            # Reconstruct device public key (add 0x04 uncompressed prefix)
            from cryptography.hazmat.primitives.asymmetric.ec import (
                EllipticCurvePublicNumbers,
            )
            x = int.from_bytes(device_pub_raw[:32], "big")
            y = int.from_bytes(device_pub_raw[32:64], "big")
            device_pub = EllipticCurvePublicNumbers(x, y, SECP256R1()).public_key(
                default_backend()
            )

            # ECDH shared secret
            shared_secret = self._private_key.exchange(ECDH(), device_pub)

            # Our raw public key
            our_pub_raw = self._get_raw_pubkey(self._private_key.public_key())

            # HKDF: salt = device_pubkey + our_pubkey
            salt = device_pub_raw + our_pub_raw
            hkdf = HKDF(
                algorithm=SHA256(),
                length=36,
                salt=salt,
                info=None,
                backend=default_backend(),
            )
            derived = hkdf.derive(shared_secret)

            self._aes_key = derived[:32]
            self._nonce_prefix = derived[32:36]
            self.ready = True
            return True

        except Exception as e:
            print(f"      ❌ Key derivation failed: {e}")
            return False

    def decrypt(self, raw: bytes) -> Optional[bytes]:
        """
        Decrypt an incoming encrypted message.
        Format: [counter(4 LE)] [encrypted_payload] [MIC(4)]
        Nonce: nonce_prefix(4) + counter(4) = 8 bytes
        """
        if not self.ready or len(raw) < 9:  # 4 counter + 1 min payload + 4 MIC
            return None

        counter = raw[:4]
        ciphertext_and_tag = raw[4:]  # AES-CCM expects ciphertext+tag together

        nonce = self._nonce_prefix + counter  # 8 bytes

        try:
            aesccm = AESCCM(self._aes_key, tag_length=4)
            plaintext = aesccm.decrypt(nonce, ciphertext_and_tag, None)
            return plaintext
        except Exception:
            return None

    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt an outgoing message."""
        counter = struct.pack("<I", self._send_counter)
        nonce = self._nonce_prefix + counter
        aesccm = AESCCM(self._aes_key, tag_length=4)
        ciphertext_and_tag = aesccm.encrypt(nonce, plaintext, None)
        self._send_counter += 1
        return counter + ciphertext_and_tag

    @staticmethod
    def _get_raw_pubkey(pub: EllipticCurvePublicKey) -> bytes:
        """Get 64-byte raw public key (x || y, no 0x04 prefix)."""
        uncompressed = pub.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
        return uncompressed[1:]  # Strip the 0x04 prefix


# ─────────────────────────────────────────────────────────────────
# Protobuf Decoders
# ─────────────────────────────────────────────────────────────────

def _varint(data, off):
    r, s = 0, 0
    while off < len(data):
        b = data[off]; off += 1
        r |= (b & 0x7F) << s
        if not (b & 0x80): break
        s += 7
    return r, off


def _zigzag(v):
    """Decode protobuf zigzag encoding."""
    return (v >> 1) ^ -(v & 1)


def decode_ride_bitmap(data: bytes) -> Optional[int]:
    """Decode Ride 0x23 bitmap message → button bitmap."""
    if len(data) < 2 or data[0] != MSG_ID_RIDE_KEYPAD:
        return None
    if data[1] == 0x08:
        v, _ = _varint(data, 2)
        return v
    return None


def decode_play_buttons(data: bytes) -> Optional[dict]:
    """
    Decode Play 0x07 button message → dict of button states.

    Format: 0x07 then pairs of (tag, varint_value)
    Tags map to:
      field 1 (0x08) = side (0=right, 1=left)
      field 2 (0x10) = Y/^       field 3 (0x18) = Z/<
      field 4 (0x20) = A/>       field 5 (0x28) = B/v
      field 6 (0x30) = ON/OFF    field 7 (0x38) = Shifter
      field 8 (0x40) = Analog LR  field 9 (0x48) = Analog brake

    Values: 0 = pressed, 1 = not pressed (normal buttons)
            analog values are zigzag-encoded signed ints
    """
    if len(data) < 2 or data[0] != MSG_ID_PLAY_KEYPAD:
        return None

    result = {}
    off = 1
    while off < len(data):
        tag = data[off]
        off += 1
        field_num = tag >> 3
        val, off = _varint(data, off)

        if field_num == 1:
            result["side"] = val  # 0=right, 1=left
        elif field_num == 2:
            result["Y"] = val == 0
        elif field_num == 3:
            result["Z"] = val == 0
        elif field_num == 4:
            result["A"] = val == 0
        elif field_num == 5:
            result["B"] = val == 0
        elif field_num == 6:
            result["ONOFF"] = val == 0
        elif field_num == 7:
            result["SHIFTER"] = val == 0
        elif field_num == 8:
            result["ANALOG_LR"] = val  # raw 0-200, use threshold on this
            result["ANALOG_LR_SIGNED"] = _zigzag(val)  # -100 to +100
        elif field_num == 9:
            result["ANALOG_BRAKE"] = val

    return result


# ─────────────────────────────────────────────────────────────────
# macOS Key Codes & TPV Mapping
# ─────────────────────────────────────────────────────────────────

class K:
    A=0; B=11; C=8; D=2; E=14; F=3; G=5; H=4; I=34; J=38; K=40
    L=37; M=46; N=45; O=31; P=35; Q=12; R=15; S=1; T=17; U=32
    V=9; W=13; X=7; Y=16; Z=6
    N0=29; N1=18; N2=19; N3=20; N4=21; N5=23; N6=22; N7=26; N8=28; N9=25
    NUM_PLUS=69; NUM_MINUS=78
    RETURN=36; TAB=48; SPACE=49; DELETE=51; ESCAPE=53
    EQUAL=24; MINUS=27
    LEFT=123; RIGHT=124; DOWN=125; UP=126
    F1=122; F2=120; F3=99; F4=118; F5=96; F6=97
    F7=98; F8=100; F9=101; F10=109; F11=103; F12=111

KEY_NAMES = {
    K.NUM_PLUS:"Num+", K.NUM_MINUS:"Num-", K.LEFT:"←", K.RIGHT:"→",
    K.UP:"↑", K.DOWN:"↓", K.V:"V", K.SPACE:"Space", K.F10:"F10",
    K.L:"L", K.G:"G", K.B:"B", K.TAB:"Tab", K.ESCAPE:"Esc",
    K.RETURN:"Return", K.EQUAL:"=", K.MINUS:"-",
    K.N1:"1", K.N2:"2", K.N3:"3", K.N4:"4", K.N5:"5",
    K.N6:"6", K.N7:"7", K.N8:"8", K.N9:"9", K.N0:"0",
}

# ── Ride button bitmap flags (inverse logic: 0 = pressed) ──
# FC82 firmware (Jan 2025+) — confirmed from hardware testing.
# RIGHT-side buttons appear on BOTH controllers.
# LEFT-side buttons (D-pad, left shifter) only appear on LEFT controller.

class RideButton(IntFlag):
    # LEFT-only buttons (bits 0-3, 8-11)
    LEFT=0x0001;         UP=0x0002;           RIGHT=0x0004;        DOWN=0x0008
    SHIFT_UP_L=0x0100;   SHIFT_DN_L=0x0200;   POWERUP_L=0x0400;    ONOFF_L=0x0800
    # Shared / RIGHT buttons (bits 4-7, 12-15)
    A=0x0010;            B=0x0020;            Y=0x0040;            Z=0x0080
    SHIFT_UP_R=0x1000;   SHIFT_DN_R=0x2000;   POWERUP_R=0x4000;    ONOFF_R=0x8000

# ── Default TPV key mapping (shared across Play and Ride) ──

DEFAULT_MAP = {
    # Ride bitmap buttons
    "SHIFT_UP_L":  {"key": K.EQUAL,     "desc": "Gear UP"},
    "SHIFT_DN_L":  {"key": K.MINUS,     "desc": "Gear DOWN"},
    "SHIFT_UP_R":  {"key": K.EQUAL,     "desc": "Gear UP"},
    "SHIFT_DN_R":  {"key": K.MINUS,     "desc": "Gear DOWN"},
    "LEFT":        {"key": K.LEFT,       "desc": "Tactical LEFT"},
    "RIGHT":       {"key": K.RIGHT,      "desc": "Tactical RIGHT"},
    "UP":          {"key": K.UP,         "desc": "Navigate UP"},
    "DOWN":        {"key": K.DOWN,       "desc": "U-Turn / Look back"},
    "A":           {"key": "CAMERA_CYCLE", "desc": "Camera view cycle"},
    "B":           {"key": K.SPACE,      "desc": "Elbow flick"},
    "Y":           {"key": K.F10,        "desc": "Screenshot"},
    "Z":           {"key": K.L,          "desc": "Mark lap"},
    "POWERUP_L":   {"key": K.G,          "desc": "Toggle graph"},
    "POWERUP_R":   {"key": K.B,          "desc": "Take a break"},
    "ONOFF_L":     {"key": K.TAB,        "desc": "Skip block"},
    "ONOFF_R":     {"key": K.ESCAPE,     "desc": "Menu / Back"},
    # Play-specific buttons (mapped to same actions)
    "SHIFTER":     {"key": K.EQUAL,     "desc": "Gear UP (Play shifter)"},
    "ONOFF":       {"key": K.ESCAPE,     "desc": "Menu / Back (Play)"},
}


# ─────────────────────────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────────────────────────

class Config:
    DIR  = Path.home() / ".zwift-ride-tpv"
    FILE = DIR / "config.json"

    def __init__(self):
        self.button_map = dict(DEFAULT_MAP)
        self.debounce_ms = 150
        self.auto_reconnect = True
        self.scan_timeout = 30
        self._load()

    def _load(self):
        if self.FILE.exists():
            try:
                with open(self.FILE) as f:
                    d = json.load(f)
                if "button_map" in d:
                    self.button_map.update(d["button_map"])
                self.debounce_ms = d.get("debounce_ms", 150)
                self.auto_reconnect = d.get("auto_reconnect", True)
                self.scan_timeout = d.get("scan_timeout", 30)
                print(f"  📂 Config: {self.FILE}")
            except Exception as e:
                print(f"  ⚠ Config error: {e}")

    def save(self):
        self.DIR.mkdir(parents=True, exist_ok=True)
        with open(self.FILE, "w") as f:
            json.dump({
                "button_map": self.button_map,
                "debounce_ms": self.debounce_ms,
                "auto_reconnect": self.auto_reconnect,
                "scan_timeout": self.scan_timeout,
            }, f, indent=2)
        print(f"  💾 Saved: {self.FILE}")


# ─────────────────────────────────────────────────────────────────
# Keystroke Sender
# ─────────────────────────────────────────────────────────────────

class Keys:
    def __init__(self):
        self._cg = False
        self._tpv_pid = None
        try:
            import Quartz
            self._Q = Quartz
            self._cg = True
            self._find_tpv_pid()
            print("  ⚡ Input: Quartz CGEvents (targeted to TPV)")
        except ImportError:
            print("  🍎 Input: AppleScript")

    def _find_tpv_pid(self):
        """Find TrainingPeaks Virtual process ID."""
        try:
            import subprocess
            # Try common process names
            for name in ["TrainingPeaks Virtual", "indieVelo", "TrainingPeaksVirtual"]:
                result = subprocess.run(
                    ["pgrep", "-f", name],
                    capture_output=True, text=True, timeout=2
                )
                if result.stdout.strip():
                    self._tpv_pid = int(result.stdout.strip().split('\n')[0])
                    print(f"  🎯 Found TPV process: PID {self._tpv_pid}")
                    return
            print("  ⚠ TPV process not found — keys will go to frontmost app")
            print("    Start TPV before the bridge for auto-targeting")
        except Exception:
            pass

    def send(self, keycode, mod=0):
        if self._cg:
            Q = self._Q
            # If we have TPV PID, send directly to it
            # Otherwise fall back to posting to frontmost app
            for pressed in (True, False):
                ev = Q.CGEventCreateKeyboardEvent(None, keycode, pressed)
                if mod:
                    Q.CGEventSetFlags(ev, mod)
                if self._tpv_pid:
                    Q.CGEventPostToPid(self._tpv_pid, ev)
                else:
                    Q.CGEventPost(Q.kCGAnnotatedSessionEventTap, ev)
        else:
            import subprocess
            # AppleScript targets TPV by name
            subprocess.run(["osascript", "-e", f'''
                tell application "System Events"
                    set tpv to first process whose name contains "TrainingPeaks"
                    tell tpv
                        set frontmost to true
                    end tell
                    delay 0.02
                    key code {keycode}
                end tell
            '''], capture_output=True, timeout=2)

    def retarget(self):
        """Re-find TPV process (call if TPV was restarted)."""
        self._tpv_pid = None
        self._find_tpv_pid()


# ─────────────────────────────────────────────────────────────────
# Detected Device Info
# ─────────────────────────────────────────────────────────────────

@dataclass
class ZwiftDevice:
    ble_device: BLEDevice
    device_type: DeviceType
    name: str
    is_encrypted: bool  # Play/Click = True, Ride = False

    @property
    def side(self) -> str:
        if self.device_type in (DeviceType.PLAY_LEFT, DeviceType.RIDE_LEFT):
            return "LEFT"
        elif self.device_type in (DeviceType.PLAY_RIGHT, DeviceType.RIDE_RIGHT):
            return "RIGHT"
        return "CLICK"

    @property
    def family(self) -> str:
        if self.device_type in (DeviceType.RIDE_LEFT, DeviceType.RIDE_RIGHT):
            return "Ride"
        elif self.device_type in (DeviceType.PLAY_LEFT, DeviceType.PLAY_RIGHT):
            return "Play"
        return "Click"


# ─────────────────────────────────────────────────────────────────
# Bridge
# ─────────────────────────────────────────────────────────────────

@dataclass
class SessionStats:
    gear: int = 0
    shifts: int = 0
    actions: int = 0


class Bridge:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.keys = Keys()
        self.stats = SessionStats()
        self.running = True

        # Connection state (may have 1 or 2 clients for Play)
        self._clients: dict[str, BleakClient] = {}   # side → client
        self._cryptos: dict[str, ZwiftPlayCrypto] = {}  # side → crypto
        self._devices: list[ZwiftDevice] = []
        self._detected_family: Optional[str] = None

        # Debounce tracking
        self._last_event: dict[str, float] = {}

        # Analog lever state (persistent across messages)
        self._lever_active: dict[str, bool] = {}

        # Play button state per side (for edge detection)
        self._play_prev: dict[str, dict] = {"LEFT": {}, "RIGHT": {}}

        # Ride bitmap state
        self._ride_prev_bitmap: int = 0xFFFFFFFF
        self._ride_flag_map = {
            btn: btn.name for btn in RideButton if btn.name in cfg.button_map
        }

    # ── Scanning ──────────────────────────────────────────────

    async def scan(self) -> list[ZwiftDevice]:
        print(f"\n🔍 Scanning for Zwift controllers ({self.cfg.scan_timeout}s)...")
        print("   Wake controllers — press any button!\n")

        # Use discover() instead of callback scanner — more reliable on macOS
        # CoreBluetooth's callback mode doesn't always deliver manufacturer
        # data on every advertisement, causing missed detections.
        discovered = await BleakScanner.discover(
            timeout=self.cfg.scan_timeout,
            return_adv=True,
        )

        found: dict[str, ZwiftDevice] = {}

        for addr, (dev, adv) in discovered.items():
            # Match by name — check BOTH local_name and dev.name
            name = adv.local_name or dev.name or ""
            is_zwift = any(
                x in name.lower() for x in ("zwift", "sf2", "play", "click")
            )
            if not is_zwift:
                continue

            # Try to get device type from manufacturer data
            mfr = adv.manufacturer_data or {}
            dtype = None

            if ZWIFT_MANUFACTURER_ID in mfr:
                d = mfr[ZWIFT_MANUFACTURER_ID]
                if len(d) >= 1:
                    try:
                        dtype = DeviceType(d[0])
                    except ValueError:
                        pass

            # If no manufacturer data, infer from name
            if dtype is None:
                nl = name.lower()
                if "play" in nl:
                    # Can't tell left/right without mfr data — we'll
                    # figure it out during connection from field 1 of first message
                    # For now, assign based on address ordering
                    if addr not in found:
                        # Check if we already have one Play
                        existing_play = [
                            d for d in found.values()
                            if d.device_type in (DeviceType.PLAY_LEFT, DeviceType.PLAY_RIGHT)
                        ]
                        if not existing_play:
                            dtype = DeviceType.PLAY_LEFT
                        else:
                            dtype = DeviceType.PLAY_RIGHT
                elif "sf2" in nl:
                    dtype = DeviceType.RIDE_LEFT
                elif "click" in nl:
                    dtype = DeviceType.CLICK

            if dtype is None:
                print(f"   ❓ Zwift device but unknown type: {name} [{addr}]")
                continue

            encrypted = dtype in (
                DeviceType.PLAY_LEFT, DeviceType.PLAY_RIGHT, DeviceType.CLICK
            )
            zd = ZwiftDevice(dev, dtype, name, encrypted)
            found[addr] = zd
            tag = "🔒" if encrypted else "🔓"
            print(f"   {tag} {zd.family} {zd.side}: {name} [{addr}]")

        # If we found 2 Play controllers but couldn't determine sides from
        # manufacturer data, assign LEFT to the one whose mfr byte is 0x03
        # or just use address ordering as fallback
        plays = [d for d in found.values()
                 if d.device_type in (DeviceType.PLAY_LEFT, DeviceType.PLAY_RIGHT)]
        if len(plays) == 2 and plays[0].device_type == plays[1].device_type:
            # Both assigned same side — fix it
            plays[0].device_type = DeviceType.PLAY_LEFT
            plays[1].device_type = DeviceType.PLAY_RIGHT
            print(f"   ℹ  Assigned sides by address order (LEFT={plays[0].ble_device.address[:8]})")

        devices = list(found.values())
        if not devices:
            print("   ❌ No Zwift controllers found.")
            print("   • Press a button to wake them")
            print("   • Make sure Zwift is NOT connected\n")

        return devices

    # ── Connection ────────────────────────────────────────────

    async def connect_all(self, devices: list[ZwiftDevice]) -> bool:
        """Connect to all discovered controllers."""
        self._devices = devices
        family = devices[0].family
        self._detected_family = family

        if family == "Ride":
            # Ride: connect to LEFT only (tunnels RIGHT presses)
            left = next((d for d in devices if d.device_type == DeviceType.RIDE_LEFT), None)
            if not left:
                print("   ❌ Ride LEFT controller not found"); return False
            return await self._connect_ride(left)
        else:
            # Play/Click: connect to each controller separately
            success = False
            for dev in devices:
                ok = await self._connect_play(dev)
                success = success or ok
            return success

    async def _connect_ride(self, dev: ZwiftDevice) -> bool:
        """Connect to Zwift Ride (plaintext, no encryption)."""
        print(f"\n🔗 Connecting to Ride LEFT [{dev.ble_device.address}]...")
        try:
            client = BleakClient(dev.ble_device, timeout=15.0)
            await client.connect()
            if not client.is_connected:
                print("   ❌ Failed"); return False
            print("   ✅ Connected")

            # Ride characteristics (same layout as Play, confirmed from hardware):
            #   002 (h24) = notify           → button data
            #   003 (h27) = write-no-resp    → send handshake
            #   004 (h29) = indicate, read   → receive handshake response
            nc = CHAR_UUID_002  # notify  — button data
            wc = CHAR_UUID_003  # write   — send "RideOn" here
            ic = CHAR_UUID_004  # indicate — receive "RideOn" response

            # Discover correct characteristics
            for svc in client.services:
                su = str(svc.uuid).lower()
                if "19ca-4651" in su or "fc82" in su:
                    print(f"   📡 Service: {svc.uuid}")

            # Handshake
            hs = asyncio.Event()
            def on_ind(_, d):
                if d == RIDEON_HANDSHAKE:
                    print("   ✅ RideOn! 🤙"); hs.set()
            try:
                await client.start_notify(ic, on_ind)
            except Exception:
                pass

            print("   🤝 Handshake...")
            await client.write_gatt_char(wc, RIDEON_HANDSHAKE, response=False)
            try:
                await asyncio.wait_for(hs.wait(), timeout=5.0)
            except asyncio.TimeoutError:
                print("   ⚠ Timeout (continuing)")

            # Subscribe to button notifications
            await client.start_notify(nc, self._on_ride_data)
            self._clients["LEFT"] = client
            self._print_ready()
            return True
        except Exception as e:
            print(f"   ❌ {e}"); return False

    async def _connect_play(self, dev: ZwiftDevice) -> bool:
        """Connect to Zwift Play/Click (encrypted)."""
        side = dev.side
        print(f"\n🔗 Connecting to {dev.family} {side} [{dev.ble_device.address}]...")

        try:
            client = BleakClient(dev.ble_device, timeout=15.0)
            await client.connect()
            if not client.is_connected:
                print("   ❌ Failed"); return False
            print("   ✅ BLE connected")

            # Play characteristics (confirmed from hardware):
            #   002 (handle 24) = Async [notify]        — receives encrypted button data
            #   003 (handle 27) = SyncRX [write-no-resp] — send handshake + commands TO device
            #   004 (handle 29) = SyncTX [indicate,read] — receive handshake response FROM device
            #   006 (handle 32) = Extra  [write,indicate,read] — purpose TBD
            async_char  = CHAR_UUID_002  # notify  — button data
            syncrx_char = CHAR_UUID_003  # write   — we write handshake here
            synctx_char = CHAR_UUID_004  # indicate — device responds here

            # Discover service and log
            for svc in client.services:
                su = str(svc.uuid).lower()
                if "19ca-4651" in su or "fc82" in su:
                    print(f"   📡 Service: {svc.uuid}")
                    for ch in svc.characteristics:
                        print(f"      {ch.uuid} h={ch.handle} {ch.properties}")

            # Set up crypto
            crypto = ZwiftPlayCrypto()
            self._cryptos[side] = crypto

            # Subscribe to SyncTX for handshake response
            handshake_done = asyncio.Event()
            handshake_response = bytearray()

            def on_synctx(_, data):
                nonlocal handshake_response
                handshake_response.extend(data)
                if len(handshake_response) >= 72:
                    if crypto.process_handshake_response(bytes(handshake_response)):
                        print(f"   ✅ Encryption established! 🔐")
                        handshake_done.set()
                    else:
                        print(f"   ⚠ Key derivation issue")

            await client.start_notify(synctx_char, on_synctx)

            # Send our public key via SyncRX (write-without-response)
            print("   🤝 ECDH key exchange...")
            handshake_payload = crypto.generate_handshake()
            await client.write_gatt_char(syncrx_char, handshake_payload, response=False)

            try:
                await asyncio.wait_for(handshake_done.wait(), timeout=10.0)
            except asyncio.TimeoutError:
                print("   ❌ Encryption handshake timeout")
                await client.disconnect()
                return False

            # Now subscribe to Async for encrypted button data
            msg_count = {"n": 0}

            def on_async(_, data):
                msg_count["n"] += 1
                if msg_count["n"] <= 3:
                    plain = crypto.decrypt(bytes(data))
                    hex_plain = plain.hex() if plain else "decrypt_fail"
                    print(f"   📨 {side} msg#{msg_count['n']}: raw={len(data)}B plain={hex_plain[:40]}")
                elif msg_count["n"] == 4:
                    print(f"   📨 {side} receiving data OK (suppressing further debug)")
                self._on_play_data(side, bytes(data))

            await client.start_notify(async_char, on_async)
            self._clients[side] = client
            print(f"   🎮 {dev.family} {side} ready!")
            return True

        except Exception as e:
            print(f"   ❌ {e}")
            import traceback; traceback.print_exc()
            return False

    # ── Data Handlers ─────────────────────────────────────────

    def _on_ride_data(self, _, data: bytearray):
        """Handle Ride plaintext button notifications."""
        bitmap = decode_ride_bitmap(bytes(data))
        if bitmap is None:
            return

        pressed = self._ride_prev_bitmap & ~bitmap
        now = time.time()

        for flag, name in self._ride_flag_map.items():
            if not (pressed & flag):
                continue
            if self._debounce(name, now):
                continue
            self._fire_action(name)

        self._ride_prev_bitmap = bitmap

    def _on_play_data(self, side: str, raw: bytes):
        """Handle Play encrypted button notifications."""
        crypto = self._cryptos.get(side)
        if not crypto or not crypto.ready:
            return

        plain = crypto.decrypt(raw)
        if plain is None:
            return

        buttons = decode_play_buttons(plain)
        if buttons is None:
            return

        # Skip status/heartbeat messages (side field > 1 = not a real button msg)
        if buttons.get("side", 0) not in (0, 1):
            return

        now = time.time()
        prev = self._play_prev.get(side, {})

        # ── Digital buttons: edge detection (0=pressed, 1=released) ──
        # Buttons are True when pressed (decoded in decode_play_buttons)
        digital_buttons = {
            "Y": "Y", "Z": "Z", "A": "A", "B": "B",
            "ONOFF": "ONOFF", "SHIFTER": "SHIFTER",
        }

        for btn_key, base_action in digital_buttons.items():
            is_pressed = buttons.get(btn_key, False)
            was_pressed = prev.get(btn_key, False)

            if is_pressed and not was_pressed:
                # Side-aware action names
                if btn_key == "SHIFTER":
                    # Digital shifter click (if present on hardware)
                    actual = "SHIFT_DN_L" if side == "LEFT" else "SHIFT_UP_R"
                elif btn_key == "ONOFF":
                    actual = "ONOFF_L" if side == "LEFT" else "ONOFF_R"
                    if actual not in self.cfg.button_map:
                        actual = "ONOFF"
                elif btn_key in ("Y", "A") and side == "RIGHT":
                    # Right-side Y/A could be mapped differently
                    actual = f"{base_action}_R" if f"{base_action}_R" in self.cfg.button_map else base_action
                elif btn_key in ("Z", "B") and side == "RIGHT":
                    actual = f"{base_action}_R" if f"{base_action}_R" in self.cfg.button_map else base_action
                else:
                    actual = base_action

                if not self._debounce(actual, now):
                    self._fire_action(actual)

        # ── Analog lever: gear shifting ──
        # Simple approach: if lever value is above threshold, fire a shift
        # but enforce a long cooldown (500ms) to prevent machine-gun.
        # LEFT lever → Gear DOWN, RIGHT lever → Gear UP
        analog_raw = buttons.get("ANALOG_LR", 0)
        analog_signed = buttons.get("ANALOG_LR_SIGNED", 0)

        ANALOG_THRESHOLD = 60
        SHIFT_COOLDOWN_MS = 500  # minimum ms between shifts from analog

        if analog_raw >= ANALOG_THRESHOLD:
            if analog_signed > 0:
                action = "SHIFT_UP_R" if side == "RIGHT" else "SHIFT_UP_L"
            else:
                action = "SHIFT_DN_L" if side == "LEFT" else "SHIFT_DN_R"

            last = self._last_event.get(f"_analog_{side}", 0)
            if (now - last) * 1000 >= SHIFT_COOLDOWN_MS:
                self._last_event[f"_analog_{side}"] = now
                self._fire_action(action)

        self._play_prev[side] = dict(buttons)

    # ── Action Dispatch ───────────────────────────────────────

    def _debounce(self, name: str, now: float) -> bool:
        last = self._last_event.get(name, 0)
        if (now - last) * 1000 < self.cfg.debounce_ms:
            return True
        self._last_event[name] = now
        return False

    def _fire_action(self, name: str):
        m = self.cfg.button_map.get(name)
        if not m:
            print(f"   ❓ Unmapped: {name}")
            return

        key = m["key"]

        # Special: camera cycle through 1,2,3,4,5,6,7,8,9,0
        if key == "CAMERA_CYCLE":
            cam_keys = [K.N1, K.N2, K.N3, K.N4, K.N5, K.N6, K.N7, K.N8, K.N9, K.N0]
            cam_names = ["1","2","3","4","5","6","7","8","9","0"]
            self._camera_idx = (getattr(self, '_camera_idx', -1) + 1) % len(cam_keys)
            self.keys.send(cam_keys[self._camera_idx])
            self.stats.actions += 1
            print(f"   📷 Camera {cam_names[self._camera_idx]:<18} {name:<16} #{self.stats.actions}")
            return

        self.keys.send(key, m.get("mod", 0))
        self.stats.actions += 1
        desc = m["desc"]

        if "Gear UP" in desc:
            self.stats.gear += 1; self.stats.shifts += 1
            print(f"   ⬆ {desc:<22} Gear:{self.stats.gear:+d}  #{self.stats.actions}")
        elif "Gear DOWN" in desc:
            self.stats.gear -= 1; self.stats.shifts += 1
            print(f"   ⬇ {desc:<22} Gear:{self.stats.gear:+d}  #{self.stats.actions}")
        else:
            print(f"   🔘 {desc:<22} {name:<16} #{self.stats.actions}")

    # ── Ready Display ─────────────────────────────────────────

    def _print_ready(self):
        family = self._detected_family or "?"
        print(f"\n   🎮 READY — {family} Controller(s) Active")
        print("   " + "─" * 52)
        fmt = "   {:<18} {:<22} {}"
        print(fmt.format("BUTTON", "TPV ACTION", "KEY"))
        print("   " + "─" * 52)

        shown = set()
        cats = [
            ("⚙ Shifting", ["SHIFT_UP_L","SHIFT_DN_L","SHIFT_UP_R","SHIFT_DN_R","SHIFTER"]),
            ("🏁 Tactical", ["LEFT","RIGHT","UP","DOWN"]),
            ("🎬 Actions", ["A","B","Y","Z"]),
            ("⭐ Extras", ["POWERUP_L","POWERUP_R","ONOFF_L","ONOFF_R","ONOFF"]),
        ]
        for label, btns in cats:
            printed_label = False
            for b in btns:
                m = self.cfg.button_map.get(b)
                if not m or b in shown:
                    continue
                shown.add(b)
                if not printed_label:
                    print(f"   {label}"); printed_label = True
                kn = KEY_NAMES.get(m["key"], m["key"] if isinstance(m["key"], str) else f"0x{m['key']:02X}")
                print(fmt.format(b, m["desc"], kn))

        print("   " + "─" * 52)
        print("   Config: ~/.zwift-ride-tpv/config.json")
        print("   Ctrl+C to quit\n")

    # ── Main Loop ─────────────────────────────────────────────

    async def run(self):
        print("\n" + "=" * 56)
        print(f"  ⚡ {APP_NAME} v{APP_VERSION}")
        print("  🏴 Warriors Racing Edition")
        print("  🔓 Ride (plaintext) + 🔒 Play/Click (encrypted)")
        print("=" * 56)
        print("\n  Direct BLE — zero middleman apps.\n")

        while self.running:
            devices = await self.scan()
            if not devices:
                if not self.cfg.auto_reconnect:
                    break
                print("  Retry in 10s...\n")
                await asyncio.sleep(10)
                continue

            ok = await self.connect_all(devices)
            if not ok:
                print("  Retry in 5s...\n")
                await asyncio.sleep(5)
                continue

            # If Play, print ready after both connected
            if self._detected_family in ("Play", "Click"):
                self._print_ready()

            # Stay alive
            try:
                while self.running:
                    all_connected = all(
                        c.is_connected for c in self._clients.values()
                    )
                    if not all_connected:
                        break
                    await asyncio.sleep(1)
            except Exception:
                pass

            # Cleanup
            for side, c in self._clients.items():
                try:
                    await c.disconnect()
                except Exception:
                    pass
            self._clients.clear()
            self._cryptos.clear()

            if self.cfg.auto_reconnect and self.running:
                print("\n  🔄 Reconnecting...\n")
                await asyncio.sleep(2)

    async def shutdown(self):
        self.running = False
        for c in self._clients.values():
            try:
                await c.disconnect()
            except Exception:
                pass
        s = self.stats
        print(f"\n  👋 Ride on! 🚴  ({s.actions} actions, {s.shifts} shifts)\n")


# ─────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────

def main():
    if "--help" in sys.argv or "-h" in sys.argv:
        print(f"""
  {APP_NAME} v{APP_VERSION}

  Usage: zwift_ride_tpv [command]

    (default)       Start the bridge
    --save-config   Write default config
    --show-map      Print current button mapping
    --help          This message

  Supports: Zwift Ride (plaintext), Play (encrypted), Click (encrypted)

  Setup:
    pip3 install bleak cryptography pyobjc-framework-Quartz
    Grant Accessibility permission to Terminal
    Disconnect Zwift from controllers
    Wake controllers (button press → LED blinks)
    Start TPVirtual, then run this bridge
""")
        return

    cfg = Config()

    if "--save-config" in sys.argv:
        cfg.save()
        print("  Edit the file to remap any button.\n")
        return

    if "--show-map" in sys.argv:
        print(f"\n  {'Button':<18} {'Action':<22} {'Key'}")
        print("  " + "─" * 50)
        for b, m in cfg.button_map.items():
            kn = KEY_NAMES.get(m["key"], m["key"] if isinstance(m["key"], str) else f"0x{m['key']:02X}")
            print(f"  {b:<18} {m['desc']:<22} {kn}")
        print()
        return

    bridge = Bridge(cfg)
    loop = asyncio.new_event_loop()

    def on_signal(sig, frame):
        loop.create_task(bridge.shutdown())
        loop.call_later(2, loop.stop)

    signal.signal(signal.SIGINT, on_signal)
    signal.signal(signal.SIGTERM, on_signal)

    try:
        loop.run_until_complete(bridge.run())
    except KeyboardInterrupt:
        loop.run_until_complete(bridge.shutdown())
    finally:
        loop.close()


if __name__ == "__main__":
    main()
