# ⚡ ZTPV — Zwift → TrainingPeaks Virtual Bridge

**Direct BLE connection from Zwift controllers to TrainingPeaks Virtual. No middleman apps. No BikeControl. No QZ. Free.**

Warriors Racing Edition 🏴

## What It Does

Connects directly to your Zwift controllers via Bluetooth LE, decodes button presses, and sends keyboard shortcuts to TrainingPeaks Virtual — gear shifting, tactical positioning, camera views, screenshots, and more.

```
Zwift Controllers ──BLE──► ZTPV ──Keypress──► TrainingPeaks Virtual
  (Ride or Play)         (decode)            (all controls)
```

## Supported Controllers

| Controller | Protocol | Status |
|---|---|---|
| **Zwift Ride** (FC82 firmware) | Plaintext protobuf | ✅ All 16 buttons working |
| **Zwift Play** | ECDH + AES-CCM encrypted | ✅ Left controller working |
| **Zwift Click** | Same as Play | 🔧 Untested |

## Button Mapping

### Zwift Ride

| Ride Button | TPV Action | Key |
|---|---|---|
| Right Shift UP | Gear UP | = |
| Right Shift DOWN | Gear DOWN | - |
| Left Shift UP | Gear UP | = |
| Left Shift DOWN | Gear DOWN | - |
| D-Pad LEFT / RIGHT | Tactical positioning | ← → |
| D-Pad UP | Navigate UP | ↑ |
| D-Pad DOWN | U-Turn / Look back | ↓ |
| A | Camera view cycle (1-0) | 1,2,3...0 |
| B | Elbow flick | Space |
| Y | Screenshot | F10 |
| Z | Mark lap | L |
| Left Powerup | Toggle workout graph | G |
| Right Powerup | Take a break | B |
| Left On/Off | Skip workout block | Tab |
| Right On/Off | Menu / Back | Esc |

### Zwift Play

Same actions as Ride, plus analog lever shifting:
- Left lever squeeze → Gear DOWN
- Right lever squeeze → Gear UP
- 500ms cooldown prevents repeated firing

## Download & Install

### Option 1: Standalone executable (recommended)

Download `ZwiftRideTPV-macos-arm64.zip` from [Releases](https://github.com/sebdenes/ZTPV/releases).

Unzip and run — no Python needed.

### Option 2: Run from source

```bash
pip3 install bleak cryptography pyobjc-framework-Quartz
python3 zwift_ride_tpv.py
```

### Option 3: Desktop launcher

```bash
cat > ~/Desktop/ZTPV.command << 'EOF'
#!/bin/bash
cd ~/ZRTPV
python3 zwift_ride_tpv.py
EOF
chmod +x ~/Desktop/ZTPV.command
```

## Setup

1. **Start TrainingPeaks Virtual** and begin a ride
2. **Disconnect Zwift** — controllers can only connect to one app
3. **Wake controllers** — press any button (LED blinks)
4. **Run ZTPV** — it auto-detects Ride vs Play and connects
5. **Grant permissions** when macOS prompts:
   - Bluetooth access
   - Accessibility (System Settings → Privacy & Security → Accessibility)

ZTPV targets the TPV process directly — keypresses work even when Terminal or another app is in the foreground.

## Configuration

Save a default config to customize:

```bash
python3 zwift_ride_tpv.py --save-config
```

Edit `~/.zwift-ride-tpv/config.json` to remap any button. Key codes are macOS virtual key codes.

```bash
python3 zwift_ride_tpv.py --show-map    # show current mapping
python3 zwift_ride_tpv.py --help        # all options
```

## How It Works

### Zwift Ride (FC82 firmware)

- BLE Service: `FC82` (16-bit)
- Handshake: write `"RideOn"` → receive `"RideOn"` back
- Buttons: protobuf message `0x23` with 16-bit bitmap (inverse logic)
- Single connection to LEFT controller (tunnels right-side presses too, but left-only buttons like D-pad only appear here)

### Zwift Play (encrypted)

- BLE Service: `00000001-19ca-4651-86e5-fa29dcdd09d1`
- ECDH key exchange (secp256r1 / P-256)
- HKDF-SHA256 key derivation (36 bytes → 32 AES key + 4 nonce prefix)
- AES-CCM encrypted messages (4-byte counter, 4-byte MIC tag)
- Connects to both LEFT and RIGHT controllers independently
- Button data: protobuf message `0x07` with per-field tags

### BLE Characteristics (same layout for both)

| UUID | Properties | Role |
|---|---|---|
| 002 | notify | Button data stream |
| 003 | write-without-response | Send handshake / commands |
| 004 | indicate, read | Receive handshake response |

## vs. Alternatives

| | BikeControl | tpv-zclick | **ZTPV** |
|---|---|---|---|
| Middleman app | Self | QZ App | **None** |
| Direct BLE | No | No | **Yes** |
| Cost | Paid Pro | Free | **Free** |
| Encryption support | Yes | No | **Yes** |
| Ride FC82 support | Yes | No | **Yes** |
| macOS executable | Yes | No | **Yes** |
| Open source | Partial | Yes | **Yes** |

## Troubleshooting

**"No Zwift controllers found"** — Wake controllers, make sure Zwift app is disconnected, check Bluetooth is on.

**Shifts show in console but TPV doesn't respond** — Make sure TPV is running before ZTPV starts (it needs to find the TPV process PID).

**"TPV process not found"** — Run `ps aux | grep -i training` to find the exact process name, then update the search in the code.

**Permissions** — Grant Accessibility to Terminal (or the executable) in System Settings → Privacy & Security → Accessibility.

## Credits

- **Makinolo** — Zwift Play and Ride BLE protocol reverse engineering
- **Rouvy** — Proving third-party Zwift hardware support is legally viable
- **OpenBikeControl** — Pioneering the multi-platform bridge concept
- **ajchellew/zwiftplay** — Zwift Play protocol research

## License

MIT — use it, fork it, share it with your team.

---

Built by [Sebastien Denes](https://www.linkedin.com/in/sebastiendenes/) / Warriors Racing 🏴
