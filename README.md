# ⚡ Zwift Ride → TrainingPeaks Virtual Bridge

**Direct BLE connection from your Zwift Ride controllers to TrainingPeaks Virtual. No middleman apps. No BikeControl. No QZ. Free.**

Warriors Racing Edition 🏴

## What It Does

Connects directly to your Zwift Ride's left controller via Bluetooth LE, decodes all 16 buttons from the protobuf wire format, and injects keyboard shortcuts into TrainingPeaks Virtual.

```
Zwift Ride Controller ──BLE──► This App ──Keypress──► TPVirtual
     (left side)              (decode)              (all controls)
```

## Full Button Mapping

| Ride Button | TPV Action | Key |
|---|---|---|
| **Left Shift UP** | Gear UP (harder) | Num+ |
| **Left Shift DOWN** | Gear DOWN (easier) | Num- |
| **Right Shift UP** | Gear UP (harder) | Num+ |
| **Right Shift DOWN** | Gear DOWN (easier) | Num- |
| **D-Pad LEFT** | Tactical position LEFT | ← |
| **D-Pad RIGHT** | Tactical position RIGHT | → |
| **D-Pad UP** | Navigate UP | ↑ |
| **D-Pad DOWN** | U-Turn / Look back | ↓ |
| **A button** | Camera view cycle | V |
| **B button** | Elbow flick | Space |
| **Y button** | Screenshot | F10 |
| **Z button** | Mark lap | L |
| **PowerUp LEFT** | Toggle workout graph | G |
| **PowerUp RIGHT** | Take a break | B |
| **On/Off LEFT** | Skip workout block | Tab |
| **On/Off RIGHT** | Menu / Back | Esc |

All mappings are customizable via `~/.zwift-ride-tpv/config.json`.

## Quick Start (Python)

```bash
pip3 install bleak pyobjc-framework-Quartz
python3 zwift_ride_tpv.py
```

## Build macOS App

```bash
pip3 install bleak pyobjc-framework-Quartz py2app
chmod +x build_mac.sh
./build_mac.sh

# Install
cp -R 'dist/Zwift Ride TPV.app' /Applications/
```

## Setup Checklist

1. **Disconnect Zwift** from the Ride controllers (BLE is exclusive)
2. **Wake controller** — press any button until blue LED blinks
3. **Start TPVirtual** — open a ride/race
4. **Run the bridge** — `python3 zwift_ride_tpv.py` or launch the .app
5. **Grant permissions** when macOS prompts:
   - Bluetooth access
   - Accessibility (System Settings → Privacy & Security → Accessibility)

## Configuration

Save a default config to customize:

```bash
python3 zwift_ride_tpv.py --save-config
```

Edit `~/.zwift-ride-tpv/config.json`:

```json
{
  "button_map": {
    "A": {"key": 9, "desc": "Camera view"},
    "B": {"key": 49, "desc": "Elbow flick"}
  },
  "debounce_ms": 150,
  "auto_reconnect": true,
  "scan_timeout": 30
}
```

Key codes are macOS virtual key codes. Run `--show-map` to see current mappings.

## How It Works

### BLE Protocol (Makinolo's research)

- **Service UUID**: `FC82` (16-bit, Jan 2025+ firmware) or `00000001-19ca-4651-86e5-fa29dcdd09d1` (legacy)
- **Handshake**: Write `"RideOn"` → receive `"RideOn"` back. No encryption.
- **Notifications**: Protobuf message ID `0x23` with 32-bit button bitmap (inverse logic)
- **Single connection**: Left controller tunnels all right-side button presses

### vs. Alternatives

| | BikeControl | tpv-zclick | **This** |
|---|---|---|---|
| Middleman app | Self | QZ App | **None** |
| Direct BLE | No | No | **Yes** |
| Cost | Paid Pro | Free | **Free** |
| All 16 buttons | Yes | Shift only | **Yes** |
| macOS app | Yes | Script | **Yes** |
| Zwift Ride native | Yes | Click only | **Yes** |

## Troubleshooting

**"No Zwift Ride found"** → Wake controller, disconnect Zwift, check Bluetooth.

**Shifts not working in TPVirtual** → Grant Accessibility permission to Terminal/.app.

**High latency** → Install `pyobjc-framework-Quartz` (CGEvents ~1ms vs AppleScript ~100ms).

**Config changes not taking effect** → Delete `~/.zwift-ride-tpv/config.json` and restart.

## Credits

- **Makinolo** — Zwift Ride BLE protocol reverse engineering
- **Rouvy** — Proving third-party Zwift hardware support is viable
- **OpenBikeControl** — Pioneering the multi-platform bridge concept

## License

MIT — use it, fork it, share it with your team.
