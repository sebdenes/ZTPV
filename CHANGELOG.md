# Changelog

## [1.0.0] - 2026-03-22

### Added
- Direct BLE connection to Zwift Ride left controller (no middleman apps)
- Support for both legacy (`00000001-19ca-...`) and new (`FC82`) service UUIDs
- Full 16-button mapping to TrainingPeaks Virtual keyboard shortcuts
- Gear shifting (Num+/Num-) via left and right shift paddles
- Tactical positioning (←/→) via D-pad
- Camera view (V), screenshot (F10), lap marker (L), elbow flick (Space)
- Workout controls: toggle graph (G), take a break (B), skip block (Tab)
- Navigation: U-Turn/look back (↓), menu/back (Esc)
- Quartz CGEvents keystroke injection (~1ms latency on macOS)
- AppleScript fallback for systems without pyobjc-framework-Quartz
- Customizable button mapping via `~/.zwift-ride-tpv/config.json`
- Per-button debouncing (150ms default, configurable)
- Auto-reconnect on connection loss
- Gear position tracking with session stats
- py2app build script for standalone macOS `.app` bundle
- CLI commands: `--save-config`, `--show-map`, `--help`
