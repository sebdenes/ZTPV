#!/bin/bash
# ─────────────────────────────────────────────────────────────
# Build Zwift Ride → TPV Bridge as a macOS .app
# ─────────────────────────────────────────────────────────────
#
# Usage:
#   chmod +x build_mac.sh
#   ./build_mac.sh
#
# Output:
#   dist/Zwift Ride TPV.app
# ─────────────────────────────────────────────────────────────

set -e

echo ""
echo "═══════════════════════════════════════════════════"
echo "  Building: Zwift Ride TPV Bridge (macOS .app)"
echo "  Warriors Racing Edition"
echo "═══════════════════════════════════════════════════"
echo ""

if ! command -v python3 &> /dev/null; then
    echo "❌ python3 not found. Install: brew install python3"
    exit 1
fi

echo "📦 Installing dependencies..."
pip3 install --upgrade pip setuptools wheel 2>&1 | tail -1
pip3 install bleak pyobjc-framework-Quartz py2app 2>&1 | tail -1

echo "🧹 Cleaning..."
rm -rf build dist .eggs *.egg-info

echo "🔨 Building .app..."
python3 setup.py py2app 2>&1 | tail -5

if [ -d "dist/Zwift Ride TPV.app" ]; then
    echo ""
    echo "✅ Success! → dist/Zwift Ride TPV.app"
    SIZE=$(du -sh "dist/Zwift Ride TPV.app" | cut -f1)
    echo "   Size: $SIZE"
    echo ""
    echo "   Install: cp -R 'dist/Zwift Ride TPV.app' /Applications/"
    echo ""
    echo "   First run:"
    echo "   1. Grant Bluetooth permission when prompted"
    echo "   2. Grant Accessibility: System Settings → Privacy → Accessibility"
    echo "   3. Disconnect Zwift from your Ride controllers"
    echo "   4. Wake controller (button press → blue LED)"
    echo "   5. Start TPVirtual and ride!"
    echo ""
else
    echo "❌ Build failed. Run directly instead:"
    echo "   python3 zwift_ride_tpv.py"
    exit 1
fi
