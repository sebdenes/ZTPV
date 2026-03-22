"""
Build script for macOS .app bundle.

Usage:
    pip3 install py2app bleak pyobjc-framework-Quartz
    python3 setup.py py2app

This creates:
    dist/Zwift Ride TPV.app
"""

from setuptools import setup

APP = ['zwift_ride_tpv.py']
APP_NAME = 'Zwift Ride TPV'

DATA_FILES = []

OPTIONS = {
    'argv_emulation': False,
    'plist': {
        'CFBundleName': APP_NAME,
        'CFBundleDisplayName': APP_NAME,
        'CFBundleIdentifier': 'com.warriorsracing.zwiftridetpv',
        'CFBundleVersion': '1.0.0',
        'CFBundleShortVersionString': '1.0.0',
        'LSMinimumSystemVersion': '12.0',
        'NSBluetoothAlwaysUsageDescription': (
            'Zwift Ride TPV needs Bluetooth to connect to your '
            'Zwift Ride controllers for virtual gear shifting.'
        ),
        'NSAppleEventsUsageDescription': (
            'Zwift Ride TPV needs to send keypresses to '
            'TrainingPeaks Virtual for gear shifting and game control.'
        ),
        'LSUIElement': False,  # Shows in dock (set True to hide)
    },
    'packages': ['bleak', 'asyncio'],
    'includes': [
        'bleak',
        'bleak.backends',
        'bleak.backends.corebluetooth',
        'Quartz',
        'objc',
    ],
    'excludes': [
        'bleak.backends.winrt',
        'bleak.backends.bluezdbus',
        'bleak.backends.p4android',
    ],
}

setup(
    name=APP_NAME,
    app=APP,
    data_files=DATA_FILES,
    options={'py2app': OPTIONS},
    setup_requires=['py2app'],
)
