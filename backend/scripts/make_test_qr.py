"""Generate sample QR PNG files for manual testing. Fake IDs only.

Usage: python scripts/make_test_qr.py
Writes into backend/test_qr_images/.
"""

from __future__ import annotations

import os

import qrcode

HERE = os.path.dirname(os.path.abspath(__file__))
OUT_DIR = os.path.join(os.path.dirname(HERE), "test_qr_images")

SAMPLES = {
    "url_harmless.png": "https://example.com",
    "upi_scammy.png": (
        "upi://pay?pa=sbi.refund.support@ybl&pn=SBI%20Refund%20Team"
        "&am=1&tn=refund%20claim&cu=INR"
    ),
    "upi_normal.png": "upi://pay?pa=rahul.sharma@okaxis&pn=Rahul%20Sharma&cu=INR",
}


def main() -> None:
    os.makedirs(OUT_DIR, exist_ok=True)
    for name, payload in SAMPLES.items():
        img = qrcode.make(payload)
        path = os.path.join(OUT_DIR, name)
        img.save(path)
        print(f"Wrote {path}")


if __name__ == "__main__":
    main()
