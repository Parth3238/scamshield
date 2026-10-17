"""Decode QR codes from uploaded image bytes. Never writes to disk."""

from __future__ import annotations

import io

import cv2
import numpy as np
from PIL import Image

MAX_FILE_BYTES = 5 * 1024 * 1024  # 5 MB
MAX_IMAGE_PIXELS = 25_000_000

ALLOWED_FORMATS = {"PNG", "JPEG", "WEBP"}

# Cap Pillow decompression before opening anything.
Image.MAX_IMAGE_PIXELS = MAX_IMAGE_PIXELS


class InvalidImageError(Exception):
    """Raised when the bytes are not a real PNG/JPEG/WEBP image."""


class ImageTooLargeError(Exception):
    """Raised when the uploaded file exceeds 5 MB."""


class QRNotFoundError(Exception):
    """Raised when no QR code can be decoded from the image."""


def _to_clean_rgb(img: Image.Image) -> Image.Image:
    """Re-encode into a fresh RGB image (drops metadata, flattens alpha)."""
    if img.mode in ("RGBA", "LA", "PA"):
        background = Image.new("RGB", img.size, (255, 255, 255))
        alpha = img.convert("RGBA").split()[-1]
        rgb = img.convert("RGB")
        background.paste(rgb, mask=alpha)
        return background
    if img.mode == "P" and "transparency" in img.info:
        background = Image.new("RGB", img.size, (255, 255, 255))
        alpha = img.convert("RGBA").split()[-1]
        rgb = img.convert("RGB")
        background.paste(rgb, mask=alpha)
        return background
    return img.convert("RGB")


def decode_qr(image_bytes: bytes) -> str:
    """Decode the first QR code payload from raw image bytes."""
    if image_bytes is None or len(image_bytes) > MAX_FILE_BYTES:
        raise ImageTooLargeError("too large")

    try:
        with Image.open(io.BytesIO(image_bytes)) as img:
            # Inspect real content, not the file name or content-type.
            img_format = img.format
            # Force full decode so truncated/corrupt files fail here.
            img.load()
            width, height = img.size
            if width <= 0 or height <= 0 or width * height > MAX_IMAGE_PIXELS:
                raise InvalidImageError("bad dimensions")
            if img_format not in ALLOWED_FORMATS:
                raise InvalidImageError("bad format")
            clean = _to_clean_rgb(img)
    except (InvalidImageError, ImageTooLargeError):
        raise
    except Exception as exc:
        raise InvalidImageError("not an image") from exc

    try:
        arr = np.asarray(clean)
        gray = cv2.cvtColor(arr, cv2.COLOR_RGB2GRAY)
        detector = cv2.QRCodeDetector()
        data, _bbox, _straight = detector.detectAndDecode(gray)
    except Exception as exc:
        raise QRNotFoundError("decode failed") from exc

    if not data or not data.strip():
        raise QRNotFoundError("no QR found")
    return data.strip()
