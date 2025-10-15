import hashlib
import random
import zlib
from pathlib import Path
from typing import Tuple

from PIL import Image


def calculate_seed(kek: bytes, resource_id: str) -> bytes:
    material = kek + resource_id.encode("utf-8")
    return hashlib.sha256(material).digest()


def _bits_from_bytes(data: bytes) -> list:
    bits = []
    for byte in data:
        for shift in range(7, -1, -1):
            bits.append((byte >> shift) & 1)
    return bits


def _bytes_from_bits(bits: list) -> bytes:
    out = bytearray()
    for idx in range(0, len(bits), 8):
        byte = 0
        for bit in bits[idx:idx + 8]:
            byte = (byte << 1) | bit
        out.append(byte)
    return bytes(out)


def embed_payload(image_path: str, payload: bytes, seed: bytes) -> str:
    compressed = zlib.compress(payload)
    length_prefix = len(compressed).to_bytes(4, "big")
    all_bits = _bits_from_bytes(length_prefix + compressed)

    with Image.open(image_path) as img:
        cover = img.convert("RGBA")
        pixels = list(cover.getdata())

    flat = [channel for pixel in pixels for channel in pixel]
    capacity = len(flat)
    if len(all_bits) > capacity:
        raise ValueError("Cover image does not have enough capacity")

    indices = list(range(capacity))
    rnd = random.Random(int.from_bytes(hashlib.sha256(seed).digest(), "big"))
    rnd.shuffle(indices)

    for bit_index, bit in enumerate(all_bits):
        idx = indices[bit_index]
        flat[idx] = (flat[idx] & ~1) | bit

    new_pixels = [tuple(flat[i:i + 4]) for i in range(0, len(flat), 4)]
    stego = Image.new("RGBA", cover.size)
    stego.putdata(new_pixels)

    out_path = Path(image_path)
    stego_name = f"stego_{out_path.stem}.png"
    stego_path = out_path.parent / stego_name
    stego.save(stego_path)
    return stego_path.as_posix()


def extract_payload(stego_image_path: str, seed: bytes) -> bytes:
    with Image.open(stego_image_path) as img:
        cover = img.convert("RGBA")
        pixels = list(cover.getdata())

    flat = [channel for pixel in pixels for channel in pixel]
    capacity = len(flat)
    indices = list(range(capacity))
    rnd = random.Random(int.from_bytes(hashlib.sha256(seed).digest(), "big"))
    rnd.shuffle(indices)

    length_bits = [flat[indices[i]] & 1 for i in range(32)]
    length = int.from_bytes(_bytes_from_bits(length_bits), "big")

    total_bits = 32 + length * 8
    if total_bits > len(indices):
        raise ValueError("Stego image capacity mismatch")
    data_bits = [flat[indices[i]] & 1 for i in range(32, total_bits)]
    compressed = _bytes_from_bits(data_bits)
    return zlib.decompress(compressed)
