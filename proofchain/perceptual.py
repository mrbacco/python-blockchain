##################################################
# author:   mrbacco <mrbacco04@gmail.com>
# date:     2026-10-07
# filename: proofchain/perceptual.py
#
# perceptual image hashing (dHash, 64 bit): unlike
# SHA3, similar images get similar hashes, so
# resized / re-compressed / lightly edited copies
# of a registered image can still be found.
# the web UI implements the same algorithm in JS.
#
# algorithm "dhash-v1":
#   1. apply EXIF orientation; halve images above
#      40 MP (bounds memory, both sides do it)
#   2. integer luminance per pixel, Pillow "L":
#      (19595 R + 38470 G + 7471 B + 32768) >> 16
#   3. exact area average (box filter, float) of
#      the full-resolution luminance down to 9x8;
#      no intermediate resize, so Python and the
#      browser (different resamplers) agree
#   4. bit = 1 when a cell is brighter than its
#      right neighbour by more than 0.1 levels (the
#      dead zone keeps flat areas stable against
#      float rounding), 8 rows x 8 comparisons
#   5. 64 bits -> 16 hex chars, row-major, MSB first
##################################################

import struct

GRID_WIDTH, GRID_HEIGHT = 9, 8
MAX_PIXELS = 40_000_000
TIE_MARGIN = 0.1
SIMILAR_DISTANCE = 10  # out of 64 bits; above this images are treated as different


def hamming_distance(a: str, b: str) -> int:
    return bin(int(a, 16) ^ int(b, 16)).count("1")


def dhash_from_grid(grid: list[list[float]]) -> str:
    # grid: GRID_HEIGHT rows of GRID_WIDTH luminance values
    value = 0
    for row in grid:
        for x in range(GRID_WIDTH - 1):
            value = (value << 1) | (1 if row[x] - row[x + 1] > TIE_MARGIN else 0)
    return f"{value:016x}"


def image_dhash(path) -> str | None:
    # returns None when Pillow is not installed or the file is not an image
    try:
        from PIL import Image, ImageOps, UnidentifiedImageError  # optional dependency
    except ImportError:
        return None
    try:
        with Image.open(path) as image:
            image = ImageOps.exif_transpose(image).convert("RGB")
            while image.width * image.height > MAX_PIXELS:
                image = image.reduce(2)
            luminance = image.convert("L").convert("F")
            small = luminance.resize((GRID_WIDTH, GRID_HEIGHT), Image.Resampling.BOX)
    except (UnidentifiedImageError, OSError):
        return None
    values = struct.unpack(f"={GRID_WIDTH * GRID_HEIGHT}f", small.tobytes())  # float32, row-major
    grid = [values[y * GRID_WIDTH:(y + 1) * GRID_WIDTH] for y in range(GRID_HEIGHT)]
    return dhash_from_grid(grid)
