#!/usr/bin/env python3
"""Extract/Replace Atmosphere's 2nd boot splash screen in package3 ("sept logo").

Install:  python -m pip install Pillow
Extract:  python 2nd_splash_screen.py extract package3 -o sept_logo.png
Replace:  python 2nd_splash_screen.py replace package3 my_logo.png -o package3_custom
Fit:      python 2nd_splash_screen.py replace package3 my_logo.png --fit h_scale -o package3_custom
Info:     python 2nd_splash_screen.py info package3

The original input is never overwritten. Existing outputs require --force.
--fit original keeps the provided dimensions.
--fit h_scale scales toward height 720, preserving the source aspect ratio.
--fit w_scale scales toward width 1280, preserving the source aspect ratio.
--fit stretch first targets 1280 x 720, allowing aspect-ratio distortion.
After fitting, dimensions are proportionally reduced as needed to stay inside
1280 x 720. Integer pixel dimensions may slightly
round aspect ratios. Images are never cropped and are always auto-centered.
Transparent pixels are composited on black. Inputs must be static, single-frame images
with displayed dimensions at most 1280 x 720 (after EXIF orientation). Larger
images are rejected. Accepted inputs are converted to 8-bit
RGBA, then stored as BGRA bytes (4 bytes per pixel). Input file size is not
limited by the raw pixel byte count: PNG/JPEG compression sizes differ.

No firmware rebuild, .inc file, or external executable is needed.
The tool discovers the boot KIP through package3 metadata, decompresses its
sections, and locates the logo through the ARM64 display-call arguments. It
patches the compiled image dimensions, position, and pointer. A built-in BLZ
encoder repacks modified sections and updates both offset tables and SHA-256
metadata. Existing non-image variables retain their virtual addresses. Larger
images can require materializing the original zero-initialized .bss inside
.data, then appending pixels; the old .bss remains zero at its old addresses.
The resulting stored KIPs must still fit their shared 3 MiB area. Resolution
alone does not guarantee that a detailed image will compress enough to fit.
Other KIPs are verified unchanged. File size stays 8 MiB.
Modified KIP compression may affect third-party patches that specifically
identify that KIP by its original hash.

Tested against the supplied package3 (SHA-256):
3cc9d6ca5688e403c36974bced1089397ef8b36a4252f720207ae3d41a6eb557.
Other builds must use the same PK31/FSS0/KIP metadata layout and recognizable
MOVZ x0..x3 / ADRP x4 / ADD x4 / BL display-call sequence. Unknown or ambiguous
layouts are rejected. Binary validation is not a hardware boot test.

Format references:
https://github.com/Atmosphere-NX/Atmosphere/blob/master/fusee/build_package3.py
https://github.com/Atmosphere-NX/Atmosphere/blob/master/fusee/program/source/fusee_stratosphere.cpp
https://github.com/Atmosphere-NX/Atmosphere/blob/master/stratosphere/boot/source/boot_splash_screen.cpp

Disclaimer: This tool is provided as-is without any warranty. Use at your own risk.

Author: zZxVxZz
"""

import argparse
import hashlib
import os
from pathlib import Path
import struct
import sys
import tempfile
from dataclasses import dataclass

PACKAGE_SIZE = 0x800000
KIP_START = 0x100000
KIP_STORAGE_SIZE = 0x300000
KIP_END = KIP_START + KIP_STORAGE_SIZE
KIP_METADATA_LEN_LIMIT = 9  # One emummc_meta plus eight kip_metas entries.
BOOT_ID = 0x0100000000000005
IMAGE_MAX_WIDTH = 1280
IMAGE_MAX_HEIGHT = 720
IMAGE_BYTES_PER_PIXEL = 4
IMAGE_MAX_PIXELS = IMAGE_MAX_WIDTH * IMAGE_MAX_HEIGHT
IMAGE_MAX_RAW_BYTES = IMAGE_MAX_PIXELS * IMAGE_BYTES_PER_PIXEL
FIT_MODES = ('original', 'h_scale', 'w_scale', 'stretch')
FRAMEBUFFER_STRIDE = 768
SECTION_DECODE_SIZE_LIMIT = 64 * 1024 * 1024


class FormatError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise FormatError(message)


def blz_decompress(src, expected_size):
    """Decode KIP's backwards LZ stream, with explicit bounds checks."""
    require(12 <= len(src) <= expected_size <= SECTION_DECODE_SIZE_LIMIT,
            "Invalid BLZ input/output sizes.")
    total, footer, extra = struct.unpack_from('<III', src, len(src) - 12)
    require(len(src) + extra == expected_size, 'BLZ output size mismatch.')
    lower, cursor = len(src) - total, len(src) - footer
    require(12 <= footer <= total <= len(src) and lower <= cursor,
            'Invalid BLZ footer.')
    data = bytearray(src) + bytearray(extra)
    output = len(data)
    while output > lower:
        require(cursor > lower, 'Truncated BLZ control byte.')
        cursor -= 1
        control = data[cursor]
        for _ in range(8):
            if output <= lower:
                break
            if control & 0x80:
                require(cursor - lower >= 2, 'Truncated BLZ back-reference.')
                cursor -= 2
                token = struct.unpack_from('<H', data, cursor)[0]
                count = min((token >> 12) + 3, output - lower)
                distance = (token & 0xFFF) + 3
                require(output - 1 + distance < len(data),
                        'BLZ back-reference is outside the output.')
                for _ in range(count):
                    output -= 1
                    data[output] = data[output + distance]
            else:
                require(cursor > lower, 'Truncated BLZ literal.')
                cursor -= 1
                output -= 1
                data[output] = data[cursor]
            control <<= 1
    require(cursor == lower, 'Unexpected unused BLZ bytes.')
    return bytes(data)


def blz_compress(raw):
    """Greedy backwards-LZ encoder; keep a raw prefix when that saves space.

    Return (stored_bytes, compressed). Every encoded result is decoded again
    before use, checking both the stream and its in-place reconstruction.
    """
    reverse = raw[::-1]
    length = len(raw)
    groups = []
    position = encoded = 0
    best_size, best = length, None
    while position < length:
        parts, control = [], 0
        for bit in range(8):
            if position >= length:
                break
            limit = min(18, length - position)
            match_length = distance = 0
            if limit >= 3:
                key = reverse[position:position + 3]
                lower, end = max(0, position - 4098), position
                for _ in range(32):
                    candidate = reverse.rfind(key, lower, end)
                    if candidate < 0:
                        break
                    size = 3
                    while size < limit and reverse[candidate + size] == reverse[position + size]:
                        size += 1
                    if size > match_length:
                        match_length, distance = size, position - candidate
                    if size == limit:
                        break
                    end = candidate + 2
            if match_length >= 3:
                control |= 0x80 >> bit
                parts.append(struct.pack('<H', ((match_length - 3) << 12) | (distance - 3)))
                position += match_length
            else:
                parts.append(reverse[position:position + 1])
                position += 1
        group = b''.join(reversed(parts)) + bytes([control])
        groups.append(group)
        encoded += len(group)
        prefix = length - position
        padding = (-(prefix + encoded)) & 3
        size = prefix + encoded + padding + 12
        if size < best_size:
            best_size, best = size, (len(groups), prefix, padding)
    if best is None:
        return raw, False
    count, prefix, padding = best
    payload = b''.join(reversed(groups[:count]))
    footer = struct.pack('<III', len(payload) + padding + 12, padding + 12,
                         length - best_size)
    stored = raw[:prefix] + payload + b'\0' * padding + footer
    require(blz_decompress(stored, len(raw)) == raw,
            'BLZ compression verification failed; no package was written.')
    return stored, True


@dataclass
class Section:
    address: int
    size: int
    stored: bytes
    compressed: bool

    def decode(self):
        if self.compressed:
            return blz_decompress(self.stored, self.size)
        require(len(self.stored) == self.size, 'Uncompressed KIP size mismatch.')
        return self.stored


@dataclass
class Kip:
    content_entry: int
    metadata_entry: int
    offset: int
    blob: bytes
    program_id: int
    name: str
    sections: list


@dataclass
class Logo:
    offset: int
    width: int
    height: int
    x: int
    y: int
    call_address: int
    section_index: int = 1

    @property
    def size(self):
        return self.width * self.height * IMAGE_BYTES_PER_PIXEL


def read_package(data):
    require(len(data) == PACKAGE_SIZE and data[:4] == b'PK31',
            'Expected an 8 MiB Atmosphere PK31 package3.')
    require(struct.unpack_from('<I', data, 4)[0] == 0x20
            and data[0x20:0x24] == b'FSS0'
            and struct.unpack_from('<I', data, 0x24)[0] == PACKAGE_SIZE,
            'Unsupported package3 header layout.')
    start, count = struct.unpack_from('<II', data, 0x2C)
    nkips = struct.unpack_from('<I', data, 0x10)[0] + 1  # includes emummc
    require(start == 0x40 and 0 < count <= 30 and start + count * 32 <= 0x400,
            'Unsupported FSS0 content table.')
    require(0 < nkips <= KIP_METADATA_LEN_LIMIT, 'Unsupported KIP metadata table.')
    metadata = {}
    for i in range(nkips):
        entry = 0x400 + i * 0x30
        pid, offset, size = struct.unpack_from('<QII', data, entry)
        key = (KIP_START + offset, size)
        require(key not in metadata, 'Duplicate KIP metadata.')
        metadata[key] = (entry, pid, data[entry + 16:entry + 48])
    kips = []
    for i in range(count):
        entry = start + i * 32
        offset, size = struct.unpack_from('<II', data, entry)
        kind = data[entry + 8]
        if kind not in (6, 8):
            require(offset + size <= KIP_START or offset >= KIP_END,
                    'Unexpected non-KIP content in the KIP area.')
            continue
        require(KIP_START <= offset < offset + size <= KIP_END
                and size >= 0x100 and offset % 16 == 0,
                'Invalid KIP bounds or alignment.')
        blob = data[offset:offset + size]
        require(blob[:4] == b'KIP1', 'KIP1 magic missing.')
        require((offset, size) in metadata, 'KIP missing from SHA-256 table.')
        meta, pid, digest = metadata[(offset, size)]
        require(pid == struct.unpack_from('<Q', blob, 0x10)[0],
                'KIP program ID mismatch.')
        require(hashlib.sha256(blob).digest() == digest,
                'Input KIP SHA-256 mismatch; refusing to modify it.')
        sections, cursor = [], 0x100
        for section in range(6):
            address, usize, csize, _ = struct.unpack_from('<4I', blob,
                                                       0x20 + section * 16)
            if section >= 3:
                require(csize == 0, 'Unsupported stored KIP section after .data.')
                continue
            require(cursor + csize <= len(blob) and usize <= SECTION_DECODE_SIZE_LIMIT,
                    'Invalid KIP section bounds.')
            compressed = bool(blob[0x1F] & (1 << section))
            require(compressed or csize == usize, 'KIP raw section size mismatch.')
            sections.append(Section(address, usize, blob[cursor:cursor + csize],
                                    compressed))
            cursor += csize
        require(cursor == len(blob), 'Unexpected trailing data inside KIP.')
        name = blob[4:16].split(b'\0')[0].decode('ascii', errors='replace')
        kips.append(Kip(entry, meta, offset, blob, pid, name, sections))
    require(len(kips) == nkips, 'KIP content and metadata counts differ.')
    kips.sort(key=lambda item: item.offset)
    cursor = KIP_START
    for kip in kips:
        require(kip.offset >= cursor, 'Overlapping KIPs.')
        require(data[cursor:kip.offset] == b'\xCC' * (kip.offset - cursor),
                'Unknown data between KIPs; refusing to overwrite it.')
        cursor = kip.offset + len(kip.blob)
    require(data[cursor:KIP_END] == b'\xCC' * (KIP_END - cursor),
            'Unknown data after KIPs; refusing to overwrite it.')
    boots = [kip for kip in kips if kip.program_id == BOOT_ID and kip.name == 'boot']
    require(len(boots) == 1, 'Expected exactly one Atmosphere boot KIP.')
    return kips, boots[0]


def locate_logo(boot):
    """Recognize ShowDisplay(x, y, width, height, pixels) in ARM64 code."""
    code = boot.sections[0].decode()
    candidates = []
    for offset in range(0, len(code) - 27, 4):
        words = struct.unpack_from('<7I', code, offset)
        args = {}
        for word in words[:4]:
            if word & 0xFFE00000 != 0xD2800000:  # MOVZ Xd, #imm16, LSL #0
                break
            reg = word & 31
            if reg not in range(4) or reg in args:
                break
            args[reg] = (word >> 5) & 0xFFFF
        if len(args) != 4:
            continue
        adrp, add, branch = words[4:]
        if (adrp & 0x9F00001F != 0x90000004
                or add & 0xFF8003FF != 0x91000084
                or branch & 0xFC000000 != 0x94000000):
            continue
        immediate = ((adrp >> 5) & 0x7FFFF) << 2 | ((adrp >> 29) & 3)
        if immediate & (1 << 20):
            immediate -= 1 << 21
        pc = boot.sections[0].address + offset + 16
        address = (pc & ~0xFFF) + (immediate << 12)
        address += ((add >> 10) & 0xFFF) << (12 if add & (1 << 22) else 0)
        x, y, width, height = (args[i] for i in range(4))
        call_pc = boot.sections[0].address + offset + 24
        disp = branch & 0x3FFFFFF
        if disp & (1 << 25):
            disp -= 1 << 26
        target = call_pc + disp * 4
        if (0 < width <= IMAGE_MAX_WIDTH and 0 < height <= IMAGE_MAX_HEIGHT
                and x in {(IMAGE_MAX_WIDTH - width) // 2,
                          max(1, (IMAGE_MAX_WIDTH - width) // 2)}
                and y == (IMAGE_MAX_HEIGHT - height) // 2
                and boot.sections[0].address <= target
                < boot.sections[0].address + len(code)):
            for section_index in (1, 2):
                section = boot.sections[section_index]
                relative = address - section.address
                if (relative >= 0 and relative % 4 == 0
                        and relative + width * height * IMAGE_BYTES_PER_PIXEL <= section.size):
                    candidates.append(Logo(relative, width, height, x, y, call_pc,
                                           section_index))
    require(len(candidates) == 1,
            f'Found {len(candidates)} possible logo display calls; expected one. '
            'This compiler/build layout is unsupported; no output was written.')
    return candidates[0]


def image_library():
    try:
        from PIL import Image, ImageOps
    except ImportError:
        raise FormatError('Pillow is required: python -m pip install Pillow') from None
    return Image, ImageOps


def validate_image_dimensions(width, height, label='Input image'):
    require(0 < width <= IMAGE_MAX_WIDTH and 0 < height <= IMAGE_MAX_HEIGHT,
            f'{label} is {width} x {height}; maximum dimensions are '
            f'{IMAGE_MAX_WIDTH} x {IMAGE_MAX_HEIGHT}.')
    require(width * height * IMAGE_BYTES_PER_PIXEL <= IMAGE_MAX_RAW_BYTES,
            f'{label} exceeds the {IMAGE_MAX_RAW_BYTES:,}-byte raw pixel limit.')


def fitted_image_dimensions(width, height, fit='original'):
    """Apply the fit mode, then constrain the result to the display bounds."""
    validate_image_dimensions(width, height)
    require(fit in FIT_MODES, f'Unsupported fit mode: {fit}')
    if fit == 'h_scale':
        target_width, target_height = width * IMAGE_MAX_HEIGHT / height, IMAGE_MAX_HEIGHT
    elif fit == 'w_scale':
        target_width, target_height = IMAGE_MAX_WIDTH, height * IMAGE_MAX_WIDTH / width
    elif fit == 'stretch':
        target_width, target_height = IMAGE_MAX_WIDTH, IMAGE_MAX_HEIGHT
    else:
        target_width, target_height = width, height
    scale = min(1.0, IMAGE_MAX_WIDTH / target_width, IMAGE_MAX_HEIGHT / target_height)
    result_width = max(1, int(target_width * scale))
    result_height = max(1, int(target_height * scale))
    validate_image_dimensions(result_width, result_height, 'Converted image')
    return result_width, result_height


def replacement_pixels(image_path, fit='original'):
    Image, ImageOps = image_library()
    with Image.open(image_path) as opened:
        # Bound decoding work before inspecting EXIF or loading pixel data.
        require(opened.width * opened.height <= IMAGE_MAX_PIXELS,
                f'Input image has {opened.width * opened.height:,} pixels; '
                f'maximum is {IMAGE_MAX_PIXELS:,} ({IMAGE_MAX_WIDTH} x {IMAGE_MAX_HEIGHT}).')
        width, height = opened.size
        if opened.getexif().get(274, 1) in (5, 6, 7, 8):
            width, height = height, width
        validate_image_dimensions(width, height)
        require(not getattr(opened, 'is_animated', False)
                and getattr(opened, 'n_frames', 1) == 1,
                'Input must be a static, single-frame image; '
                'animated or multi-frame images are not supported.')
        image = ImageOps.exif_transpose(opened).convert('RGBA')
        validate_image_dimensions(image.width, image.height)
    background = Image.new('RGBA', image.size, (0, 0, 0, 255))
    image = Image.alpha_composite(background, image)
    size = fitted_image_dimensions(image.width, image.height, fit)
    if size != image.size:
        image = image.resize(size, Image.Resampling.LANCZOS)
    pixels = image.tobytes('raw', 'BGRA')
    require(len(pixels) == image.width * image.height * IMAGE_BYTES_PER_PIXEL,
            'Converted image must use 32-bit pixels.')
    return image.width, image.height, pixels


def align_up(value, alignment):
    return (value + alignment - 1) & ~(alignment - 1)


def validate_boot_memory_layout(header):
    """Check segment alignment/order as required by the upstream KIP reader."""
    segments = [struct.unpack_from('<II', header, 0x20 + index * 16)
                for index in range(4)]
    require(segments[0][0] == 0, 'Boot text must begin at virtual offset zero.')
    require(all(address % 0x1000 == 0 for address, _ in segments[:3]),
            'Boot text/rodata/data addresses must be page-aligned.')
    require(all(address + align_up(size, 0x1000) <= 0x100000000
                for address, size in segments), 'Boot segment address overflow.')
    require(segments[0][0] + align_up(segments[0][1], 0x1000) <= segments[1][0]
            and segments[1][0] + align_up(segments[1][1], 0x1000) <= segments[2][0]
            and segments[2][0] + segments[2][1] <= segments[3][0],
            'Boot text/rodata/data/BSS segments overlap.')


def centered_position(width, height):
    # The native renderer uses 1280 - (x + cur_x), without a trailing -1.
    # x=0 would address row 1280 outside the allocated framebuffer. Use x=1
    # for edge-to-edge widths; this maps a 1280-pixel image to rows 1279..0.
    x, y = max(1, (IMAGE_MAX_WIDTH - width) // 2), (IMAGE_MAX_HEIGHT - height) // 2
    first_row = IMAGE_MAX_WIDTH - x
    last_row = IMAGE_MAX_WIDTH - (x + width - 1)
    require(0 <= last_row <= first_row < IMAGE_MAX_WIDTH
            and 0 <= y and y + height <= IMAGE_MAX_HEIGHT,
            'Replacement position exceeds the native framebuffer bounds.')
    require(first_row * FRAMEBUFFER_STRIDE + y + height - 1
            < IMAGE_MAX_WIDTH * FRAMEBUFFER_STRIDE,
            'Replacement framebuffer address is out of bounds.')
    return x, y


def patch_display_arguments(boot, old_logo, new_logo):
    code = bytearray(boot.sections[0].decode())
    start = old_logo.call_address - boot.sections[0].address - 24
    require(0 <= start and start + 28 <= len(code), 'Invalid display-call location.')
    args = (new_logo.x, new_logo.y, new_logo.width, new_logo.height)
    registers = set()
    for index in range(4):
        offset = start + index * 4
        word = struct.unpack_from('<I', code, offset)[0]
        reg = word & 31
        require(word & 0xFFE00000 == 0xD2800000 and reg < 4,
                'Unsupported display-argument instruction.')
        registers.add(reg)
        struct.pack_into('<I', code, offset,
                         (word & ~(0xFFFF << 5)) | (args[reg] << 5))
    require(registers == {0, 1, 2, 3}, 'Missing display-argument register.')
    pointer = boot.sections[new_logo.section_index].address + new_logo.offset
    pc = boot.sections[0].address + start + 16
    pages = ((pointer & ~0xFFF) - (pc & ~0xFFF)) >> 12
    require(-(1 << 20) <= pages < (1 << 20), 'Logo pointer is outside ADRP range.')
    adrp = struct.unpack_from('<I', code, start + 16)[0]
    encoded_pages = pages & 0x1FFFFF
    adrp = ((adrp & ~((3 << 29) | (0x7FFFF << 5)))
            | ((encoded_pages & 3) << 29) | ((encoded_pages >> 2) << 5))
    add = struct.unpack_from('<I', code, start + 20)[0]
    add = (add & ~((0xFFF << 10) | (1 << 22))) | ((pointer & 0xFFF) << 10)
    struct.pack_into('<II', code, start + 16, adrp, add)
    return bytes(code)


def build_boot_with_image(boot, logo, width, height, pixels):
    """Allocate pixels without relocating any existing non-image variable."""
    raw = [section.decode() for section in boot.sections]
    old_raw = list(raw)
    rw_address = boot.sections[2].address
    bss_address, bss_size = struct.unpack_from('<II', boot.blob, 0x50)
    require(logo.section_index in (1, 2), 'Unsupported logo storage section.')
    x, y = centered_position(width, height)
    section_index, offset = logo.section_index, logo.offset
    is_data_tail = (section_index == 2 and bss_size == 0
                    and offset + logo.size == len(raw[2]))
    allocated_after_bss = False
    if is_data_tail:
        # A previous replacement's array is the final initialized object.
        # Resize it in place; existing globals and their addresses are retained.
        raw[2] = raw[2][:offset] + pixels
        allocated_after_bss = True
    elif len(pixels) <= logo.size:
        raw[section_index] = (raw[section_index][:offset] + pixels
                              + b'\0' * (logo.size - len(pixels))
                              + raw[section_index][offset + logo.size:])
    else:
        # Preserve all existing .rodata/.data addresses. Make the existing BSS
        # zeros explicit in .data, then place the new image beyond that region.
        require(bss_size == 0 or bss_address >= rw_address + len(raw[2]),
                'Overlapping writable data and BSS are unsupported.')
        raw[section_index] = (raw[section_index][:offset] + b'\0' * logo.size
                              + raw[section_index][offset + logo.size:])
        address = align_up(max(rw_address + len(raw[2]), bss_address + bss_size), 4)
        offset = address - rw_address
        require(0 <= offset and offset + len(pixels) <= SECTION_DECODE_SIZE_LIMIT,
                'Replacement exceeds the supported writable-section size.')
        raw[2] += b'\0' * (offset - len(raw[2])) + pixels
        section_index = 2
        allocated_after_bss = True
    new_logo = Logo(offset, width, height, x, y, logo.call_address, section_index)
    raw[0] = patch_display_arguments(boot, logo, new_logo)
    header = bytearray(boot.blob[:0x100])
    if allocated_after_bss:
        # The old BSS still exists, zero-filled, at its original virtual
        # addresses inside the expanded writable segment. No old pointer moves.
        struct.pack_into('<II', header, 0x50,
                         align_up(rw_address + len(raw[2]), 0x1000), 0)
    stored_sections = []
    for index, section in enumerate(boot.sections):
        if raw[index] == old_raw[index]:
            stored = section.stored
        else:
            require(len(raw[index]) <= SECTION_DECODE_SIZE_LIMIT,
                    'Modified boot section exceeds the supported decoded size.')
            stored, compressed = blz_compress(raw[index])
            header[0x1F] = (header[0x1F] & ~(1 << index)) | (int(compressed) << index)
            struct.pack_into('<II', header, 0x24 + index * 16,
                             len(raw[index]), len(stored))
        stored_sections.append(stored)
    validate_boot_memory_layout(header)
    return bytes(header) + b''.join(stored_sections), new_logo, raw


def replace_logo(data, kips, boot, logo, width, height, pixels):
    validate_image_dimensions(width, height)
    require(len(pixels) == width * height * IMAGE_BYTES_PER_PIXEL,
            'Replacement pixel length mismatch.')
    old_pixels = boot.sections[logo.section_index].decode()[logo.offset:logo.offset + logo.size]
    if width == logo.width and height == logo.height and old_pixels == pixels:
        return data  # A pixel-identical round trip preserves the entire binary.
    new_boot, new_logo, expected_sections = build_boot_with_image(boot, logo, width, height, pixels)
    required = sum(align_up(len(new_boot if kip is boot else kip.blob), 16) for kip in kips)
    require(required <= KIP_STORAGE_SIZE,
            f'Modified KIPs need {required:,} stored bytes; package3 has '
            f'{KIP_STORAGE_SIZE:,} bytes of KIP storage. The image does not fit '
            'after compression; use a smaller or simpler image.')
    result = bytearray(data)
    result[KIP_START:KIP_END] = b'\xCC' * KIP_STORAGE_SIZE
    cursor = KIP_START
    for kip in kips:
        blob = new_boot if kip is boot else kip.blob
        require(cursor + len(blob) <= KIP_END,
                'Modified KIPs exceed package3 KIP storage capacity.')
        result[cursor:cursor + len(blob)] = blob
        struct.pack_into('<II', result, kip.content_entry, cursor, len(blob))
        struct.pack_into('<II', result, kip.metadata_entry + 8,
                         cursor - KIP_START, len(blob))
        result[kip.metadata_entry + 16:kip.metadata_entry + 48] = hashlib.sha256(blob).digest()
        cursor = (cursor + len(blob) + 15) & ~15
    output = bytes(result)
    require(len(output) == len(data), 'Verification failed: package size changed.')
    require(output[0x800:KIP_START] == data[0x800:KIP_START],
            'Verification failed: non-KIP firmware changed.')
    # Every header byte outside the known offset/size/hash fields must survive.
    old_header, new_header = bytearray(data[:0x800]), bytearray(output[:0x800])
    for kip in kips:
        for start, length in [(kip.content_entry, 8), (kip.metadata_entry + 8, 40)]:
            old_header[start:start + length] = new_header[start:start + length]
    require(old_header == new_header, 'Verification failed: unrelated header changed.')
    verified_kips, verified_boot = read_package(output)  # Includes all SHA-256 checks.
    require(locate_logo(verified_boot) == new_logo,
            'Verification failed: replacement image geometry or pointer differs.')
    require(all(section.decode() == expected for section, expected
                in zip(verified_boot.sections, expected_sections)),
            'Verification failed: rebuilt boot sections differ from expected data.')
    actual = verified_boot.sections[new_logo.section_index].decode()
    require(actual[new_logo.offset:new_logo.offset + new_logo.size] == pixels,
            'Verification failed: replacement image pixels differ.')
    originals = {kip.metadata_entry: kip.blob for kip in kips if kip is not boot}
    require(all(kip.blob == originals[kip.metadata_entry]
                for kip in verified_kips if kip is not verified_boot),
            'Verification failed: another KIP changed.')
    return output


def output_path(path, input_paths, force):
    path = Path(path)
    for source in input_paths:
        same = path.resolve() == Path(source).resolve()
        if path.exists() and Path(source).exists():
            same = same or os.path.samefile(path, source)
        require(not same, 'Output must differ from every input file.')
    require(force or not path.exists(), f'Output already exists: {path} (use --force).')
    require(path.parent.is_dir(), f'Output directory does not exist: {path.parent}')
    return path


def atomic_write(path, writer, force):
    descriptor, temporary = tempfile.mkstemp(prefix='.' + path.name + '.',
                                           dir=str(path.parent))
    os.close(descriptor)
    try:
        writer(Path(temporary))
        if force:
            os.replace(temporary, path)
        else:
            # Exclusive creation avoids accidentally overwriting a new output.
            with path.open('xb') as dest, open(temporary, 'rb') as source:
                dest.write(source.read())
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest='command', required=True)
    info = commands.add_parser('info', help='Locate the small boot logo.')
    info.add_argument('package3', type=Path)
    extract = commands.add_parser('extract', help='Extract the small boot logo as PNG.')
    extract.add_argument('package3', type=Path)
    extract.add_argument('-o', '--output', type=Path, default=Path('sept_logo.png'))
    extract.add_argument('--force', action='store_true', help='Overwrite an existing output.')
    replace = commands.add_parser('replace', help='Replace only the small boot logo.')
    replace.add_argument('package3', type=Path)
    replace.add_argument('image', type=Path)
    replace.add_argument('-o', '--output', type=Path, default=Path('package3_custom'))
    replace.add_argument('--fit', choices=FIT_MODES, default='original',
                         help='Fit within 1280 x 720 (default: original); '
                              'final image is auto-centered.')
    replace.add_argument('--force', action='store_true', help='Overwrite an existing output.')
    args = parser.parse_args(argv)
    try:
        data = args.package3.read_bytes()
        kips, boot = read_package(data)
        logo = locate_logo(boot)
        print(f'boot KIP: file offset 0x{boot.offset:X}')
        print(f'Logo: {logo.width} x {logo.height}, display position ({logo.x}, {logo.y})')
        section_name = '.rodata' if logo.section_index == 1 else '.data'
        print(f'Pixels: decompressed {section_name} + 0x{logo.offset:X}, {logo.size:,} bytes')
        if args.command == 'info':
            return 0
        inputs = [args.package3] + ([args.image] if args.command == 'replace' else [])
        target = output_path(args.output, inputs, args.force)
        match args.command:
            case 'extract':
                Image, _ = image_library()
                image_data = boot.sections[logo.section_index].decode()
                image = Image.frombytes('RGBA', (logo.width, logo.height),
                                        image_data[logo.offset:logo.offset + logo.size], 'raw', 'BGRA')
                atomic_write(target, lambda path: image.save(path, format='PNG'), args.force)
            case 'replace':
                width, height, pixels = replacement_pixels(args.image, args.fit)
                x, y = centered_position(width, height)
                print(f'Replacement after --fit {args.fit}: {width} x {height}, '
                      f'{len(pixels):,} raw bytes; '
                      f'centered at ({x}, {y})')
                result = replace_logo(data, kips, boot, logo, width, height, pixels)
                atomic_write(target, lambda path: path.write_bytes(result), args.force)
                require(target.read_bytes() == result,
                        'Verification failed: saved file differs from the generated package.')
                print('Verified: saved bytes match the generated package; KIP hashes, '
                      'replacement dimensions/pixels, and other KIPs validated.')
            case _:
                raise FormatError(f'Unknown command: {args.command}')
        print(f'Saved: {target}')
        return 0
    except (OSError, ValueError, struct.error) as error:
        print(f'Error: {error}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
