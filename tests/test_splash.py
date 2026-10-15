import hashlib
import contextlib
import io
import importlib.util
from pathlib import Path
import random
import struct
import sys
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location(
    'splash', Path(__file__).resolve().parents[1] / '2nd_splash_screen.py')
splash = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = splash
SPEC.loader.exec_module(splash)


def package_fixture():
    header = bytearray(0x100)
    header[:4] = b'KIP1'
    header[4:8] = b'boot'
    struct.pack_into('<Q', header, 0x10, splash.BOOT_ID)
    words = [0xD2800000 | (value << 5) | reg
             for reg, value in enumerate((639, 359, 2, 2))]
    words += [0xB0000004, 0x91000084, 0x97FFFFFA, 0xD65F03C0]
    sections = [struct.pack('<8I', *words), b'\x11\x22\x33\xff' * 4, b'DATA']
    for index, (address, raw) in enumerate(zip((0, 0x1000, 0x2000), sections)):
        struct.pack_into('<4I', header, 0x20 + index * 16,
                         address, len(raw), len(raw), 0)
    struct.pack_into('<II', header, 0x50, 0x3000, 32)
    blob = bytes(header) + b''.join(sections)
    data = bytearray(splash.PACKAGE_SIZE)
    data[:4] = b'PK31'
    struct.pack_into('<I', data, 4, 0x20)
    data[0x20:0x24] = b'FSS0'
    struct.pack_into('<I', data, 0x24, len(data))
    struct.pack_into('<II', data, 0x2C, 0x40, 1)
    struct.pack_into('<II', data, 0x40, splash.KIP_START, len(blob))
    data[0x48] = 6
    struct.pack_into('<QII', data, 0x400, splash.BOOT_ID, 0, len(blob))
    data[0x410:0x430] = hashlib.sha256(blob).digest()
    data[splash.KIP_START:splash.KIP_END] = b'\xcc' * splash.KIP_STORAGE_SIZE
    data[splash.KIP_START:splash.KIP_START + len(blob)] = blob
    return bytes(data)


class SplashTests(unittest.TestCase):
    def test_verify_cli_preserves_input_and_rejects_bad_section(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'package3'
            data = package_fixture()
            path.write_bytes(data)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(splash.main(['verify', str(path)]), 0)
            self.assertIn('3 decoded sections', output.getvalue())
            self.assertEqual(path.read_bytes(), data)
            self.assertEqual(list(Path(directory).iterdir()), [path])
            damaged = bytearray(data)
            damaged[splash.KIP_START + 0x1F] |= 2
            size = struct.unpack_from('<I', damaged, 0x44)[0]
            damaged[0x410:0x430] = hashlib.sha256(
                damaged[splash.KIP_START:splash.KIP_START + size]).digest()
            path.write_bytes(damaged)
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(splash.main(['verify', str(path)]), 1)

    def test_compression_round_trips(self):
        rng = random.Random(7)
        for size in (0, 1, 16, 128, 4096):
            for raw in (bytes(size), (b'abcd' * size)[:size], rng.randbytes(size)):
                stored, compressed = splash.blz_compress(raw)
                self.assertEqual(splash.blz_decompress(stored, size)
                                 if compressed else stored, raw)

    def test_replace_grow_shrink_and_identical(self):
        data = package_fixture()
        kips, boot = splash.read_package(data)
        logo = splash.locate_logo(boot)
        self.assertEqual((logo.width, logo.height), (2, 2))
        pixels = boot.sections[1].decode()
        self.assertEqual(splash.replace_logo(data, kips, boot, logo, 2, 2, pixels), data)
        for width, height in ((16, 8), (1, 1), (1280, 1)):
            pixels = b'\x44\x55\x66\xff' * width * height
            data = splash.replace_logo(data, kips, boot, logo, width, height, pixels)
            kips, boot = splash.read_package(data)
            logo = splash.locate_logo(boot)
            self.assertEqual((logo.width, logo.height), (width, height))
            raw = boot.sections[logo.section_index].decode()
            self.assertEqual(raw[logo.offset:logo.offset + logo.size], pixels)
            self.assertEqual(boot.sections[2].decode()[:4], b'DATA')
            self.assertEqual(boot.sections[2].decode()[0x1000:0x1020], bytes(32))

    def test_reject_overlapping_boot_sections_even_with_valid_hash(self):
        data = bytearray(package_fixture())
        struct.pack_into('<I', data, splash.KIP_START + 0x40, 0x1000)
        size = struct.unpack_from('<I', data, 0x44)[0]
        data[0x410:0x430] = hashlib.sha256(
            data[splash.KIP_START:splash.KIP_START + size]).digest()
        with self.assertRaisesRegex(splash.FormatError, 'overlap'):
            splash.read_package(data)

    def test_reject_out_of_bounds_non_kip_content(self):
        data = bytearray(package_fixture())
        struct.pack_into('<I', data, 0x30, 2)
        struct.pack_into('<II', data, 0x60, len(data), 1)
        with self.assertRaisesRegex(splash.FormatError, 'beyond'):
            splash.read_package(data)

    def test_exclusive_output_and_failed_writer(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'output'
            def failed_writer(path):
                path.write_bytes(b'partial')
                raise OSError('disk full')
            with self.assertRaises(OSError):
                splash.atomic_write(target, failed_writer, False)
            self.assertEqual(list(Path(directory).iterdir()), [])
            splash.atomic_write(target, lambda p: p.write_bytes(b'complete'), False)
            with self.assertRaises(FileExistsError):
                splash.atomic_write(target, lambda p: p.write_bytes(b'new'), False)
            self.assertEqual(target.read_bytes(), b'complete')
            splash.atomic_write(target, lambda p: p.write_bytes(b'new'), True)
            self.assertEqual(target.read_bytes(), b'new')
            self.assertEqual(list(Path(directory).iterdir()), [target])

    def test_image_alpha_and_fit(self):
        Image, _ = splash.image_library()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'image.png'
            Image.new('RGBA', (2, 1), (255, 0, 0, 128)).save(path)
            width, height, pixels = splash.replacement_pixels(path)
            self.assertEqual((width, height, pixels), (2, 1, b'\0\0\x80\xff' * 2))
            self.assertEqual(splash.fitted_image_dimensions(2, 1, 'stretch'), (1280, 720))


if __name__ == '__main__':
    unittest.main()
