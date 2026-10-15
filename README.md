# Extract/Replace Atmosphere's 2nd boot splash screen in package3 ("sept logo").

## Description
This tool is providing a convenient way to alternate 2nd splash screen which stored in package3

## Disclaimer:
This tool is provided as-is without any warranty. Use at your own risk.

## How to use
- Install:  `python -m pip install Pillow`
- Extract:  `python 2nd_splash_screen.py extract package3 -o sept_logo.png`
- Replace:  `python 2nd_splash_screen.py replace package3 my_logo.png -o package3_custom`
- Info:     `python 2nd_splash_screen.py info package3`
- Verify:   `python 2nd_splash_screen.py verify package3`

`verify` checks package structure, every KIP SHA-256 and stored section,
boot memory layout, and logo pixel bounds without writing files. A successful
check exits with status 0; invalid input exits with status 1. Existing logo
positions outside the native framebuffer bounds produce a warning, independently
of structural validity. Verification does not test hardware boot behavior.

For the supplied firmware files:
```
python 2nd_splash_screen.py verify package3.original.bk
python 2nd_splash_screen.py verify package3.kefir.bk
```

### Flags
*-o, --output*: Specify the output file.

*--force*: Force overwrite if the output file already exists.
```
$ python 2nd_splash_screen.py extract package3 -o sept_logo.png --force

$ python 2nd_splash_screen.py replace package3 my_logo.png -o package3_custom --force
```

*--fit*:
- *original*: keeps the provided dimensions.
- *h_scale*: scales toward height 720, preserving the source aspect ratio.
- *w_scale*: scales toward width 1280, preserving the source aspect ratio.
- *stretch*: first targets 1280 x 720, allowing aspect-ratio distortion.
```
$ python 2nd_splash_screen.py replace package3 my_logo.png -o package3_custom --fit original

$ python 2nd_splash_screen.py replace package3 my_logo.png -o package3_custom --fit h_scale

$ python 2nd_splash_screen.py replace package3 my_logo.png -o package3_custom --fit w_scale

$ python 2nd_splash_screen.py replace package3 my_logo.png -o package3_custom --fit stretch
```

## Behaviors
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

## Tested Builds
Tested against the supplied package3 (SHA-256):
3cc9d6ca5688e403c36974bced1089397ef8b36a4252f720207ae3d41a6eb557.
Other builds must use the same PK31/FSS0/KIP metadata layout and recognizable
MOVZ x0..x3 / ADRP x4 / ADD x4 / BL display-call sequence. Unknown or ambiguous
layouts are rejected. Binary validation is not a hardware boot test.

## Format references:
- `https://github.com/Atmosphere-NX/Atmosphere/blob/master/fusee/build_package3.py`
- `https://github.com/Atmosphere-NX/Atmosphere/blob/master/fusee/program/source/fusee_stratosphere.cpp`
- `https://github.com/Atmosphere-NX/Atmosphere/blob/master/stratosphere/boot/source/boot_splash_screen.cpp`


***Author:*** `zZxVxZz`
