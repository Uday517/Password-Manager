#!/usr/bin/env python3
"""
Generates a simple lock-shield icon for the Vault app.
Requires: pip install Pillow
Output: assets/icon.png (512x512), assets/icon.ico (multi-size), assets/icon.icns (macOS)
"""
import sys
import os

try:
    from PIL import Image, ImageDraw, ImageFont
except ImportError:
    print("Installing Pillow...")
    os.system(f"{sys.executable} -m pip install Pillow --quiet")
    from PIL import Image, ImageDraw, ImageFont

def create_icon(size=512):
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    s = size
    pad = int(s * 0.08)

    # Background: rounded square gradient-ish (dark purple)
    draw.rounded_rectangle([pad, pad, s - pad, s - pad],
                            radius=int(s * 0.18),
                            fill=(30, 20, 60, 255))

    # Shield body
    shield_left   = int(s * 0.25)
    shield_right  = int(s * 0.75)
    shield_top    = int(s * 0.18)
    shield_bottom = int(s * 0.82)
    shield_cx     = s // 2

    # Draw shield polygon
    shield_pts = [
        (shield_cx, shield_top),                            # top center
        (shield_right, int(s * 0.35)),                      # top right
        (shield_right, int(s * 0.58)),                      # mid right
        (shield_cx, shield_bottom),                         # bottom point
        (shield_left, int(s * 0.58)),                       # mid left
        (shield_left, int(s * 0.35)),                       # top left
    ]
    draw.polygon(shield_pts, fill=(124, 58, 237, 255))

    # Inner shield highlight
    inner = 0.07 * s
    inner_pts = [(x + (shield_cx - x) * 0.12, y + (shield_bottom - y) * 0.08 + inner * 0.5)
                 for x, y in shield_pts]
    draw.polygon(inner_pts, fill=(144, 97, 249, 255))

    # Keyhole body
    kx, ky = shield_cx, int(s * 0.47)
    kr = int(s * 0.10)  # circle radius
    draw.ellipse([kx - kr, ky - kr, kx + kr, ky + kr], fill=(0, 0, 0, 200))

    # Keyhole bottom slot
    slot_w = int(s * 0.07)
    slot_h = int(s * 0.14)
    draw.rectangle([kx - slot_w // 2, ky, kx + slot_w // 2, ky + slot_h],
                   fill=(0, 0, 0, 200))

    return img


def main():
    os.makedirs("assets", exist_ok=True)

    print("Generating icons...")

    # 512x512 PNG
    img512 = create_icon(512)
    img512.save("assets/icon.png", "PNG")
    print("  ✓ assets/icon.png")

    # Multi-size ICO for Windows
    sizes = [16, 32, 48, 64, 128, 256]
    ico_images = [create_icon(s) for s in sizes]
    ico_images[0].save("assets/icon.ico", format="ICO",
                       append_images=ico_images[1:],
                       sizes=[(s, s) for s in sizes])
    print("  ✓ assets/icon.ico")

    # Also copy to resources for the JAR
    os.makedirs("src/main/resources/com/passwordmanager/icons", exist_ok=True)
    img512.save("src/main/resources/com/passwordmanager/icons/icon.png", "PNG")
    print("  ✓ src/main/resources/com/passwordmanager/icons/icon.png")

    print("\nDone! For macOS .icns, install iconutil (macOS only) and run:")
    print("  iconutil -c icns assets/icon.iconset")


if __name__ == "__main__":
    main()
