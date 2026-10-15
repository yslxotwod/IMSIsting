#!/usr/bin/env python3
"""Generate the module icon set from the category-base + module-mark grammar.

Every icon is two layers on a 256x256 grid:

  base   the category pictogram, stroked, anchored to the LEFT so that its
         recognisable features survive the overlap on the right
  mark   the module's own glyph, solid, centred at (188,150), overlapping the
         base's right third

A mask punches a hole through the base behind the mark. The icons are GTK
symbolic icons, so the whole file is rendered in ONE colour selected by the
widget - the layers are separated by weight (thin outline base, solid mark)
and by that hole, never by colour.

SYSTEM has no base: those four modules are the bench itself, so their mark is
drawn alone and larger, which is what makes them read as the deliberate
exception rather than the unfinished set.

Run from the repo root:  python3 tools/gen-module-icons.py
"""

import os

OUT = "native/resources/icons/symbolic"
# The icons are loaded straight out of the binary with
# gtk_image_new_from_resource(), exactly as wifisting does, so they are NOT
# recoloured by the icon theme and must carry their own colour. Two tones,
# because that is what separates the category base from the module mark at
# 16px - the identical trick the mask plays on the geometry.
BASE_COLOR = "#63798f"    # muted slate: the category, read as a frame
MARK_COLOR = "#c8d4e2"    # near-white: this module, read as the subject

BASE_SW = 13          # base stroke width
MARK_SW = 12          # stroke width used inside a mark
MCX, MCY = 188.0, 150.0   # mark centre; base is composed to avoid its own
                          # defining feature living here
MASK_R = 56.0


# ---------------------------------------------------------------- primitives
def C(cx, cy, r):
    return '<circle cx="%.1f" cy="%.1f" r="%.1f"/>' % (cx, cy, r)


def R(x, y, w, h, rx=4):
    return ('<rect x="%.1f" y="%.1f" width="%.1f" height="%.1f" rx="%.1f"/>'
            % (x, y, w, h, rx))


def P(d):
    return '<path d="%s"/>' % d


def Ln(x1, y1, x2, y2):
    return ('<line x1="%.1f" y1="%.1f" x2="%.1f" y2="%.1f"/>'
            % (x1, y1, x2, y2))


def SL(d, w=MARK_SW):
    """A stroked mark element - fill must be off or it floods the path."""
    return ('<path d="%s" fill="none" stroke="%s" '
            'stroke-width="%d" stroke-linecap="round" '
            'stroke-linejoin="round"/>' % (d, MARK_COLOR, w))


def arc(r, cx=-34.0, cy=34.0, w=MARK_SW):
    """A signal arc centred bottom-left, leaving the top for the next one."""
    return SL("M %.1f %.1f A %.1f %.1f 0 0 1 %.1f %.1f"
              % (cx, cy - r, r, r, cx + r, cy), w)


def dot(cx, cy, r=10):
    return C(cx, cy, r)


def rings(d, w=MARK_SW):
    return SL(d, w)


# ------------------------------------------------------------------- bases
# Left-anchored. Anything that would land in the mark's mask is already gone,
# so each of these is drawn to keep its own signature on the left half.
BASES = {
    "RECON": (            # binoculars: two barrels kept low and narrow so the
                          # right one is not what makes it a binocular
        SL("M72 208 A40 40 0 1 1 72 128", BASE_SW) +
        SL("M140 208 A40 40 0 1 1 140 128", BASE_SW) +
        R(96, 148, 22, 40, 2)
    ),
    "AIR INTERFACE": (    # handset, body on the left, arcs deliberately NOT
                          # top-right (that is the mark's zone)
        SL("M52 40 h50 a12 12 0 0 1 12 12 v152 a12 12 0 0 1 -12 12 h-50 "
           "a12 12 0 0 1 -12 -12 v-152 a12 12 0 0 1 12 -12 z", BASE_SW) +
        SL("M66 62 h24", BASE_SW)
    ),
    "CORE NETWORK": (     # cell tower: mast, braces, two rungs
        SL("M92 36 v196", BASE_SW) +
        SL("M92 58 L34 232", BASE_SW) +
        SL("M92 58 L150 232", BASE_SW) +
        SL("M58 170 h68", BASE_SW) +
        SL("M70 124 h44", BASE_SW)
    ),
    "SIM / IDENTITY": (   # SIM card; the clipped corner stays top-right, well
                          # clear of a mask centred at y=150
        SL("M44 44 h88 l34 34 v138 a8 8 0 0 1 -8 8 h-114 a8 8 0 0 1 -8 -8 "
           "v-164 a8 8 0 0 1 8 -8 z", BASE_SW) +
        SL("M62 126 h50 v50 h-50 z", BASE_SW)
    ),
    "ATTACKS": (          # lightning bolt, shifted left so its head clears
        P("M132 26 L58 142 h50 l-26 88 L170 106 h-50 z")
    ),
    "ANALYSIS": (         # magnifier: lens left, and the handle points DOWN-
                          # LEFT so it is not the thing under the mark
        SL("M100 116 m-62 0 a62 62 0 1 0 124 0 a62 62 0 1 0 -124 0", BASE_SW) +
        SL("M56 168 L18 216", BASE_SW)
    ),
    "RF / TRACKING": (    # crosshair: four ticks, arrow shortened and pointed
                          # down-right so it stays out of the mask
        SL("M104 128 m-66 0 a66 66 0 1 0 132 0 a66 66 0 1 0 -132 0", BASE_SW) +
        SL("M104 44 v18", BASE_SW) + SL("M104 194 v18", BASE_SW) +
        SL("M20 128 h18", BASE_SW) + SL("M170 128 h18", BASE_SW) +
        SL("M104 128 L142 166", BASE_SW)
    ),
}


# ------------------------------------------------------------------- marks
# Drawn around (0,0), roughly +/-44 units, then translated onto the mark centre.
M = {}

# --- SYSTEM: no base, drawn alone and larger -----------------------------
M["00_deps"] = (R(-36, -34, 72, 16, 4) + R(-36, -10, 72, 16, 4) +
                R(-36, 14, 44, 16, 4) +
                SL("M14 22 l10 12 l22 -28"))
M["01_radio"] = (R(-38, -8, 76, 34, 6) + C(-6, -34, 8) +
                 SL("M-6 -8 L-6 -26") + arc(30, -30.0, 30.0))
M["05_field_kit"] = (R(-40, -18, 80, 44, 6) +
                     SL("M-16 -18 a16 16 0 0 1 32 0") + C(0, 4, 6))
M["30_killchain"] = (C(-30, 0, 13) + C(0, 0, 13) + C(30, 0, 13) +
                     SL("M-18 0 h6") + SL("M12 0 h6"))

# --- RECON: binoculars base ----------------------------------------------
M["02_cell_recon"] = P("M0 -34 L30 -17 v34 L0 34 L-30 17 v-34 z")
M["03_gsmtap"] = dot(-26, 0, 11) + dot(0, 0, 11) + dot(26, 0, 11)
M["04_tower_map"] = P("M0 38 L-20 2 A22 22 0 1 1 20 2 z")
M["54_ntn"] = (R(-16, -14, 32, 28, 4) + R(-46, -10, 22, 20, 3) +
               R(24, -10, 22, 20, 3))
M["58_non3gpp"] = (R(-30, -18, 46, 36, 6) + SL("M16 -18 L32 -38") +
                   C(34, -42, 7))

# --- AIR INTERFACE: handset base, the arc count IS the generation ---------
M["10_gsm_air"] = dot(-34, 34, 9) + arc(30)
M["12_umts_air"] = dot(-34, 34, 9) + arc(26) + arc(48)
M["14_lte_air"] = dot(-34, 34, 9) + arc(22) + arc(40) + arc(58)
M["16_nr_air"] = dot(-34, 34, 9) + arc(20) + arc(36) + arc(52) + arc(68)
M["50_iot"] = (dot(-34, 34, 9) +
               '<path d="M -34 4 A 30 30 0 0 1 -4 34" fill="none" '
               'stroke="%s" stroke-width="12" '
               'stroke-dasharray="10 9"/>' % MARK_COLOR)
M["55_gprs"] = dot(-34, 34, 9) + arc(28) + R(-8, -22, 22, 22, 4)
M["56_sidelink"] = (R(-42, -18, 20, 36, 4) + R(22, -18, 20, 36, 4) +
                    arc(24, -12.0, 0.0) + arc(40, -12.0, 0.0))

# --- CORE NETWORK: tower base, solid nodes inside the frame ---------------
M["13_lte_attach"] = (dot(4, 4, 16) + SL("M-44 -26 L-6 -26") +
                      P("M-6 -38 L16 -26 L-6 -14 z"))
M["15_lte_core"] = dot(0, 0, 20)
M["17_nr_core"] = dot(-22, 20, 13) + dot(22, 20, 13) + dot(0, -20, 13)
M["31_ss7_map"] = (dot(-30, 0, 11) + dot(0, 0, 11) + dot(30, 0, 11) +
                   SL("M-19 0 h8") + SL("M11 0 h8"))
M["32_cellular_dns"] = (dot(0, -20, 13) + dot(-28, 26, 9) + dot(0, 28, 9) +
                        dot(28, 26, 9) + SL("M-4 -8 L-22 18") +
                        SL("M0 -8 L0 20") + SL("M4 -8 L22 18"))
M["39_slicing"] = (R(-34, -32, 68, 20, 4) + R(-34, -6, 68, 20, 4) +
                   R(-34, 20, 68, 20, 4))
M["41_vowifi"] = (dot(-34, 34, 9) + arc(26) + arc(44) + arc(62))
M["42_femtocell"] = (R(-26, -4, 52, 32, 5) + SL("M0 -4 L0 -26") +
                     C(0, -32, 7))
M["43_ussd"] = (dot(-16, -16, 11) + dot(16, -16, 11) +
                dot(-16, 16, 11) + dot(16, 16, 11))
M["45_sba_pivot"] = (dot(-26, -14, 11) + dot(0, 0, 11) + dot(-26, 16, 11) +
                     P("M16 -8 L42 0 L16 8 z"))
M["48_ran_share"] = (SL("M-18 0 m-22 0 a22 22 0 1 0 44 0 a22 22 0 1 0 -44 0") +
                     SL("M18 0 m-22 0 a22 22 0 1 0 44 0 a22 22 0 1 0 -44 0"))
M["52_wifioff"] = (arc(24) + arc(42) + P("M14 -22 L40 -30 L14 -38 z"))

# --- SIM / IDENTITY: card base, the mark sits on the pads ----------------
M["18_suci"] = C(0, -12, 16) + P("M0 4 L-11 34 L11 34 z")
M["20_sim"] = (R(-26, -16, 52, 34, 4) + SL("M0 -40 L0 -20") +
               P("M-12 -30 L0 -16 L12 -30 z"))
M["36_sim_defense"] = P("M0 -38 L30 -24 v22 A30 30 0 0 1 0 38 "
                        "A30 30 0 0 1 -30 0 v-22 z")
M["46_ota_sms"] = (R(-34, -22, 68, 44, 5) + SL("M-34 -22 L0 8 L34 -22"))
M["57_stk"] = (SL("M-30 -18 h20") + SL("M-30 0 h20") + SL("M-30 18 h20") +
               C(20, -18, 8) + C(20, 0, 8) + C(20, 18, 8))

# --- ATTACKS: lightning base, mark beside it -----------------------------
M["11_gsm_attack"] = dot(-34, 34, 9) + arc(34) + SL("M-40 30 L26 -34")
M["19_downgrade"] = SL("M-38 30 h22 v-18 h22 v-18 h22")
M["24_gsm_cve"] = (dot(-40, 34, 8) + arc(24, -40.0, 34.0) + arc(42, -40.0, 34.0) +
                   SL("M10 -34 L-4 -6 L10 4 L-4 34"))
M["25_lte_cve"] = (dot(-40, 34, 8) + arc(20, -40.0, 34.0) + arc(34, -40.0, 34.0) +
                   arc(48, -40.0, 34.0) + SL("M16 -34 L2 -6 L16 4 L2 34"))
M["26_nr_cve"] = (dot(-40, 34, 8) + arc(18, -40.0, 34.0) + arc(30, -40.0, 34.0) +
                  arc(42, -40.0, 34.0) + arc(54, -40.0, 34.0) +
                  SL("M18 -34 L4 -6 L18 4 L4 34"))
M["35_volte_ims"] = (R(-32, -28, 64, 46, 10) + P("M-6 18 L-14 34 L8 18 z"))
M["40_baseband"] = (R(-30, -30, 60, 60, 6) + C(0, 0, 8) +
                    SL("M-30 -18 h-10") + SL("M-30 0 h-10") +
                    SL("M-30 18 h-10") + SL("M30 -18 h10") + SL("M30 0 h10") +
                    SL("M30 18 h10"))
M["53_oran"] = SL("M22 -20 A30 30 0 1 0 22 20")
M["59_baseband_exploit"] = (R(-30, -30, 60, 60, 6) +
                            SL("M0 -34 L-8 -8 L4 2 L-6 34"))
M["60_nr_inject"] = (dot(-40, 34, 8) + arc(20, -40.0, 34.0) + arc(34, -40.0, 34.0) +
                     arc(48, -40.0, 34.0) + P("M20 -6 L46 2 L20 10 z"))

# --- ANALYSIS: magnifier base, mark inside the lens ----------------------
M["21_pcap_analysis"] = SL("M-38 8 l12 -22 l12 32 l12 -36 l12 26 l12 -12 l10 8")
M["22_imsi_exposure"] = (SL("M-14 -32 h-16 v64 h16") +
                         SL("M14 -32 h16 v64 h-16") + C(0, 0, 11))
M["23_cipher_audit"] = C(0, -12, 16) + P("M0 4 L-11 34 L11 34 z")
M["27_traffic_analysis"] = SL("M-34 -12 h68") + SL("M-34 12 h68")
M["34_mac_layer"] = R(-34, -28, 68, 22, 4) + R(-34, 6, 68, 22, 4)
M["37_nas_signaling"] = (R(-32, -26, 64, 40, 10) +
                         P("M-6 14 L-14 32 L8 14 z"))
M["47_li_probe"] = (SL("M-40 0 h80") + C(0, 0, 11) + SL("M0 0 L0 -30"))
M["49_carrier_api"] = (SL("M-10 -34 h-14 v68 h14") +
                       SL("M10 -34 h14 v68 h-14"))

# --- RF / TRACKING: crosshair base ---------------------------------------
M["28_rf_fingerprint"] = (arc(24, -30.0, 26.0) + arc(40, -30.0, 26.0) +
                          arc(56, -30.0, 26.0))
M["33_paging_track"] = (dot(0, 0, 10) + dot(-30, -26, 8) + dot(30, -26, 8) +
                        dot(-38, 14, 8) + dot(38, 14, 8) + dot(0, 34, 8))
M["38_jamming_detect"] = ('<path d="M0 -40 A40 40 0 0 1 40 0" fill="none" '
                          'stroke="%s" stroke-width="12" '
                          'stroke-linecap="round"/>' % MARK_COLOR +
                          '<path d="M0 -26 A26 26 0 0 1 26 0" fill="none" '
                          'stroke="%s" stroke-width="12" '
                          'stroke-dasharray="8 8"/>' % MARK_COLOR +
                          SL("M0 -12 h12"))
M["44_ta_geoloc"] = (SL("M0 0 m-38 0 a38 38 0 1 0 76 0 a38 38 0 1 0 -76 0") +
                     SL("M0 0 m-22 0 a22 22 0 1 0 44 0 a22 22 0 1 0 -44 0") +
                     dot(0, 0, 9))
M["51_lpp"] = (R(-16, -30, 32, 22, 4) + R(-40, -26, 18, 14, 3) +
               R(22, -26, 18, 14, 3) + SL("M0 -8 L0 12") + dot(0, 22, 10))


HEAD = ('<svg xmlns="http://www.w3.org/2000/svg" width="256" height="256" '
        'viewBox="0 0 256 256">\n')


def build(module_id, category):
    base = BASES.get(category, "")
    mark = M.get(module_id)
    if mark is None:
        raise SystemExit("no mark defined for %s" % module_id)
    if category == "SYSTEM":
        # No base: the mark is the whole icon, so it runs larger and centred.
        xform = 'transform="translate(128 128) scale(1.55)"'
        return (HEAD +
                '<g fill="%s" stroke="none" %s>%s</g>\n</svg>\n'
                % (MARK_COLOR, xform, mark))
    return (
        HEAD +
        '<defs><mask id="cut">'
        '<rect width="256" height="256" fill="white"/>'
        '<circle cx="%.0f" cy="%.0f" r="%.0f" fill="black"/>'
        '</mask></defs>\n' % (MCX, MCY, MASK_R) +
        '<g fill="none" stroke="%s" stroke-width="%d" '
        'stroke-linecap="round" stroke-linejoin="round" mask="url(#cut)">'
        '%s</g>\n' % (BASE_COLOR, BASE_SW, base) +
        '<g fill="%s" stroke="none" '
        'transform="translate(%.0f %.0f)">%s</g>\n' % (MARK_COLOR, MCX, MCY, mark) +
        '</svg>\n')


def main():
    # the registry, read straight out of the C table so the two cannot drift
    import re
    CATS = ("SYSTEM", "RECON", "AIR INTERFACE", "CORE NETWORK",
            "SIM / IDENTITY", "ATTACKS", "ANALYSIS", "RF / TRACKING")
    row = re.compile(r'^\s*\{ "([0-9][a-z0-9_]*)",\s*"[^"]*",\s*"([^"]+)"')
    mods = []
    with open("native/src/main1.c") as f:
        for line in f:
            m = row.match(line)
            if m and m.group(2) in CATS:
                mods.append((m.group(1), m.group(2)))

    if len(mods) != 56:
        raise SystemExit("expected 56 modules, parsed %d" % len(mods))

    os.makedirs(OUT, exist_ok=True)
    for mid, cat in mods:
        path = os.path.join(OUT, "imsisting-%s-symbolic.svg" % mid)
        with open(path, "w") as f:
            f.write(build(mid, cat))
    print("wrote %d icons to %s" % (len(mods), OUT))


if __name__ == "__main__":
    main()
