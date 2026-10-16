#!/usr/bin/env bash
# 61_baseband_diag — Qualcomm DM/DIAG: framing, NV, EFS, identity, AT, log demux.
#                                                                        (tag: bbdg)
#
# WHAT THIS IS. DIAG is Qualcomm's modem diagnostic interface. It is reached over a
# USB interface or a UART, never over the air, so nothing here emits RF. This module
# is the wire- and protocol-level half: it builds and parses DIAG frames for real, and
# it talks to a device when one is attached.
#
# NOTHING HERE IS GATED. --nv-write and --efs-write are raw primitives and they write.
# That is deliberate: they are the layer an operator drives deliberately, with the item
# numbers and paths they choose. What is deliberately NOT here is a pre-baked
# "--set-imsi" one-liner. No published table maps NV item numbers to semantics (the
# single authoritative data point found is item 178 = DIAG_NV_DIR_NUMBER), so a
# hardcoded identity mapping would be a guess dressed as a feature. The discovery verbs
# (--nv-scan, --nv-read, --efs-walk, --state-info, --efs-stat) exist so the mapping is
# found on the real device instead of assumed.
#
# PROVENANCE AND LICENSING. libqcdm (ModemManager) is GPL-2.0-ONLY and osmo-qcdiag is
# GPL-2.0-or-later, so no source text is copied from either. Protocol facts, command
# codes and byte layouts are not copyrightable; the CRC table below is generated here
# from the polynomial. The known-answer vectors in the selftest are DATA (numbers) and
# are restated as numbers.
#
# CLAUSE MAP (every asserted value is recomputed here, never trusted):
#   [MM] libqcdm/src/utils.c        dm_encapsulate_buffer / dm_escape / dm_crc16
#        §1.1 delimiter 0x7E, appended only (never emitted as a leading marker)
#        §1.2 escape 0x7D, mask 0x20, SINGLE pass over the original bytes
#        §1.3 CRC-16/X-25 — reflected poly 0x8408, init 0xFFFF, xorout 0xFFFF,
#             transmitted little-endian
#   [MM] libqcdm/src/dm-commands.h
#        struct DMCmdNVReadWrite  = code(1) nv_item(2 LE) data[128] status(2) = 133 B
#        struct DMCmdSubsysHeader = code(1) subsys_id(1) subsys_cmd(2 LE)
#        struct DMCmdVersionInfoRsp = 55 bytes
#        struct DMCmdGsmStateInfoRsp / DMCmdWcdmaStateInfoRsp
#        DMNVStatus
#        DIAG_SUBSYS_GSM = 8, DIAG_SUBSYS_WCDMA = 4, DIAG_SUBSYS_CM = 15,
#        DIAG_SUBSYS_FS = 19
#   [MM] libqcdm/src/commands.c     imxi_bcd_to_string — the IMEI/IMSI BCD decode
#   [QS] QCSuper src/qcsuper/protocol/{messages,efs2,subsystems}.py
#        DIAG_SUBSYS_CMD_F = 75, DIAG_FS_OP_F = 89; EFS2 subcommand codes and the
#        OPEN/READ/WRITE/CLOSE field layouts; DIAG_SUBSYS_FS_ALTERNATE = 62
#   [OSMO] osmo-qcdiag src/protocol/diagcmd.h — independent agreement on 38/39/75
#
# WHAT IS NOT SOURCED (marked so it is never mistaken for verified):
#   * The STAT / UNLINK / PUT / GET argument forms below are this module's construction
#     from the path-string convention that OPEN uses. Only their SUBCOMMAND CODES are
#     sourced ([QS] efs2.py). The selftest therefore asserts the codes, not the args.
#   * No published NV read/write RESPONSE byte vector exists in any implementation, and
#     no published EFS byte vector of any kind exists (QCSuper has no EFS test suite).
#     The parser layouts rest on the sourced structs; --efs-parse is exercised only
#     against responses this module builds.
#   * The version-info field-by-field semantics are derived from the sourced struct
#     layout; the published test asserts the decapsulated BYTES, not the field decode.
#
# KNOWN-ANSWER AUTHORITIES (re-extracted and re-verified, not transcribed from memory):
#   * [MM] libqcdm/tests/test-qcdm-crc.c — a 48-byte subsystem request (CRC 0x097A) and
#     a 133-byte NV-read request for item 178 (CRC 0x6D69). The second independently
#     proves the 128-byte padded layout: the CRC only matches if all 133 bytes are sent.
#   * [MM] libqcdm/tests/test-qcdm-escaping.c — a 256-byte data1 and its 266-byte
#     expected1; plus a 48-byte vector (the CRC one) that must escape to itself.
#   * [MM] src/tests/test-qcdm-serial-port.c — the 58-byte version-info frame
#     (CRC 0xC419), a 12x-leading-0x7E tolerance case, and two REJECT vectors.
#   * CRC-16/X-25 catalogue check value: crc16("123456789") == 0x906E.
#
# HARDWARE. None is required for any verb except --write-hex/--read, which need a USB
# cable. The repo has no SDR and no serial radio, so the live path is a handoff (--plan)
# naming the exact device. `pyserial` is deliberately NOT used: this is a byte-level
# protocol over a tty and is driven with `stty` + `dd`, so no new dependency appears.

# --------------------------------------------------------------------------- header
BBDG_SELF="${BASH_SOURCE[0]}"
while [ -L "$BBDG_SELF" ]; do
    BBDG_LINK="$(readlink "$BBDG_SELF")"
    case "$BBDG_LINK" in
        /*) BBDG_SELF="$BBDG_LINK" ;;
        *)  BBDG_SELF="$(dirname "$BBDG_SELF")/$BBDG_LINK" ;;
    esac
done
BBDG_MODDIR="$(cd "$(dirname "$BBDG_SELF")" && pwd)"
IMSISTING_ROOT="${IMSISTING_ROOT:-$(cd "$BBDG_MODDIR/.." && pwd)}"
export IMSISTING_ROOT
# Under pkexec HOME is /root; repair it so loot lands in the invoking user's tree.
if [ -n "${SUDO_USER:-}" ] && [ "${HOME:-}" = "/root" ]; then
    HOME="$(getent passwd "$SUDO_USER" | cut -d: -f6)"
    export HOME
fi

TMP_DIR="${TMP_DIR:-${TMPDIR:-/tmp}/imsisting}"
LOOT_DIR="${LOOT_DIR:-$IMSISTING_ROOT/loot}"
CAPTURES_DIR="${CAPTURES_DIR:-$IMSISTING_ROOT/captures}"
STATE_DIR="${STATE_DIR:-$IMSISTING_ROOT/state}"
BBDG_DIR="$LOOT_DIR/baseband_diag"
mkdir -p "$TMP_DIR" "$BBDG_DIR" 2>/dev/null

# --------------------------------------------------------------------------- shims
# `declare -F`, never `command -v`: /usr/bin/info (texinfo) exists, so command -v
# succeeds and the shim is never defined, making `info "msg"` exec texinfo.
declare -F info >/dev/null 2>&1 || info()  { printf '[i] %s\n' "$*" >&2; }
declare -F warn >/dev/null 2>&1 || warn()  { printf '[!] %s\n' "$*" >&2; }
declare -F err  >/dev/null 2>&1 || err()   { printf '[x] %s\n' "$*" >&2; }
declare -F ok   >/dev/null 2>&1 || ok()    { printf '[+] %s\n' "$*" >&2; }
declare -F banner >/dev/null 2>&1 || banner() { printf '\n== %s ==\n' "$*" >&2; }

# --------------------------------------------------------------------------- helpers
# Field splitting. NEVER `IFS=$'\t' read` — tab is whitespace to read(1), runs of it
# collapse, and a row with an empty column shifts every later field. Convert the tabs
# to newlines and read one value at a time instead. KEY at index 2k, VALUE at 2k+1.
BBDG_F=()
bbdg_split() {
    BBDG_F=()
    local line
    # `read` returns non-zero on a final line with no trailing newline, and command
    # substitution strips exactly that newline -- without the extra test the LAST
    # field of every record is silently dropped.
    while IFS= read -r line || [ -n "$line" ]; do BBDG_F+=("$line"); done \
        < <(printf '%s\n' "${1:-}" | tr '\t' '\n')
}

bbdg_is_hex() {
    local s="${1:-}"
    [ -n "$s" ] || return 1
    case "$s" in *[!0-9A-Fa-f]*) return 1 ;; esac
    [ $(( ${#s} % 2 )) -eq 0 ]
}

# printf %02X does NOT truncate: above 255 it emits three hex digits and corrupts
# whatever it was spliced into. Mask at the point of emission, always.
# Lowercase, like every other byte this module emits. Mixing case inside one frame
# (lowercase payload, uppercase CRC) makes byte-wise comparison of two frames fail for
# no reason a reader can see.
bbdg_oct() { printf '%02x' "$(( ${1:-0} & 0xFF ))"; }

bbdg_le16() {
    local v=$(( ${1:-0} & 0xFFFF ))
    printf '%02x%02x' "$(( v & 0xFF ))" "$(( (v >> 8) & 0xFF ))"
}

bbdg_le32() {
    local v=$(( ${1:-0} & 0xFFFFFFFF ))
    printf '%02x%02x%02x%02x' \
        "$(( v & 0xFF ))" "$(( (v >> 8) & 0xFF ))" \
        "$(( (v >> 16) & 0xFF ))" "$(( (v >> 24) & 0xFF ))"
}

bbdg_hexlen() { printf '%d' "$(( ${#1} / 2 ))"; }

# Read a little-endian u16/u32 at a BYTE offset out of a hex string.
bbdg_u16at() { local o=$(( $1 * 2 )); printf '%d' "$(( 16#${2:$((o+2)):2}${2:$o:2} ))"; }
bbdg_u32at() {
    local o=$(( $1 * 2 ))
    printf '%d' "$(( 16#${2:$((o+6)):2}${2:$((o+4)):2}${2:$((o+2)):2}${2:$o:2} ))"
}

# ------------------------------------------------------------------- §1 framing
# §1.3 CRC-16/X-25. Table built lazily so sourcing every module into the launcher's
# single shell does not pay 256 iterations at load time.
BBDG_CRC_TABLE=()
bbdg_crc_table() {
    [ "${#BBDG_CRC_TABLE[@]}" -eq 256 ] && return 0
    BBDG_CRC_TABLE=()
    local i j c
    for (( i = 0; i < 256; i++ )); do
        c=$i
        for (( j = 0; j < 8; j++ )); do
            if (( c & 1 )); then c=$(( (c >> 1) ^ 0x8408 )); else c=$(( c >> 1 )); fi
        done
        BBDG_CRC_TABLE[$i]=$c
    done
}

# bbdg_crc16 <hex> -> four hex digits, lowercase (the CRC value, not the wire order).
bbdg_crc16() {
    local hex="${1:-}"
    bbdg_crc_table
    local crc=65535 i b
    for (( i = 0; i < ${#hex}; i += 2 )); do
        b=$(( 16#${hex:$i:2} ))
        crc=$(( (crc >> 8) ^ BBDG_CRC_TABLE[(crc ^ b) & 0xFF] ))
    done
    printf '%04x' "$(( crc ^ 0xFFFF ))"
}

# §1.2 escaping. Single left-to-right pass over the ORIGINAL bytes: an inserted 0x7D
# is emitted by the pass and never revisited. A two-pass "replace 7E, then 7D"
# implementation is WRONG — it double-escapes the 0x7D it just inserted.
bbdg_escape() {
    local hex="${1:-}" out="" i b
    for (( i = 0; i < ${#hex}; i += 2 )); do
        b="${hex:$i:2}"
        case "${b^^}" in
            7E) out+="7d5e" ;;
            7D) out+="7d5d" ;;
            *)  out+="$b" ;;
        esac
    done
    printf '%s' "$out"
}

# bbdg_unescape <hex> -> hex. Rejects a stray 0x7D: a decoder must not silently drop a
# byte it does not understand, because that turns a corrupt frame into a valid one.
bbdg_unescape() {
    local hex="${1:-}" out="" i b n
    i=0
    while (( i < ${#hex} )); do
        b="${hex:$i:2}"
        if [ "${b^^}" = "7D" ]; then
            n="${hex:$(( i + 2 )):2}"
            case "${n^^}" in
                5E) out+="7e" ;;
                5D) out+="7d" ;;
                *)  printf 'stray 7D at byte %d (followed by %s)\n' "$(( i / 2 ))" "${n:-<end>}" >&2
                    return 1 ;;
            esac
            i=$(( i + 4 ))
        else
            out+="$b"
            i=$(( i + 2 ))
        fi
    done
    printf '%s' "$out"
}

# §1.1 encapsulate: <payload hex> -> <escaped frame hex>7e. The escape pass runs over
# payload AND CRC together, because either can contain 0x7D or 0x7E.
bbdg_encapsulate() {
    local hex="${1:-}" crc logical
    bbdg_is_hex "$hex" || { printf 'need even-length hex\n' >&2; return 2; }
    crc="$(bbdg_crc16 "$hex")"
    logical="${hex}${crc:2:2}${crc:0:2}"
    printf '%s7e' "$(bbdg_escape "$logical")"
}

# bbdg_decapsulate <frame hex> -> TSV, 0; or a message on stderr, 1.
# Liberal in what it accepts (leading 0x7E markers are tolerated — libqcdm's own test
# demands it) and strict in what it reports (the CRC must verify).
bbdg_decapsulate() {
    local hex="${1:-}" u body want got crclo crchi code
    [ -n "$hex" ] || { printf 'empty input\n' >&2; return 2; }
    bbdg_is_hex "$hex" || { printf 'not even-length hex\n' >&2; return 2; }
    while [ "${hex:0:2}" = "7e" ]; do hex="${hex:2}"; done
    [ -n "$hex" ] || { printf 'no frame after leading markers\n' >&2; return 1; }
    case "${hex: -2}" in
        7e|7E) ;;
        *) printf 'missing trailing 7E terminator\n' >&2; return 1 ;;
    esac
    hex="${hex:0:${#hex}-2}"
    u="$(bbdg_unescape "$hex")" || return 1
    (( ${#u} >= 6 )) || { printf 'frame shorter than the 4-byte minimum\n' >&2; return 1; }
    body="${u:0:${#u}-4}"
    crclo="${u: -4:2}"
    crchi="${u: -2:2}"
    want="$(bbdg_crc16 "$body")"
    got="${crchi}${crclo}"
    if [ "$got" != "$want" ]; then
        printf 'CRC mismatch: frame carries %s, computed %s\n' "$got" "$want" >&2
        return 1
    fi
    code=$(( 16#${body:0:2} ))
    printf 'cmd\t%s\n'        "${body:0:2}"
    printf 'cmd_dec\t%d\n'    "$code"
    printf 'cmd_name\t%s\n'   "$(bbdg_cmd_name "$code")"
    printf 'frame_kind\t%s\n' "$(bbdg_frame_kind "$code")"
    printf 'payload\t%s\n'    "${body:2}"
    printf 'payload_len\t%d\n' "$(( (${#body} - 2) / 2 ))"
    printf 'crc\t%s\n'        "$want"
    # `body` is the decoded frame INCLUDING its command byte, which is the shape the
    # DM command structs describe (e.g. DMCmdVersionInfoRsp starts with its own
    # `code`). Re-encapsulating `body` must reproduce the original frame.
    printf 'body\t%s\n'       "$body"
    printf 'body_len\t%d\n'   "$(( ${#body} / 2 ))"
}

# ------------------------------------------------------------------- §2 command codec
bbdg_cmd_name() {
    case "${1:-0}" in
        0)   printf 'DIAG_VERNO_F (version info)' ;;
        1)   printf 'DIAG_ESN_F (ESN)' ;;
        4)   printf 'DIAG_PEEK_F' ;;
        16)  printf 'DIAG_LOG_F' ;;
        31)  printf 'DIAG_MSG_F' ;;
        38)  printf 'DIAG_NV_READ_F' ;;
        39)  printf 'DIAG_NV_WRITE_F' ;;
        41)  printf 'DIAG_CONTROL_F' ;;
        75)  printf 'DIAG_SUBSYS_CMD_F' ;;
        89)  printf 'DIAG_FS_OP_F (legacy EFS)' ;;
        115) printf 'DIAG_LOG_CONFIG_F' ;;
        121) printf 'DIAG_EXT_MSG_F' ;;
        122) printf 'DIAG_EXT_MSG_TERSE_F' ;;
        125) printf 'DIAG_EXT_MSG_CONFIG_F' ;;
        *)   printf 'unknown (0x%02X)' "$(( ${1:-0} & 0xFF ))" ;;
    esac
}

bbdg_frame_kind() {
    case "${1:-0}" in
        0|1|4)          printf 'identity' ;;
        38|39)          printf 'nv' ;;
        75|89)          printf 'fs' ;;
        16|31|121|122)  printf 'log' ;;
        115|125)        printf 'config' ;;
        *)              printf 'unknown' ;;
    esac
}

bbdg_subsys_name() {
    case "${1:-0}" in
        4)   printf 'DIAG_SUBSYS_WCDMA' ;;
        8)   printf 'DIAG_SUBSYS_GSM' ;;
        15)  printf 'DIAG_SUBSYS_CM' ;;
        19)  printf 'DIAG_SUBSYS_FS (EFS2)' ;;
        62)  printf 'DIAG_SUBSYS_FS_ALTERNATE' ;;
        *)   printf 'unknown (%d)' "$(( ${1:-0} & 0xFF ))" ;;
    esac
}

bbdg_nv_status() {
    case "${1:-0}" in
        0)  printf 'DM_NV_STATUS_OK' ;;
        1)  printf 'DM_NV_STATUS_BUSY' ;;
        2)  printf 'DM_NV_STATUS_BAD_COMMAND' ;;
        3)  printf 'DM_NV_STATUS_MEMORY_FULL' ;;
        4)  printf 'DM_NV_STATUS_FAILED' ;;
        5)  printf 'DM_NV_STATUS_INACTIVE' ;;
        6)  printf 'DM_NV_STATUS_BAD_PARAMETER' ;;
        7)  printf 'DM_NV_STATUS_READ_ONLY' ;;
        *)  printf 'unknown NV status (%d)' "$(( ${1:-0} & 0xFFFF ))" ;;
    esac
}

bbdg_efs_errno() {
    case "${1:-0}" in
        0)  printf 'OK' ;;
        1)  printf 'EPERM' ;;
        2)  printf 'ENOENT' ;;
        5)  printf 'EIO' ;;
        9)  printf 'EBADF' ;;
        12) printf 'ENOMEM' ;;
        13) printf 'EACCES' ;;
        17) printf 'EEXIST' ;;
        20) printf 'ENOTDIR' ;;
        21) printf 'EISDIR' ;;
        22) printf 'EINVAL' ;;
        28) printf 'ENOSPC' ;;
        30) printf 'EROFS' ;;
        34) printf 'ERANGE' ;;
        *)  printf 'errno %d' "$1" ;;
    esac
}

bbdg_efs_filetype() {
    # EFS2_FILE_TYPES from the EFS2 DIAG interface; STAT's mode field is a UNIX
    # st_mode, so the file type is mode & 0170000.
    # bash `case` patterns are decimal, so the S_IF* masks are written in decimal:
    # 010000=4096, 020000=8192, 040000=16384, 060000=24576, 100000=32768,
    # 120000=40960, 140000=49152, 160000=57344.
    case $(( ${1:-0} & 0170000 )) in
        0)     printf 'Unknown' ;;
        4096)  printf 'FIFO (S_IFIFO)' ;;
        8192)  printf 'Character device (S_IFCHR)' ;;
        16384) printf 'Directory (S_IFDIR)' ;;
        24576) printf 'Block device (S_IFBLK)' ;;
        32768) printf 'Regular file (S_IFREG)' ;;
        40960) printf 'Symlink (S_IFLNK)' ;;
        49152) printf 'Socket (S_IFSOCK)' ;;
        57344) printf 'Item File (S_IFITM)' ;;
        *)     printf 'unknown type 0%o' "$(( ${1:-0} & 0170000 ))" ;;
    esac
}

# --------------------------------------------------------------- §3 NV read/write
# struct DMCmdNVReadWrite = code(1) nv_item(2 LE) data(128) status(2 LE) = 133 bytes.
bbdg_nv_build() {
    local op="${1:-}" item="${2:-}" data="${3:-}" code pad need
    case "$op" in
        read)  code=38 ;;
        write) code=39 ;;
        *) printf 'op must be read or write (got %s)\n' "${op:-<empty>}" >&2; return 2 ;;
    esac
    case "$item" in
        ''|*[!0-9]*) printf 'nv item must be a decimal number 0..65535\n' >&2; return 2 ;;
    esac
    (( item >= 0 && item <= 65535 )) || { printf 'nv item out of 16-bit range\n' >&2; return 2; }
    if [ -n "$data" ]; then
        bbdg_is_hex "$data" || { printf 'nv data must be even-length hex\n' >&2; return 2; }
    fi
    (( ${#data} <= 256 )) || { printf 'nv data exceeds the 128-byte field\n' >&2; return 2; }
    need=$(( 256 - ${#data} ))
    pad=""
    if (( need > 0 )); then
        printf -v pad '%*s' "$need" ''
        pad="${pad// /0}"
    fi
    printf '%02x%s%s0000' "$code" "$(bbdg_le16 "$item")" "${data}${pad}"
}

# bbdg_nv_parse <hex> -> TSV. Requires exactly 133 bytes: a short NV response means the
# transport truncated, which must be reported rather than parsed into rubbish.
bbdg_nv_parse() {
    local hex="${1:-}" code item status
    bbdg_is_hex "$hex" || { printf 'not even-length hex\n' >&2; return 2; }
    (( ${#hex} == 266 )) || {
        printf 'NV response must be 133 bytes (266 hex chars), got %d bytes\n' "$(( ${#hex} / 2 ))" >&2
        return 1
    }
    code="${hex:0:2}"
    item="$(bbdg_u16at 1 "$hex")"
    status="$(bbdg_u16at 131 "$hex")"
    printf 'code\t%s\n'          "$code"
    printf 'code_name\t%s\n'     "$(bbdg_cmd_name "$(( 16#$code ))")"
    printf 'item\t%d\n'          "$item"
    printf 'item_hex\t0x%04X\n'  "$item"
    printf 'data\t%s\n'          "${hex:6:256}"
    printf 'data_len\t%d\n'      128
    printf 'status\t%d\n'        "$status"
    printf 'status_name\t%s\n'   "$(bbdg_nv_status "$status")"
}

# ------------------------------------------------------------------- §4 identity
# imxi_bcd_to_string: the LOW nibble of byte 0 is skipped, then for each byte emit the
# low nibble followed by the high nibble. A nibble above 9 is a decode FAILURE, not a
# wildcard — that is exactly how libqcdm rejects a malformed response.
bbdg_bcd_decode() {
    local hex="${1:-}" out="" i b lo hi
    bbdg_is_hex "$hex" || { printf 'not even-length hex\n' >&2; return 2; }
    for (( i = 0; i < ${#hex}; i += 2 )); do
        b=$(( 16#${hex:$i:2} ))
        hi=$(( (b >> 4) & 0xF ))
        lo=$(( b & 0xF ))
        if (( hi > 9 )); then
            printf 'non-BCD high nibble %X at byte %d\n' "$hi" "$(( i / 2 ))" >&2; return 1
        fi
        if (( i > 0 )); then
            if (( lo > 9 )); then
                printf 'non-BCD low nibble %X at byte %d\n' "$lo" "$(( i / 2 ))" >&2; return 1
            fi
            out+="$lo"
        fi
        out+="$hi"
    done
    printf '%s' "$out"
}

# IMEI check digit: Luhn, doubling every second digit counting from the right.
bbdg_luhn() {
    local s="${1:-}" total=0 i d pos=0
    case "$s" in ''|*[!0-9]*) printf 'Luhn needs digits only\n' >&2; return 2 ;; esac
    for (( i = ${#s} - 1; i >= 0; i-- )); do
        d="${s:$i:1}"
        if (( pos % 2 == 1 )); then
            d=$(( d * 2 ))
            (( d > 9 )) && d=$(( d - 9 ))
        fi
        total=$(( total + d ))
        pos=$(( pos + 1 ))
    done
    (( total % 10 == 0 ))
}

# struct DMCmdSubsysHeader = code(1) subsys_id(1) subsys_cmd(2 LE).
bbdg_subsys_build() {
    local sub="${1:-0}" cmd="${2:-0}" args="${3:-}"
    case "$sub" in ''|*[!0-9]*) printf 'subsystem id must be a decimal number\n' >&2; return 2 ;; esac
    case "$cmd" in ''|*[!0-9]*) printf 'subsystem command must be a decimal number\n' >&2; return 2 ;; esac
    (( sub >= 0 && sub <= 255 )) || { printf 'subsystem id out of range\n' >&2; return 2; }
    (( cmd >= 0 && cmd <= 65535 )) || { printf 'subsystem command out of range\n' >&2; return 2; }
    if [ -n "$args" ]; then
        bbdg_is_hex "$args" || { printf 'args must be even-length hex\n' >&2; return 2; }
    fi
    printf '4b%s%s%s' "$(bbdg_oct "$sub")" "$(bbdg_le16 "$cmd")" "$args"
}

bbdg_subsys_parse() {
    local hex="${1:-}" sub cmd
    bbdg_is_hex "$hex" || { printf 'not even-length hex\n' >&2; return 2; }
    (( ${#hex} >= 8 )) || { printf 'too short for DMCmdSubsysHeader (4 bytes)\n' >&2; return 1; }
    [ "${hex:0:2}" = "4b" ] || {
        printf 'not a DIAG_SUBSYS_CMD_F frame (code %s)\n' "${hex:0:2}" >&2; return 1; }
    sub=$(( 16#${hex:2:2} ))
    cmd="$(bbdg_u16at 2 "$hex")"
    printf 'subsys\t%d\n'         "$sub"
    printf 'subsys_name\t%s\n'    "$(bbdg_subsys_name "$sub")"
    printf 'subcmd\t%d\n'         "$cmd"
    printf 'subcmd_hex\t0x%04X\n' "$cmd"
    printf 'args\t%s\n'           "${hex:8}"
}

# The three state-info requests. Request = 4B <subsys> <cmd LE>, no args.
bbdg_state_build() {
    case "${1:-}" in
        gsm)   bbdg_subsys_build 8  1  "" ;;   # 4b 08 01 00
        wcdma) bbdg_subsys_build 4  15 "" ;;   # 4b 04 0f 00
        cm)    bbdg_subsys_build 15 0  "" ;;   # 4b 0f 00 00
        *) printf 'state kind must be gsm, wcdma or cm\n' >&2; return 2 ;;
    esac
}

# struct DMCmdVersionInfoRsp, 55 bytes. Offsets are the struct's; the field NAMES are
# the struct's. The published test asserts the bytes, not this decode (see header).
bbdg_verno_parse() {
    local hex="${1:-}" f
    bbdg_is_hex "$hex" || { printf 'not even-length hex\n' >&2; return 2; }
    (( ${#hex} == 110 )) || {
        printf 'version-info response must be 55 bytes, got %d\n' "$(( ${#hex} / 2 ))" >&2
        return 1
    }
    f="$(printf '%s' "${hex:2:22}"  | xxd -r -p 2>/dev/null)";  printf 'comp_date\t%s\n' "${f//[![:print:]]/.}"
    f="$(printf '%s' "${hex:24:16}" | xxd -r -p 2>/dev/null)";  printf 'comp_time\t%s\n' "${f//[![:print:]]/.}"
    f="$(printf '%s' "${hex:40:22}" | xxd -r -p 2>/dev/null)";  printf 'rel_date\t%s\n'  "${f//[![:print:]]/.}"
    f="$(printf '%s' "${hex:62:16}" | xxd -r -p 2>/dev/null)";  printf 'rel_time\t%s\n'  "${f//[![:print:]]/.}"
    f="$(printf '%s' "${hex:78:16}" | xxd -r -p 2>/dev/null)";  printf 'model\t%s\n'     "${f//[![:print:]]/.}"
    printf 'scm\t0x%s\n'            "${hex:94:2}"
    printf 'mob_cai_rev\t0x%s\n'    "${hex:96:2}"
    printf 'mob_model\t0x%s\n'      "${hex:98:2}"
    printf 'mob_firmware_rev\t%d\n' "$(bbdg_u16at 50 "$hex")"
    printf 'slot_cycle_index\t%d\n' "$(( 16#${hex:104:2} ))"
    printf 'msm_ver\t0x%s\n'        "${hex:106:2}"
    printf 'trailing\t0x%s\n'       "${hex:108:2}"
}

# DMCmdGsmStateInfoRsp after the 4-byte subsys header:
#   imei_len(1) imei(8) imsi_len(1) imsi(8) lai(5) cellid(2 LE)
#   cm_call_state cm_opmode cm_sysmode    -> 32 bytes total
# DMCmdWcdmaStateInfoRsp: header(4) imei_len(1) imei(8) imsi_len(1) imsi(8) l1(1)
#   -> 24 bytes total
bbdg_state_parse() {
    local hex="${1:-}" sub cmd ilen imei ims ilen2 imsi
    bbdg_is_hex "$hex" || { printf 'not even-length hex\n' >&2; return 2; }
    (( ${#hex} >= 8 )) || { printf 'too short for a subsystem state-info response\n' >&2; return 1; }
    sub=$(( 16#${hex:2:2} ))
    cmd="$(bbdg_u16at 2 "$hex")"
    printf 'subsys\t%d\n'      "$sub"
    printf 'subsys_name\t%s\n' "$(bbdg_subsys_name "$sub")"
    printf 'subcmd\t%d\n'      "$cmd"
    case "$sub" in
        8)
            (( ${#hex} == 64 )) || {
                printf 'GSM state-info response must be 32 bytes, got %d\n' "$(( ${#hex} / 2 ))" >&2
                return 1
            }
            ilen=$(( 16#${hex:8:2} ))
            printf 'imei_len\t%d\n' "$ilen"
            if (( ilen == 8 )); then
                if imei="$(bbdg_bcd_decode "${hex:10:16}")"; then
                    printf 'imei\t%s\n' "$imei"
                    if bbdg_luhn "$imei"; then printf 'imei_luhn\tvalid\n'
                    else printf 'imei_luhn\tINVALID\n'; fi
                else
                    printf 'imei\t<malformed BCD>\n'
                fi
            else
                printf 'imei\t<none>\n'
            fi
            ilen2=$(( 16#${hex:26:2} ))
            printf 'imsi_len\t%d\n' "$ilen2"
            if (( ilen2 == 8 )); then
                if imsi="$(bbdg_bcd_decode "${hex:28:16}")"; then printf 'imsi\t%s\n' "$imsi"
                else printf 'imsi\t<malformed BCD>\n'; fi
            else
                printf 'imsi\t<none>\n'
            fi
            local lai="${hex:44:10}" l0 l1 l2 l3 l4 mcc mnc mnc3 lac cid
            l0=$(( 16#${lai:0:2} )); l1=$(( 16#${lai:2:2} )); l2=$(( 16#${lai:4:2} ))
            l3=$(( 16#${lai:6:2} )); l4=$(( 16#${lai:8:2} ))
            mcc=$(( (l0 & 0xF) * 100 + ((l0 >> 4) & 0xF) * 10 + (l1 & 0xF) ))
            mnc=$(( (l2 & 0xF) * 100 + ((l2 >> 4) & 0xF) * 10 ))
            mnc3=$(( (l1 >> 4) & 0xF ))
            (( mnc3 != 0xF )) && mnc=$(( mnc + mnc3 ))
            lac=$(( l4 << 8 | l3 ))
            cid="$(bbdg_u16at 27 "$hex")"
            printf 'lai\t%s\n'    "$lai"
            printf 'mcc\t%d\n'    "$mcc"
            printf 'mnc\t%d\n'    "$mnc"
            printf 'lac\t%d\n'    "$lac"
            printf 'cellid\t%d\n' "$cid"
            printf 'cm_call_state\t%d\n' "$(( 16#${hex:58:2} ))"
            printf 'cm_opmode\t%d\n'     "$(( 16#${hex:60:2} ))"
            printf 'cm_sysmode\t%d\n'    "$(( 16#${hex:62:2} ))"
            ;;
        4)
            (( ${#hex} == 48 )) || {
                printf 'WCDMA state-info response must be 24 bytes, got %d\n' "$(( ${#hex} / 2 ))" >&2
                return 1
            }
            ilen=$(( 16#${hex:8:2} ))
            printf 'imei_len\t%d\n' "$ilen"
            if (( ilen == 8 )); then
                if imei="$(bbdg_bcd_decode "${hex:10:16}")"; then
                    printf 'imei\t%s\n' "$imei"
                    if bbdg_luhn "$imei"; then printf 'imei_luhn\tvalid\n'
                    else printf 'imei_luhn\tINVALID\n'; fi
                else
                    printf 'imei\t<malformed BCD>\n'
                fi
            else
                printf 'imei\t<none>\n'
            fi
            ilen2=$(( 16#${hex:26:2} ))
            printf 'imsi_len\t%d\n' "$ilen2"
            if (( ilen2 == 8 )); then
                if imsi="$(bbdg_bcd_decode "${hex:28:16}")"; then printf 'imsi\t%s\n' "$imsi"
                else printf 'imsi\t<malformed BCD>\n'; fi
            else
                printf 'imsi\t<none>\n'
            fi
            printf 'l1_state\t%d\n' "$(( 16#${hex:44:2} ))"
            ;;
        *)
            printf 'note\tnot a state-info subsystem response\n'
            ;;
    esac
}

# ------------------------------------------------------------------- §5 EFS2
# EFS2 rides inside DIAG_SUBSYS_CMD_F. Every request is
#   4B <subsys> <subcmd LE> <args>
# and the response carries the SAME 1+1+2 header followed by the subcommand's fields.
#
# Layouts below are transcribed from the struct format strings QCSuper sends and
# unpacks (all little-endian, no padding):
#   OPEN   req '<BHii'    oflag:4 mode:4 then path+NUL
#   OPEN   rsp '<BHIi'    fd:4 errno:4                  -> 12 bytes total
#   CLOSE  req '<BHi'     fd:4
#   CLOSE  rsp '<BHi'     errno:4                       -> 8 bytes total
#   READ   req '<BHiII'   fd:4 nbytes:4 offset:4
#   READ   rsp '<BHiIii'  fd:4 offset:4 num:4 errno:4   -> 20 bytes, then raw data
#   WRITE  req '<BHiI'    fd:4 position:4 then data
#   WRITE  rsp '<BHiIii'  fd:4 offset:4 num:4 errno:4   -> 20 bytes
#   STAT   req '<BH'      path+NUL
#   STAT   rsp '<BH7i'    errno:4 mode:4 size:4 nlink:4 atime:4 mtime:4 ctime:4
#                                                       -> 32 bytes total
#   READLINK req '<BH'    path+NUL
#   READLINK rsp '<BHI'   errno:4 then NUL-terminated target
#   HELLO  req '<BH6I3II' 6x u32 windows, 3x u32 version, u32 feature_bits
#                                                       -> 44 bytes total
# The file descriptor is a 32-bit field; an earlier revision of this module used
# a 16-bit fd and built short READ/CLOSE/WRITE frames.
#
# Source-verified request forms: HELLO, OPEN, CLOSE, READ, WRITE, STAT, READLINK.
# The remaining path-only opcodes (LSTAT, UNLINK, MKDIR, RMDIR, OPENDIR) are the
# same '<BH' + path + NUL convention as STAT and READLINK -- they are sibling
# opcodes in the EFS2 DIAG interface, but this module has not seen them built by
# an upstream implementation, so treat their frames as convention-derived.
# EFS2_DIAG_PUT (38) / EFS2_DIAG_GET (39) are NOT built here: they use a
# multi-packet protocol that no source in hand implements, and guessing it would
# put an unverified frame on the wire. Use OPEN+WRITE / OPEN+READ instead.
bbdg_efs_build() {
    local op="${1:-}" sub="${2:-19}"
    case "$sub" in ''|*[!0-9]*) printf 'subsystem must be 19 (FS) or 62 (FS_ALTERNATE)\n' >&2; return 2 ;; esac
    case "$op" in
        hello)
            # <B H 6I 3I I>: 0x00100000 x6, then 1,1,1, then 0xFFFFFFFF.
            bbdg_subsys_build "$sub" 0 \
                "000010000000100000001000000010000000100000001000010000000100000001000000ffffffff"
            ;;
        open)
            local path="${3:-}" mode="${4:-read}" oflag pathhex
            [ -n "$path" ] || { printf 'open needs a path\n' >&2; return 2; }
            case "$mode" in
                read)  oflag=0 ;;
                write) oflag=577 ;;   # 0o1101 O_WRONLY|O_CREAT|O_TRUNC
                *) printf 'open mode must be read or write\n' >&2; return 2 ;;
            esac
            pathhex="$(printf '%s' "$path" | xxd -p 2>/dev/null | tr -d '\n')"
            bbdg_subsys_build "$sub" 2 "$(bbdg_le32 "$oflag")00000000${pathhex}00"
            ;;
        close)
            bbdg_subsys_build "$sub" 3 "$(bbdg_le32 "${3:-0}")"
            ;;
        read)
            bbdg_subsys_build "$sub" 4 \
                "$(bbdg_le32 "${3:-0}")$(bbdg_le32 "${4:-1024}")$(bbdg_le32 "${5:-0}")"
            ;;
        write)
            local fd="${3:-0}" off="${4:-0}" data="${5:-}"
            bbdg_is_hex "$data" || { printf 'write data must be even-length hex\n' >&2; return 2; }
            bbdg_subsys_build "$sub" 5 "$(bbdg_le32 "$fd")$(bbdg_le32 "$off")${data}"
            ;;
        stat|lstat|unlink|mkdir|rmdir|opendir|readlink)
            local p="${3:-}" ph sc
            [ -n "$p" ] || { printf '%s needs a path\n' "$op" >&2; return 2; }
            case "$op" in
                stat)     sc=15 ;;
                lstat)    sc=16 ;;
                readlink) sc=7  ;;
                unlink)   sc=8  ;;
                mkdir)    sc=9  ;;
                rmdir)    sc=10 ;;
                opendir)  sc=11 ;;
            esac
            ph="$(printf '%s' "$p" | xxd -p 2>/dev/null | tr -d '\n')"
            bbdg_subsys_build "$sub" "$sc" "${ph}00"
            ;;
        *)
            printf 'unknown efs op %s (hello open close read write stat lstat unlink mkdir rmdir opendir readlink)\n' "$op" >&2
            return 2 ;;
    esac
}

bbdg_efs_parse() {
    local hex="${1:-}" sub cmd
    bbdg_is_hex "$hex" || { printf 'not even-length hex\n' >&2; return 2; }
    (( ${#hex} >= 8 )) || { printf 'too short for an EFS2 response\n' >&2; return 1; }
    [ "${hex:0:2}" = "4b" ] || { printf 'not a DIAG_SUBSYS_CMD_F frame\n' >&2; return 1; }
    sub=$(( 16#${hex:2:2} ))
    cmd="$(bbdg_u16at 2 "$hex")"
    printf 'subsys\t%d\n' "$sub"
    printf 'subcmd\t%d\n' "$cmd"
    case "$cmd" in
        0)
            printf 'op\thello\n'
            (( ${#hex} >= 88 )) || {
                printf 'short HELLO response (%d bytes, need 44)\n' "$(( ${#hex} / 2 ))" >&2
                return 1
            }
            printf 'targ_pkt_window\t%d\n'  "$(bbdg_u32at 4  "$hex")"
            printf 'targ_byte_window\t%d\n' "$(bbdg_u32at 8  "$hex")"
            printf 'host_pkt_window\t%d\n'  "$(bbdg_u32at 12 "$hex")"
            printf 'iter_pkt_window\t%d\n'  "$(bbdg_u32at 20 "$hex")"
            printf 'version\t%d\n'          "$(bbdg_u32at 28 "$hex")"
            printf 'min_version\t%d\n'      "$(bbdg_u32at 32 "$hex")"
            printf 'max_version\t%d\n'      "$(bbdg_u32at 36 "$hex")"
            printf 'feature_bits\t%s\n'     "${hex:80:8}"
            ;;
        2)
            printf 'op\topen\n'
            (( ${#hex} >= 24 )) || {
                printf 'short OPEN response (%d bytes, need 12)\n' "$(( ${#hex} / 2 ))" >&2
                return 1
            }
            printf 'file_fd\t%d\n' "$(bbdg_u32at 4 "$hex")"
            printf 'errno\t%d (%s)\n' "$(bbdg_u32at 8 "$hex")" "$(bbdg_efs_errno "$(bbdg_u32at 8 "$hex")")"
            ;;
        4)
            printf 'op\tread\n'
            (( ${#hex} >= 40 )) || {
                printf 'short READ response (%d bytes, need 20)\n' "$(( ${#hex} / 2 ))" >&2
                return 1
            }
            printf 'file_fd\t%d\n'  "$(bbdg_u32at 4 "$hex")"
            printf 'offset\t%d\n'   "$(bbdg_u32at 8 "$hex")"
            printf 'num_read\t%d\n' "$(bbdg_u32at 12 "$hex")"
            printf 'errno\t%d (%s)\n' "$(bbdg_u32at 16 "$hex")" "$(bbdg_efs_errno "$(bbdg_u32at 16 "$hex")")"
            printf 'data\t%s\n' "${hex:40}"
            ;;
        5)
            printf 'op\twrite\n'
            (( ${#hex} >= 40 )) || {
                printf 'short WRITE response (%d bytes, need 20)\n' "$(( ${#hex} / 2 ))" >&2
                return 1
            }
            printf 'file_fd\t%d\n'     "$(bbdg_u32at 4 "$hex")"
            printf 'offset\t%d\n'      "$(bbdg_u32at 8 "$hex")"
            printf 'num_written\t%d\n' "$(bbdg_u32at 12 "$hex")"
            printf 'errno\t%d (%s)\n'  "$(bbdg_u32at 16 "$hex")" "$(bbdg_efs_errno "$(bbdg_u32at 16 "$hex")")"
            ;;
        3)
            printf 'op\tclose\n'
            (( ${#hex} >= 16 )) || {
                printf 'short CLOSE response (%d bytes, need 8)\n' "$(( ${#hex} / 2 ))" >&2
                return 1
            }
            printf 'errno\t%d (%s)\n' "$(bbdg_u32at 4 "$hex")" "$(bbdg_efs_errno "$(bbdg_u32at 4 "$hex")")"
            ;;
        15)
            printf 'op\tstat\n'
            (( ${#hex} >= 64 )) || {
                printf 'short STAT response (%d bytes, need 32)\n' "$(( ${#hex} / 2 ))" >&2
                return 1
            }
            printf 'errno\t%d (%s)\n' "$(bbdg_u32at 4 "$hex")" "$(bbdg_efs_errno "$(bbdg_u32at 4 "$hex")")"
            printf 'mode\t0%o (%s)\n' "$(bbdg_u32at 8 "$hex")" "$(bbdg_efs_filetype "$(bbdg_u32at 8 "$hex")")"
            printf 'size\t%d\n'   "$(bbdg_u32at 12 "$hex")"
            printf 'nlink\t%d\n'  "$(bbdg_u32at 16 "$hex")"
            printf 'atime\t%d\n'  "$(bbdg_u32at 20 "$hex")"
            printf 'mtime\t%d\n'  "$(bbdg_u32at 24 "$hex")"
            printf 'ctime\t%d\n'  "$(bbdg_u32at 28 "$hex")"
            ;;
        7)
            printf 'op\treadlink\n'
            (( ${#hex} >= 16 )) || {
                printf 'short READLINK response (%d bytes, need 8)\n' "$(( ${#hex} / 2 ))" >&2
                return 1
            }
            printf 'errno\t%d (%s)\n' "$(bbdg_u32at 4 "$hex")" "$(bbdg_efs_errno "$(bbdg_u32at 4 "$hex")")"
            printf 'target\t%s\n' "$(printf '%s' "${hex:16}" | xxd -r -p 2>/dev/null | tr -d '\000')"
            ;;
        *)
            printf 'op\tsubcmd%d\n' "$cmd"
            ;;
    esac
}

# ------------------------------------------------------------------- §6 AT
# AT is a line protocol, not a frame protocol: CR-terminated and human-readable, and
# the only one here that can be exercised against a plain tty. `AT` + CR is the
# canonical probe; the response grammar is OK / ERROR / +CME ERROR: <n> / +CMS ERROR: <n>.
bbdg_at_build() {
    local cmd="${1:-AT}" term="${2:-cr}"
    case "$cmd" in *$'\n'*) printf 'AT command must not contain a newline\n' >&2; return 2 ;; esac
    printf '%s' "$cmd" | xxd -p 2>/dev/null | tr -d '\n'
    case "$term" in
        cr)   printf '0d' ;;
        crlf) printf '0d0a' ;;
        none) ;;
        *) printf 'terminator must be cr, crlf or none\n' >&2; return 2 ;;
    esac
}

bbdg_at_parse() {
    local hex="${1:-}" txt line found=0 result="unknown" errcode=""
    bbdg_is_hex "$hex" || { printf 'not even-length hex\n' >&2; return 2; }
    txt="$(printf '%s' "$hex" | xxd -r -p 2>/dev/null)"
    # A response must be terminated; an unterminated tail is a partial read, not a result.
    case "$txt" in
        *$'\r') ;;
        *) printf 'response is not CR-terminated (partial read?)\n' >&2; return 1 ;;
    esac
    while IFS= read -r line; do
        line="${line%$'\r'}"
        [ -n "$line" ] || continue
        found=1
        printf 'line\t%s\n' "$line"
        case "$line" in
            OK)            result="OK" ;;
            ERROR)         result="ERROR"; [ -n "$errcode" ] || errcode=0 ;;
            "NO CARRIER")  result="NO CARRIER"; [ -n "$errcode" ] || errcode=2 ;;
            "+CME ERROR:"*) result="CME_ERROR"; errcode="${line#+CME ERROR: }" ;;
            "+CMS ERROR:"*) result="CMS_ERROR"; errcode="${line#+CMS ERROR: }" ;;
        esac
    done <<< "$txt"
    (( found )) || { printf 'no lines in response\n' >&2; return 1; }
    printf 'result\t%s\n' "$result"
    [ -n "$errcode" ] && printf 'error_code\t%s\n' "$errcode"
    [ "$result" = "OK" ]
}

# ------------------------------------------------------------------- §7 log demux
# A DIAG byte stream is a sequence of 0x7E-delimited frames. Classification reads the
# command byte of each frame. An unrecognised command byte is reported as unknown —
# never mapped onto a plausible-looking default, because that is how a decoder starts
# lying about what it saw.
bbdg_demux() {
    local stream="${1:-}" n=0 out frame j len stop
    bbdg_is_hex "$stream" || { printf 'not even-length hex\n' >&2; return 2; }
    while [ -n "$stream" ]; do
        while [ "${stream:0:2}" = "7e" ]; do stream="${stream:2}"; done
        [ -n "$stream" ] || break
        # A raw 0x7E is always a delimiter: an escaped one travels as 7D 5E.
        j=0; len=$(( ${#stream} / 2 )); stop=-1
        while (( j < len )); do
            if [ "${stream:$(( j * 2 )):2}" = "7e" ]; then stop=$j; break; fi
            j=$(( j + 1 ))
        done
        if (( stop < 0 )); then
            printf 'truncated\tframe %d has no terminator, %d byte(s) discarded\n' \
                "$n" "$(( len - j ))"
            break
        fi
        frame="${stream:0:$(( stop * 2 ))}"
        stream="${stream:$(( (stop + 1) * 2 ))}"
        printf 'frame\t%d\n' "$n"
        if out="$(bbdg_decapsulate "${frame}7e" 2>/dev/null)"; then
            bbdg_split "$out"
            printf 'cmd\t%s\n'         "${BBDG_F[1]}"
            printf 'kind\t%s\n'        "${BBDG_F[7]}"
            printf 'payload_len\t%s\n' "${BBDG_F[11]}"
        else
            printf 'cmd\t-\n'
            printf 'kind\tinvalid\n'
            printf 'payload_len\t0\n'
        fi
        n=$(( n + 1 ))
    done
    printf 'frames\t%d\n' "$n"
}

bbdg_log_classify() {
    local code=$(( 16#${1:-00} ))
    case "$code" in
        16)  printf 'DIAG_LOG_F\tsystem log record\n' ;;
        31)  printf 'DIAG_MSG_F\tmessage log record\n' ;;
        121) printf 'DIAG_EXT_MSG_F\textended message record\n' ;;
        122) printf 'DIAG_EXT_MSG_TERSE_F\tterse extended message record\n' ;;
        115) printf 'DIAG_LOG_CONFIG_F\tlog-mask configuration request\n' ;;
        125) printf 'DIAG_EXT_MSG_CONFIG_F\trecord-mask configuration request\n' ;;
        *)   printf 'unknown\tnot classified (refusing to guess)\n' ;;
    esac
}

# ------------------------------------------------------------------- §8 audit
bbdg_audit() {
    local hex="${1:-}" out
    if ! out="$(bbdg_decapsulate "$hex" 2>/dev/null)"; then
        printf 'verdict\tUNPARSED\n'
        printf 'reason\tframe did not decapsulate (bad CRC or framing)\n'
        return 1
    fi
    bbdg_split "$out"
    local code="${BBDG_F[1]}" kind="${BBDG_F[7]}" payload="${BBDG_F[9]}"
    printf 'cmd\t%s\n' "$code"
    printf 'kind\t%s\n' "$kind"
    case "$kind" in
        identity)
            if [ "$code" = "00" ] && (( ${#payload} >= 4 )); then
                printf 'verdict\tIDENTITY-BEARING\n'
                printf 'note\tversion-info response: model and firmware strings\n'
            else
                printf 'verdict\tidentity class\n'
            fi
            ;;
        nv)   printf 'verdict\tNV-ACCESS\n'
              printf 'note\titem number and the 128-byte field are in the payload\n' ;;
        fs)   printf 'verdict\tFS-ACCESS\n' ;;
        log)  printf 'verdict\tLOG-RECORD\n' ;;
        *)    printf 'verdict\tUNCLASSIFIED\n' ;;
    esac
}

# ------------------------------------------------------------------- §9 device I/O
bbdg_ports() {
    local p found=0
    for p in /dev/ttyUSB* /dev/ttyACM* /dev/ttyS[0-9]* /dev/cdc-wdm*; do
        [ -e "$p" ] || continue
        printf '%s\n' "$p"
        found=1
    done
    (( found )) || printf 'none\n'
}

bbdg_dev_config() {
    local dev="${1:-}"
    [ -n "$dev" ] || { printf 'a device path is required\n' >&2; return 2; }
    [ -e "$dev" ] || { printf 'no such device: %s\n' "$dev" >&2; return 1; }
    # 115200 8N1 raw: DIAG is a byte stream, so no line-discipline mangling.
    stty -F "$dev" 115200 cs8 -cstopb -parenb raw -echo 2>/dev/null || {
        printf 'could not configure %s (permission or unsupported tty)\n' "$dev" >&2; return 1; }
    printf 'device\t%s\n' "$dev"
    printf 'baud\t115200\n'
    printf 'framing\t8N1 raw\n'
}

bbdg_dev_write() {
    local dev="${1:-}" hex="${2:-}"
    bbdg_is_hex "$hex" || { printf 'payload must be even-length hex\n' >&2; return 2; }
    [ -n "$dev" ] || { printf 'a device path is required\n' >&2; return 2; }
    bbdg_dev_config "$dev" >/dev/null || return 1
    printf '%s' "$hex" | xxd -r -p > "$dev" 2>/dev/null || {
        printf 'write to %s failed\n' "$dev" >&2; return 1; }
    printf 'wrote_bytes\t%d\n' "$(( ${#hex} / 2 ))"
    printf 'device\t%s\n' "$dev"
    return 0
}

# bbdg_dev_read <dev> <seconds> <max-bytes> -> hex on stdout
bbdg_dev_read() {
    local dev="${1:-}" secs="${2:-2}" max="${3:-4096}" tmp
    [ -n "$dev" ] || { printf 'a device path is required\n' >&2; return 2; }
    bbdg_dev_config "$dev" >/dev/null || return 1
    tmp="$(mktemp "$TMP_DIR/bbdg_read.XXXXXX")" || return 1
    timeout "$secs" dd if="$dev" of="$tmp" bs=1 count="$max" 2>/dev/null
    xxd -p "$tmp" 2>/dev/null | tr -d '\n'
    printf '\n'
    rm -f "$tmp"
    return 0
}

# ------------------------------------------------------------------- plan
bbdg_plan() {
    printf 'status\thandoff\n'
    printf 'module\t61_baseband_diag\n'
    printf 'target\t%s\n' "${1:-<no device attached>}"
    cat <<'PLAN'
requirement	USB cable to a Qualcomm-based handset in DIAG mode, or a modem exposing a DIAG tty
devices	/dev/ttyUSB0 (DM), /dev/ttyACM0 (QCDM), /dev/cdc-wdm0 (rmnet control)
baud	115200 8N1 raw; DIAG is a byte stream, so no line discipline
step	1. --ports to enumerate candidates
step	2. --config <dev>, then --write-hex <dev> 0078f07e (version-info request) and --read <dev> 2
step	3. --unframe <response hex>; the CRC must verify before anything is decoded
step	4. --nv-read <item> to enumerate; start at item 178 (DIAG_NV_DIR_NUMBER, the one published meaning)
step	5. --efs-hello before any EFS access; the handshake must return version 1
caveat	The repo has no serial radio and no SDR, so none of this was executed here. Nothing in this module claims a live result.
PLAN
}

# ------------------------------------------------------------------- status
bbdg_status_tsv() {
    printf 'MODULE\t61_baseband_diag\n'
    printf 'TAG\tbbdg\n'
    printf 'KIND\tno-SDR (protocol level)\n'
    printf 'TARGET\tQualcomm DM/DIAG over USB or UART\n'
    printf 'FRAMING\tready (delimit 0x7E, escape 0x7D/0x20, CRC-16/X-25)\n'
    printf 'NV\tready (read/write, 133-byte layout)\n'
    printf 'EFS2\tready (hello open close read write stat + lstat unlink mkdir rmdir opendir readlink; put/get refused)\n'
    printf 'IDENTITY\tready (version info, GSM/WCDMA/CM state info, BCD, Luhn)\n'
    printf 'AT\tready (build + response parse)\n'
    printf 'DEMUX\tready (frame split + command classification)\n'
    # Read the whole list, then take its first line. `bbdg_ports | head -1`
    # would close the pipe early and every later printf would die on EPIPE,
    # spraying "write error: Broken pipe" over the caller's stderr.
    local _ports _first
    _ports="$(bbdg_ports)"; _first="${_ports%%$'\n'*}"
    printf 'DEVICE\t%s\n' "$_first"
    printf 'KAT\tready (CRC, escaping, NV layout, version-info, negative vectors)\n'
    printf 'GATING\tnone (raw NV/EFS write primitives by design)\n'
    printf 'UNSOURCED\tLSTAT/UNLINK/MKDIR/RMDIR/OPENDIR request forms (convention-derived); PUT/GET framing; no published NV or EFS response byte vectors\n'
}

# ------------------------------------------------------------------- selftest
bbdg_selftest() {
    local d n=0 bad=0 i
    d="$(mktemp -d "$TMP_DIR/bbdg_selftest.XXXXXX")" || return 1
    trap 'rm -rf "$d"' EXIT
    LOOT_DIR="$d/loot"; CAPTURES_DIR="$d/captures"; STATE_DIR="$d/state"
    export LOOT_DIR CAPTURES_DIR STATE_DIR
    mkdir -p "$LOOT_DIR" "$CAPTURES_DIR" "$STATE_DIR"

    nchk() {  # nchk <name> <want> <got>
        n=$(( n + 1 ))
        if [ "$2" = "$3" ]; then
            printf '%-42s PASS\n' "$1"
        else
            printf '%-42s FAIL want=%s got=%s\n' "$1" "$2" "$3"
            bad=$(( bad + 1 ))
        fi
    }
    rcchk() {  # rcchk <name> <want-rc> <actual-rc>
        n=$(( n + 1 ))
        if [ "$2" = "$3" ]; then
            printf '%-42s PASS\n' "$1"
        else
            printf '%-42s FAIL want_rc=%s got_rc=%s\n' "$1" "$2" "$3"
            bad=$(( bad + 1 ))
        fi
    }
    hl() { printf '%d' "$(( ${#1} / 2 ))"; }
    # The wire is lowercase hex; the published libqcdm vectors print uppercase, so
    # catalogue comparisons are folded up rather than changing the encoder's case.
    uc() { printf '%s' "${1^^}"; }

    # ---- §1.3 CRC-16/X-25 against three independently published values
    nchk "crc-123456789-catalogue" "906E" \
        "$(uc "$(bbdg_crc16 "$(printf '123456789' | xxd -p | tr -d '\n')")")"

    # [MM] libqcdm/tests/test-qcdm-crc.c test_crc16_1: 48 bytes, expected 0x097A.
    # This doubles as test-qcdm-escaping.c's data2 (must escape to itself).
    local d2="4b0f000000000000050000000200000002000000ffffff3fff00000000000000000000000100000000000000ffffffff"
    nchk "crc-d2-len" "48" "$(hl "$d2")"
    nchk "crc-d2-value" "097A" "$(uc "$(bbdg_crc16 "$d2")")"

    # [MM] test-qcdm-crc.c test_crc16_2: the NV-read request for item 178, 0x6D69.
    # This vector is what proves the 128-byte padded data field: the CRC only agrees
    # if all 133 bytes are present.
    local nv178="26b2$(printf '0%.0s' $(seq 1 262))"
    nchk "nv178-len" "133" "$(hl "$nv178")"
    nchk "nv178-value" "6D69" "$(uc "$(bbdg_crc16 "$nv178")")"
    nchk "nv-build-matches-published" "$nv178" "$(bbdg_nv_build read 178)"

    # ---- §1.2 escaping
    nchk "escape-d2-identity" "$d2" "$(bbdg_escape "$d2")"

    # [MM] test-qcdm-escaping.c data1/expected1, inlined verbatim from the C arrays.
    local d1="70686f6e656661696c7572650a6e6f636f6e6e656374696f6e746f70686f6e650a70686f6e7e7e7e7d7d7e7d7e7d7e6e6b72657365727665640a6f7065726174696f6e6e6f74616c6c6f7765640a6f7065726174696f6e6e6f74737570706f727465640a706873696d70696e72657175697265640a70686673696d70696e72657175697265640a70686673696d70756b72657175697265640a73696d6e6f74696e7365727465640a73696d70696e72657175697265640a73696d70756b72657175697265640a73696d6661696c7572650a73696d627573790a73696d77726f6e670a696e636f727265637470617373776f72640a73696d70696e327265717569"
    local e1="70686f6e656661696c7572650a6e6f636f6e6e656374696f6e746f70686f6e650a70686f6e7d5e7d5e7d5e7d5d7d5d7d5e7d5d7d5e7d5d7d5e6e6b72657365727665640a6f7065726174696f6e6e6f74616c6c6f7765640a6f7065726174696f6e6e6f74737570706f727465640a706873696d70696e72657175697265640a70686673696d70696e72657175697265640a70686673696d70756b72657175697265640a73696d6e6f74696e7365727465640a73696d70696e72657175697265640a73696d70756b72657175697265640a73696d6661696c7572650a73696d627573790a73696d77726f6e670a696e636f727265637470617373776f72640a73696d70696e327265717569"
    nchk "escape-d1-input-len"   "256" "$(hl "$d1")"
    nchk "escape-d1-output-len"  "266" "$(hl "$e1")"
    nchk "escape-d1-exact"       "$e1" "$(bbdg_escape "$d1")"
    nchk "unescape-d1-roundtrip" "$d1" "$(bbdg_unescape "$e1")"
    # The ten-byte region, asserted literally so a regression names the right bytes.
    nchk "escape-d1-hot-region" "7d5e7d5e7d5e7d5d7d5d7d5e7d5d7d5e7d5d7d5e" \
        "$(bbdg_escape "7e7e7e7d7d7e7d7e7d7e")"
    rcchk "unescape-stray-7d-rejected" "1" "$(bbdg_unescape '7d41' >/dev/null 2>&1; echo $?)"

    # ---- §1.1 encapsulation / decapsulation
    nchk "frame-verno-request" "0078f07e" "$(bbdg_encapsulate "00")"
    nchk "frame-nv178-read" \
        "26b2$(printf '0%.0s' $(seq 1 262))696d7e" "$(bbdg_encapsulate "$nv178")"

    # [MM] test-qcdm-serial-port.c version_info_rsp — the 58-byte frame, CRC 0xC419.
    # It contains no 0x7D and no 0x7E except the trailer, so it is its own escape test.
    local v3="00417567203139203230303832303a34383a34374f6374203239203230303731393a30303a303053434e525a2e2e2e2a0604b90b0200b219c47e"
    nchk "verno-frame-len" "58" "$(hl "$v3")"
    nchk "verno-crc-in-frame" "C419" "$(uc "$(bbdg_crc16 "${v3:0:110}")")"
    local vout vbody
    if vout="$(bbdg_decapsulate "$v3")"; then
        bbdg_split "$vout"
        # body (index 15) is the decoded frame including its command byte, which is
        # what DMCmdVersionInfoRsp describes; payload (index 9) drops that byte.
        vbody="${BBDG_F[15]}"
        nchk "verno-decaps-cmd"        "00"       "${BBDG_F[1]}"
        nchk "verno-decaps-frame-kind" "identity" "${BBDG_F[7]}"
        nchk "verno-body-len"          "55"       "${BBDG_F[17]}"
        nchk "verno-decaps-crc"        "C419"     "$(uc "${BBDG_F[13]}")"
        nchk "verno-encaps-roundtrip"  "$v3"      "$(bbdg_encapsulate "$vbody")"
        nchk "verno-model-offset" "SCNRZ..." \
            "$(printf '%s' "${vbody:78:16}" | xxd -r -p 2>/dev/null)"
        nchk "verno-mob-model" "0x04" "0x${vbody:98:2}"
        nchk "verno-mob-firmware" "3001" \
            "$(bbdg_verno_parse "$vbody" | sed -n 's/^mob_firmware_rev\t//p')"
    else
        nchk "verno-decapsulates" "ok" "rejected"
    fi
    # Leading-marker tolerance: libqcdm's own test prefixes 12 x 0x7E.
    local lead=""
    for (( i = 0; i < 12; i++ )); do lead+="7e"; done
    if vout="$(bbdg_decapsulate "${lead}${v3}")"; then
        bbdg_split "$vout"
        nchk "verno-12x-leading-7e" "00" "${BBDG_F[1]}"
    else
        nchk "verno-12x-leading-7e" "00" "rejected"
    fi

    # ---- §1.1 published REJECT vectors. These are the only expected-failure byte
    # vectors in the corpus; a decoder that accepts them is not checking the CRC.
    rcchk "reject-sierra-cns" "1" \
        "$(bbdg_decapsulate "7e000a6b6d000007000000000000007e" >/dev/null 2>&1; echo $?)"
    rcchk "reject-random-data" "1" \
        "$(bbdg_decapsulate "7e7e7e6b6d7e7e7e7e000000000000007e" >/dev/null 2>&1; echo $?)"
    rcchk "reject-missing-terminator" "1" "$(bbdg_decapsulate "0078f0" >/dev/null 2>&1; echo $?)"
    rcchk "reject-short-frame" "1" "$(bbdg_decapsulate "7e007e" >/dev/null 2>&1; echo $?)"
    rcchk "reject-odd-hex" "2" "$(bbdg_decapsulate "7e007e0" >/dev/null 2>&1; echo $?)"
    rcchk "reject-empty" "2" "$(bbdg_decapsulate "" >/dev/null 2>&1; echo $?)"

    # ---- §2 command codec
    nchk "cmd-name-38" "DIAG_NV_READ_F" "$(bbdg_cmd_name 38)"
    nchk "cmd-name-39" "DIAG_NV_WRITE_F" "$(bbdg_cmd_name 39)"
    nchk "cmd-name-75" "DIAG_SUBSYS_CMD_F" "$(bbdg_cmd_name 75)"
    nchk "cmd-name-unknown-is-named" "unknown (0xEE)" "$(bbdg_cmd_name 238)"
    nchk "cmd-name-not-a-safe-default" "unknown (0xFF)" "$(bbdg_cmd_name 255)"
    nchk "frame-kind-log" "log" "$(bbdg_frame_kind 121)"
    nchk "frame-kind-unknown" "unknown" "$(bbdg_frame_kind 238)"
    nchk "subsys-name-fs" "DIAG_SUBSYS_FS (EFS2)" "$(bbdg_subsys_name 19)"
    # libqcdm's NV status enum: 0 OK, 1 BUSY, 2 BAD_COMMAND, 3 MEMORY_FULL,
    # 4 FAILED, 5 INACTIVE, 6 BAD_PARAMETER, 7 READ_ONLY.
    nchk "nv-status-4" "DM_NV_STATUS_FAILED" "$(bbdg_nv_status 4)"
    nchk "nv-status-7" "DM_NV_STATUS_READ_ONLY" "$(bbdg_nv_status 7)"
    nchk "nv-status-unknown" "unknown NV status (9)" "$(bbdg_nv_status 9)"
    nchk "efs-errno-2" "ENOENT" "$(bbdg_efs_errno 2)"

    # ---- §3 NV layout
    local nvb
    nvb="$(bbdg_nv_build read 178)"
    nchk "nv-build-read-code"    "26"   "${nvb:0:2}"
    nchk "nv-build-read-item-le" "b200" "${nvb:2:4}"
    nchk "nv-build-read-len"     "133"  "$(hl "$nvb")"
    nchk "nv-build-read-crc"     "6D69" "$(uc "$(bbdg_crc16 "$nvb")")"
    nchk "nv-build-write-code"   "27"   "$(bbdg_nv_build write 178 | cut -c1-2)"
    # nv_item is a 16-bit field, so byte 0 of the payload is the code, bytes 1-2 the
    # item, then the 128-byte data field: "26 b2 00 aa bb".
    nchk "nv-build-read-data-align"  "26b200aa" "$(bbdg_nv_build read  178 aabb | cut -c1-8)"
    nchk "nv-build-write-data-align" "27b200aa" "$(bbdg_nv_build write 178 aabb | cut -c1-8)"
    rcchk "nv-build-rejects-bad-item"   "2" "$(bbdg_nv_build read 99999 >/dev/null 2>&1; echo $?)"
    rcchk "nv-build-rejects-empty-item" "2" "$(bbdg_nv_build read '' >/dev/null 2>&1; echo $?)"
    rcchk "nv-build-rejects-bad-op"     "2" "$(bbdg_nv_build frobnicate 1 >/dev/null 2>&1; echo $?)"
    rcchk "nv-build-rejects-oversize"   "2" \
        "$(bbdg_nv_build write 1 "$(printf 'aa%.0s' $(seq 1 129))" >/dev/null 2>&1; echo $?)"
    # Round trip: a response carrying status 4 must decode to that, not to a default.
    # 133 bytes = code(1) + nv_item(2) + data(128) + status(2).
    local nvr="26b2$(printf '0%.0s' $(seq 1 258))0400" nvout
    nchk "nv-parse-input-len" "133" "$(hl "$nvr")"
    nvout="$(bbdg_nv_parse "$nvr")"
    bbdg_split "$nvout"
    # keys: code(0) code_name(1) item(2) item_hex(3) data(4) data_len(5) status(6) status_name(7)
    nchk "nv-parse-item"        "178"                "${BBDG_F[5]}"
    nchk "nv-parse-item-hex"    "0x00B2"             "${BBDG_F[7]}"
    nchk "nv-parse-data-len"    "128"                "${BBDG_F[11]}"
    nchk "nv-parse-status"      "4"                  "${BBDG_F[13]}"
    nchk "nv-parse-status-name" "DM_NV_STATUS_FAILED" "${BBDG_F[15]}"
    rcchk "nv-parse-rejects-short" "1" "$(bbdg_nv_parse "26b200" >/dev/null 2>&1; echo $?)"
    rcchk "nv-parse-rejects-odd"   "2" "$(bbdg_nv_parse "26b20" >/dev/null 2>&1; echo $?)"

    # ---- §4 identity
    # BCD: byte 0 contributes only its HIGH nibble (d0), then byte i contributes
    # low nibble (d_2i-1) then high nibble (d_2i). So the Luhn-valid IMEI
    # 353325060462136 packs to 30 35 23 05 06 64 12 63.
    nchk "bcd-decode-imei" "353325060462136" "$(bbdg_bcd_decode "3035230506641263")"
    nchk "bcd-decode-imsi" "310150123456789" "$(bbdg_bcd_decode "3001511032547698")"
    rcchk "bcd-rejects-non-bcd-high" "1" "$(bbdg_bcd_decode "30fa" >/dev/null 2>&1; echo $?)"
    rcchk "bcd-rejects-non-bcd-low"  "1" "$(bbdg_bcd_decode "30fa1234" >/dev/null 2>&1; echo $?)"
    rcchk "luhn-valid-imei"        "0" "$(bbdg_luhn "353325060462136" >/dev/null 2>&1; echo $?)"
    rcchk "luhn-invalid-imei"      "1" "$(bbdg_luhn "353325060462131" >/dev/null 2>&1; echo $?)"
    rcchk "luhn-second-valid"      "0" "$(bbdg_luhn "490154203237518" >/dev/null 2>&1; echo $?)"
    rcchk "luhn-rejects-nondigits" "2" "$(bbdg_luhn "abc" >/dev/null 2>&1; echo $?)"

    # State-info requests (DMCmdSubsysHeader, little-endian subcommand).
    nchk "state-build-gsm"   "4b080100" "$(bbdg_state_build gsm)"
    nchk "state-build-wcdma" "4b040f00" "$(bbdg_state_build wcdma)"
    nchk "state-build-cm"    "4b0f0000" "$(bbdg_state_build cm)"
    nchk "subsys-build-envelope"  "4b080100" "$(bbdg_subsys_build 8 1 '')"
    nchk "subsys-parse-subcmd-le" "1" "$(bbdg_subsys_parse "4b080100" | sed -n 's/^subcmd\t//p')"
    rcchk "subsys-parse-rejects-non-subsys" "1" \
        "$(bbdg_subsys_parse "26b200000000" >/dev/null 2>&1; echo $?)"

    # A synthetic GSM state-info response, placed field by field at its offsets so a
    # layout regression changes a decoded value.
    local gsm="4b080100"          # header
    gsm+="08"                     # imei_len
    gsm+="3035230506641263"       # imei BCD -> 353325060462136 (Luhn-valid)
    gsm+="08"                     # imsi_len
    gsm+="3001511032547698"       # imsi BCD -> 310150123456789
    gsm+="1300513412"             # lai: MCC 310, MNC 150, LAC 0x1234
    gsm+="efbe"                   # cellid 0xBEEF little-endian
    gsm+="000001"                 # call state, opmode, sysmode(GSM)
    nchk "gsm-state-len" "32" "$(hl "$gsm")"
    local gout
    gout="$(bbdg_state_parse "$gsm")"
    bbdg_split "$gout"
    # keys: subsys(0) subsys_name(1) subcmd(2) imei_len(3) imei(4) imei_luhn(5)
    #       imsi_len(6) imsi(7) lai(8) mcc(9) mnc(10) lac(11) cellid(12) ...
    nchk "gsm-state-subsys"    "8"               "${BBDG_F[1]}"
    nchk "gsm-state-imei-len"  "8"               "${BBDG_F[7]}"
    nchk "gsm-state-imei"      "353325060462136" "${BBDG_F[9]}"
    nchk "gsm-state-imei-luhn" "valid"           "${BBDG_F[11]}"
    nchk "gsm-state-imsi-len"  "8"               "${BBDG_F[13]}"
    nchk "gsm-state-imsi"      "310150123456789" "${BBDG_F[15]}"
    nchk "gsm-state-mcc"       "310"             "${BBDG_F[19]}"
    nchk "gsm-state-mnc"       "150"             "${BBDG_F[21]}"
    nchk "gsm-state-lac"       "4660"            "${BBDG_F[23]}"
    nchk "gsm-state-cellid"    "48879"           "${BBDG_F[25]}"
    rcchk "state-parse-rejects-short" "1" "$(bbdg_state_parse "4b080100" >/dev/null 2>&1; echo $?)"
    rcchk "state-parse-rejects-wrong-len" "1" \
        "$(bbdg_state_parse "4b080100083035230506641236" >/dev/null 2>&1; echo $?)"
    # A response with a non-BCD nibble must be reported malformed, never coerced.
    nchk "gsm-state-bad-bcd-reports-malformed" "<malformed BCD>" \
        "$(bbdg_state_parse "4b0801000830352305066412360830fa5110325476981300513412efbe000001" \
            2>/dev/null | sed -n 's/^imsi\t//p')"

    # ---- §5 EFS2
    nchk "efs-hello-envelope" "4b130000" "$(bbdg_efs_build hello 19 | cut -c1-8)"
    nchk "efs-hello-len"      "44"       "$(hl "$(bbdg_efs_build hello 19)")"
    nchk "efs-hello-window"   "00001000" "$(bbdg_efs_build hello 19 | cut -c9-16)"
    nchk "efs-open-read-oflag"  "4b13020000000000" "$(bbdg_efs_build open 19 /nv/item_files read | cut -c1-16)"
    nchk "efs-open-write-oflag" "41020000" "$(bbdg_efs_build open 19 /x write | cut -c9-16)"
    nchk "efs-open-path-hex"    "2f78"     "$(bbdg_efs_build open 19 /x read | cut -c25-28)"
    nchk "efs-open-path-nul"    "00"       "$(bbdg_efs_build open 19 /x read | tail -c 2)"
    nchk "efs-read-layout" "4b130400000000000004000000000000" "$(bbdg_efs_build read 19 0 1024 0)"
    nchk "efs-close-layout" "4b13030000000000" "$(bbdg_efs_build close 19 0)"
    nchk "efs-write-layout" "4b1305000000000000000000aabb" "$(bbdg_efs_build write 19 0 0 aabb)"
    nchk "efs-alt-subsys"    "3e"   "$(bbdg_efs_build hello 62 | cut -c3-4)"
    nchk "efs-stat-subcmd"   "0f00" "$(bbdg_efs_build stat 19 /x | cut -c5-8)"
    nchk "efs-unlink-subcmd" "0800" "$(bbdg_efs_build unlink 19 /x | cut -c5-8)"
    nchk "efs-readlink-subcmd" "0700" "$(bbdg_efs_build readlink 19 /x | cut -c5-8)"
    nchk "efs-mkdir-subcmd"  "0900" "$(bbdg_efs_build mkdir 19 /x | cut -c5-8)"
    rcchk "efs-rejects-bad-op"   "2" "$(bbdg_efs_build frobnicate 19 >/dev/null 2>&1; echo $?)"
    rcchk "efs-rejects-bad-path" "2" "$(bbdg_efs_build open 19 '' >/dev/null 2>&1; echo $?)"
    # EFS2_DIAG_PUT/GET are a multi-packet protocol no source in hand implements, so
    # this module must refuse to emit a guessed frame for them.
    rcchk "efs-refuses-put" "2" "$(bbdg_efs_build put 19 /x >/dev/null 2>&1; echo $?)"
    rcchk "efs-refuses-get" "2" "$(bbdg_efs_build get 19 /x >/dev/null 2>&1; echo $?)"
    # Hand-built responses with the sourced layouts (fd is a 32-bit field).
    nchk "efs-parse-open-fd"    "3" "$(bbdg_efs_parse "4b130200030000000000000000" | sed -n 's/^file_fd\t//p')"
    nchk "efs-parse-open-errno" "ENOENT" \
        "$(bbdg_efs_parse "4b1302000300000002000000" | sed -n 's/^errno\t[0-9]* (\(.*\))$/\1/p')"
    nchk "efs-parse-close-errno" "OK" \
        "$(bbdg_efs_parse "4b13030000000000" | sed -n 's/^errno\t[0-9]* (\(.*\))$/\1/p')"
    # READ: fd 3, offset 0, num_read 4, errno 0, data aabbccdd
    local eresp="4b13040003000000000000000400000000000000aabbccdd"
    nchk "efs-parse-read-fd"   "3" "$(bbdg_efs_parse "$eresp" | sed -n 's/^file_fd\t//p')"
    nchk "efs-parse-read-num"  "4" "$(bbdg_efs_parse "$eresp" | sed -n 's/^num_read\t//p')"
    nchk "efs-parse-read-data" "aabbccdd" "$(bbdg_efs_parse "$eresp" | sed -n 's/^data\t//p')"
    # STAT: errno 0, mode 0o100777, size 4096, nlink 1, times 0
    nchk "efs-parse-stat-type" "Regular file (S_IFREG)" \
        "$(bbdg_efs_parse "4b130f0000000000ff8100000010000001000000000000000000000000000000" \
           | sed -n 's/^mode\t[^ ]* (\(.*\))$/\1/p')"
    # READLINK: errno 0, target "/nv\0"
    nchk "efs-parse-readlink-target" "/nv" \
        "$(bbdg_efs_parse "4b130700000000002f6e7600" | sed -n 's/^target\t//p')"
    rcchk "efs-parse-rejects-short" "1" "$(bbdg_efs_parse "4b1302" >/dev/null 2>&1; echo $?)"
    rcchk "efs-parse-rejects-non-subsys" "1" "$(bbdg_efs_parse "26000000" >/dev/null 2>&1; echo $?)"

    # ---- §6 AT
    nchk "at-build-probe"     "41540d"   "$(bbdg_at_build AT)"
    nchk "at-build-crlf"      "41540d0a" "$(bbdg_at_build AT crlf)"
    nchk "at-build-lowercase" "61740d"   "$(bbdg_at_build at)"
    rcchk "at-build-rejects-newline" "2" "$(bbdg_at_build "$(printf 'AT\nAT')" >/dev/null 2>&1; echo $?)"
    nchk "at-parse-ok-result" "OK" "$(bbdg_at_parse "4f4b0d" | sed -n 's/^result\t//p')"
    rcchk "at-parse-ok"    "0" "$(bbdg_at_parse "4f4b0d" >/dev/null 2>&1; echo $?)"
    rcchk "at-parse-error" "1" "$(bbdg_at_parse "4552524f520d" >/dev/null 2>&1; echo $?)"
    nchk "at-parse-multiline" "OK" \
        "$(bbdg_at_parse "$(printf 'ATE0\r\r\nOK\r' | xxd -p | tr -d '\n')" | sed -n 's/^result\t//p')"
    nchk "at-parse-cme-code" "10" \
        "$(bbdg_at_parse "$(printf '+CME ERROR: 10\r' | xxd -p | tr -d '\n')" | sed -n 's/^error_code\t//p')"
    nchk "at-parse-cms-code" "500" \
        "$(bbdg_at_parse "$(printf '+CMS ERROR: 500\r' | xxd -p | tr -d '\n')" | sed -n 's/^error_code\t//p')"
    rcchk "at-parse-unterminated-rejected" "1" "$(bbdg_at_parse "4f4b" >/dev/null 2>&1; echo $?)"
    rcchk "at-parse-empty-rejected"        "1" "$(bbdg_at_parse "0d" >/dev/null 2>&1; echo $?)"

    # ---- §7 demux + log classification
    nchk "log-classify-ext-msg"    "DIAG_EXT_MSG_F"    "$(bbdg_log_classify 79 | cut -f1)"
    nchk "log-classify-log-config" "DIAG_LOG_CONFIG_F" "$(bbdg_log_classify 73 | cut -f1)"
    nchk "log-classify-unknown-refuses" "unknown"      "$(bbdg_log_classify ee | cut -f1)"
    # Two valid frames back to back must demux to two frames, not one.
    local two="0078f07e${v3}"
    nchk "demux-two-frames"  "2"        "$(bbdg_demux "$two" | sed -n 's/^frames\t//p')"
    nchk "demux-first-cmd"   "00"       "$(bbdg_demux "$two" | sed -n 's/^cmd\t//p' | sed -n '1p')"
    nchk "demux-second-kind" "identity" "$(bbdg_demux "$two" | sed -n 's/^kind\t//p' | sed -n '2p')"
    # A good frame followed by a bad one: both must be reported, the bad one as invalid.
    nchk "demux-good-then-invalid" "2" \
        "$(bbdg_demux "0078f07e000a6b6d000007000000000000007e" | sed -n 's/^frames\t//p')"
    nchk "demux-invalid-marked" "invalid" \
        "$(bbdg_demux "0078f07e000a6b6d000007000000000000007e" | sed -n 's/^kind\t//p' | sed -n '2p')"

    # ---- §8 audit
    nchk "audit-verno-identity" "IDENTITY-BEARING" "$(bbdg_audit "$v3" | sed -n 's/^verdict\t//p')"
    nchk "audit-nv-access" "NV-ACCESS" \
        "$(bbdg_audit "$(bbdg_encapsulate "$nv178")" | sed -n 's/^verdict\t//p')"
    nchk "audit-unparsed" "UNPARSED" \
        "$(bbdg_audit "7e000a6b6d000007000000000000007e" | sed -n 's/^verdict\t//p')"

    # ---- §9 device layer (no device required)
    nchk "ports-runs" "0" "$(bbdg_ports >/dev/null 2>&1; echo $?)"
    rcchk "config-rejects-missing-device" "1" \
        "$(bbdg_dev_config /dev/definitely-not-a-device >/dev/null 2>&1; echo $?)"
    rcchk "config-rejects-empty-device" "2" "$(bbdg_dev_config '' >/dev/null 2>&1; echo $?)"
    rcchk "write-rejects-bad-hex"       "2" "$(bbdg_dev_write /dev/null zz >/dev/null 2>&1; echo $?)"
    rcchk "read-rejects-empty-device"   "2" "$(bbdg_dev_read '' 1 >/dev/null 2>&1; echo $?)"

    # ---- plan + status
    nchk "plan-status" "handoff" "$(bbdg_plan | sed -n 's/^status\t//p')"
    nchk "status-module" "61_baseband_diag" "$(bbdg_status_tsv | sed -n 's/^MODULE\t//p')"
    nchk "status-no-gating" "none (raw NV/EFS write primitives by design)" \
        "$(bbdg_status_tsv | sed -n 's/^GATING\t//p')"

    printf 'ASSERTIONS\t%d\n' "$n"
    if (( bad > 0 )); then printf 'RESULT\tFAIL(%d)\n' "$bad"; return 1; fi
    printf 'RESULT\tPASS\n'
    return 0
}

# ------------------------------------------------------------------- menu
bbdg_menu() {
    cat <<'MENU'
61_baseband_diag — Qualcomm DM/DIAG (no SDR; a cable is needed for the live path)
  [1]  Status                  - what is ready, what needs a cable
  [2]  Framing KATs            - CRC / escape / frame vectors
  [3]  Ports                   - enumerate candidate DIAG ttys
  [4]  Configure a device      - 115200 8N1 raw
  [5]  Version info request    - build, send, classify the response
  [6]  NV read                 - build a 133-byte read (item 178 is the known one)
  [7]  NV parse                - decode a 133-byte NV response
  [8]  EFS2 hello              - handshake before any file access
  [9]  EFS2 read               - OPEN + READ for a path
  [10] EFS2 write              - OPEN + WRITE for a path
  [11] Identity                - GSM/WCDMA/CM state info
  [12] AT probe                - build AT and parse the response grammar
  [13] Demux a capture         - split a DIAG byte stream into frames
  [14] Audit                   - classify one frame and say what it exposes
  [15] Plan                    - the handoff, naming the exact device
MENU
}

# ------------------------------------------------------------------- CLI
bbdg_usage() {
    cat <<'USAGE'
61_baseband_diag — Qualcomm DM/DIAG protocol surface (tag: bbdg)

Framing
  --selftest                       run the known-answer assertions
  --status                         TSV status
  --menu                           interactive menu
  --kat                            print the framing KATs as TSV
  --crc <hex>                      CRC-16/X-25 over the bytes (prints lowercase)
  --escape <hex>                   escape a payload
  --unescape <hex>                 unescape a payload
  --frame <hex>                    encapsulate a payload into a frame
  --unframe <hex>                  decapsulate a frame to TSV
  --demux <hex>                    split a DIAG stream into frames
  --cmd-name <dec>                 name a DIAG command code
  --log-classify <hex>             classify a log/config command byte

NV
  --nv-build <read|write> <item> [data-hex]
  --nv-read <item>                 build a 133-byte read request
  --nv-write <item> [data-hex]     build a 133-byte write request
  --nv-parse <hex>                 decode a 133-byte NV response
  --nv-scan                        the NV item discovery plan (needs a cable)

Identity
  --state-build <gsm|wcdma|cm>     build a state-info request
  --state <hex>                    decode a state-info response
  --state-info <gsm|wcdma|cm>      build + plan the round trip
  --verno                          build the version-info request frame
  --verno-parse <hex>              decode a 55-byte version-info response
  --bcd <hex>                      decode an IMEI/IMSI BCD field
  --luhn <digits>                  IMEI check digit (exit 0 valid, 1 invalid)

EFS
  --efs-hello [subsys]             EFS2 hello (19 = FS, 62 = FS_ALTERNATE)
  --efs-open <path> <read|write>   build an OPEN
  --efs-read <path>                build OPEN + READ
  --efs-write <path> [data-hex]    build OPEN + WRITE
  --efs-stat <path>                build a STAT
  --efs-parse <hex>                decode an EFS2 response
  --efs-walk <path>                the EFS discovery plan (needs a cable)
    EFS2 builders also accept: lstat unlink mkdir rmdir opendir readlink.
    PUT(38)/GET(39) are refused: their multi-packet framing is unverified here.

AT
  --at [command] [cr|crlf|none]    build an AT command
  --at-parse <hex>                 parse an AT response (exit 0 only on OK)

Device
  --ports                          enumerate candidate devices
  --config <dev>                   115200 8N1 raw
  --write-hex <dev> <hex>          write raw bytes
  --read <dev> [seconds] [max]     read raw bytes as hex
  --audit <hex>                    classify a frame and report what it exposes
  --plan [dev]                     the handoff plan
  --guard-check                    report any silent failure path

Scope: protocol-level, no RF. Nothing here is gated; --nv-write and --efs-write are
raw primitives. --plan names the cable the live path needs.
USAGE
}

bbdg_print_kats() {
    printf 'name\tvalue\tsource\n'
    printf 'crc-check\t906E\tCRC-16/X-25 catalogue, crc16("123456789")\n'
    printf 'crc-d2\t097A\tlibqcdm test-qcdm-crc.c test_crc16_1 (48-byte subsystem request)\n'
    printf 'crc-nv178\t6D69\tlibqcdm test-qcdm-crc.c test_crc16_2 (133-byte NV read, item 178)\n'
    printf 'crc-verno\tC419\tlibqcdm test-qcdm-serial-port.c version_info_rsp (58-byte frame)\n'
    printf 'verno-request\t0078f07e\tpayload 0x00, CRC 0xF078\n'
    printf 'nv178-request\t26b2..00 696d 7e\tbbdg_nv_build read 178, escaped\n'
    printf 'escape-hot\t7d5e7d5e7d5e7d5d7d5d7d5e7d5d7d5e7d5d7d5e\t7e7e7e7d7d7e7d7e7d7e escaped (libqcdm data1 bytes 37..46)\n'
    printf 'escape-identity\t4b0f0000..ffffffff\t48-byte vector that must escape to itself\n'
    printf 'reject-sierra\t7e000a6b6d000007000000000000007e\tlibqcdm test_sierra_cns_rejected (must be rejected)\n'
    printf 'reject-random\t7e7e7e6b6d7e7e7e7e000000000000007e\tlibqcdm test_random_data_rejected (must be rejected)\n'
    printf 'leading-markers\t12 x 7e + version_info_rsp\tlibqcdm test_leading_frame_markers (must still decode)\n'
}

bbdg_guard_check() {
    local bad=0
    # No verb may accept a value it is supposed to reject, and none may fail silently.
    if bbdg_decapsulate "7e000a6b6d000007000000000000007e" >/dev/null 2>&1; then
        printf 'silent-fail\t--unframe accepted a published reject vector\n'; bad=$(( bad + 1 ))
    fi
    if bbdg_decapsulate "7e7e7e6b6d7e7e7e7e000000000000007e" >/dev/null 2>&1; then
        printf 'silent-fail\t--unframe accepted the random-data reject vector\n'; bad=$(( bad + 1 ))
    fi
    if bbdg_nv_build read 99999 >/dev/null 2>&1; then
        printf 'silent-fail\t--nv-read accepted an out-of-range item\n'; bad=$(( bad + 1 ))
    fi
    if bbdg_luhn "353325060462131" >/dev/null 2>&1; then
        printf 'silent-fail\t--luhn reported an invalid IMEI as valid\n'; bad=$(( bad + 1 ))
    fi
    if bbdg_bcd_decode "30fa" >/dev/null 2>&1; then
        printf 'silent-fail\t--bcd accepted a non-BCD nibble\n'; bad=$(( bad + 1 ))
    fi
    if bbdg_at_parse "4f4b" >/dev/null 2>&1; then
        printf 'silent-fail\t--at-parse accepted an unterminated response\n'; bad=$(( bad + 1 ))
    fi
    if bbdg_efs_build open 19 '' >/dev/null 2>&1; then
        printf 'silent-fail\t--efs-open accepted an empty path\n'; bad=$(( bad + 1 ))
    fi
    if bbdg_subsys_parse "26000000" >/dev/null 2>&1; then
        printf 'silent-fail\t--subsys accepted a non-subsystem frame\n'; bad=$(( bad + 1 ))
    fi
    if (( bad > 0 )); then printf 'guard-check\tFAIL(%d)\n' "$bad"; return 1; fi
    printf 'guard-check\tclean\n'
    return 0
}

bbdg_cli_main() {
    local a1="${1:-}"
    case "$a1" in
        ""|-h|--help|help) bbdg_usage; return 0 ;;
        --selftest)    bbdg_selftest; return $? ;;
        --status)      bbdg_status_tsv; return 0 ;;
        --menu)        bbdg_menu; return 0 ;;
        --kat)         bbdg_print_kats; return 0 ;;
        --plan)        bbdg_plan "${2:-}"; return 0 ;;
        --ports)       bbdg_ports; return 0 ;;
        --guard-check) bbdg_guard_check; return $? ;;
        --crc)         shift; bbdg_is_hex "${1:-}" || { printf 'need even-length hex\n' >&2; return 2; }
                       bbdg_crc16 "${1:-}"; printf '\n'; return 0 ;;
        --escape)      shift; bbdg_is_hex "${1:-}" || { printf 'need even-length hex\n' >&2; return 2; }
                       bbdg_escape "${1:-}"; printf '\n'; return 0 ;;
        --unescape)    shift; bbdg_is_hex "${1:-}" || { printf 'need even-length hex\n' >&2; return 2; }
                       bbdg_unescape "${1:-}"; printf '\n'; return 0 ;;
        --frame)       shift; bbdg_encapsulate "${1:-}"; printf '\n'; return $? ;;
        --unframe)     shift; bbdg_decapsulate "${1:-}"; return $? ;;
        --demux)       shift; bbdg_demux "${1:-}"; return $? ;;
        --subsys)      shift; bbdg_subsys_build "${1:-0}" "${2:-0}" "${3:-}"; printf '\n'; return $? ;;
        --subsys-parse) shift; bbdg_subsys_parse "${1:-}"; return $? ;;
        --cmd-name)    shift; bbdg_cmd_name "${1:-0}"; printf '\n'; return 0 ;;
        --log-classify) shift; bbdg_log_classify "${1:-00}"; return 0 ;;
        --nv-build)    shift; bbdg_nv_build "${1:-}" "${2:-}" "${3:-}"; printf '\n'; return $? ;;
        --nv-read)     shift; bbdg_nv_build read "${1:-}" ""; printf '\n'; return $? ;;
        --nv-write)    shift; bbdg_nv_build write "${1:-}" "${2:-}"; printf '\n'; return $? ;;
        --nv-parse)    shift; bbdg_nv_parse "${1:-}"; return $? ;;
        --nv-scan)
            printf 'status\thandoff\n'
            printf 'step\tPower on the handset in DIAG mode and attach the cable\n'
            printf 'step\t--write-hex <dev> 0078f07e then --read <dev> 2 to confirm framing\n'
            printf 'step\t--nv-read <item> for each candidate item, then --nv-parse the response\n'
            printf 'known\titem 178 = DIAG_NV_DIR_NUMBER (the only item with a published meaning)\n'
            printf 'caveat\tNo published NV item-to-semantics table exists; discovery is the point\n'
            return 0 ;;
        --state-build) shift; bbdg_state_build "${1:-}"; printf '\n'; return $? ;;
        --state)       shift; bbdg_state_parse "${1:-}"; return $? ;;
        --state-info)
            shift
            printf 'request\t%s\n' "$(bbdg_state_build "${1:-gsm}")"
            printf 'status\thandoff\n'
            printf 'step\tSend the request over the configured tty, then --state <response>\n'
            return 0 ;;
        --verno)       bbdg_encapsulate "00"; printf '\n'; return $? ;;
        --verno-parse) shift; bbdg_verno_parse "${1:-}"; return $? ;;
        --bcd)         shift; bbdg_bcd_decode "${1:-}"; printf '\n'; return $? ;;
        --luhn)        shift
                       if bbdg_luhn "${1:-}"; then printf 'valid\n'; return 0
                       else printf 'INVALID\n'; return 1; fi ;;
        --efs-hello)   shift; bbdg_efs_build hello "${1:-19}"; printf '\n'; return $? ;;
        --efs-open)    shift; bbdg_efs_build open "${3:-19}" "${1:-}" "${2:-read}"; printf '\n'; return $? ;;
        --efs-read)
            shift
            local p="${1:-}"
            printf 'open\t%s\n' "$(bbdg_efs_build open 19 "$p" read)"
            printf 'read\t%s\n' "$(bbdg_efs_build read 19 0 1024 0)"
            printf 'status\thandoff\n'
            printf 'note\tOPEN must return a valid fd before READ is issued\n'
            return 0 ;;
        --efs-write)
            shift
            local p="${1:-}" dat="${2:-}"
            printf 'open\t%s\n'  "$(bbdg_efs_build open 19 "$p" write)"
            printf 'write\t%s\n' "$(bbdg_efs_build write 19 0 0 "$dat")"
            printf 'status\thandoff\n'
            printf 'note\tOPEN with O_WRONLY|O_CREAT|O_TRUNC (0o1101), then WRITE, then CLOSE\n'
            return 0 ;;
        --efs-stat)    shift; bbdg_efs_build stat 19 "${1:-}"; printf '\n'; return $? ;;
        --efs-parse)   shift; bbdg_efs_parse "${1:-}"; return $? ;;
        --efs-walk)
            printf 'status\thandoff\n'
            printf 'step\t--efs-hello, then OPEN a directory and READDIR (subcmd 12)\n'
            printf 'caveat\tNo published EFS byte vector exists in any implementation; OPEN/READ/WRITE/CLOSE layouts come from QCSuper and are unverified against a device\n'
            return 0 ;;
        --at)          shift; bbdg_at_build "${1:-AT}" "${2:-cr}"; printf '\n'; return $? ;;
        --at-parse)    shift; bbdg_at_parse "${1:-}"; return $? ;;
        --config)      shift; bbdg_dev_config "${1:-}"; return $? ;;
        --write-hex|--write) shift; bbdg_dev_write "${1:-}" "${2:-}"; return $? ;;
        --read)        shift; bbdg_dev_read "${1:-}" "${2:-2}" "${3:-4096}"; return $? ;;
        --audit)       shift; bbdg_audit "${1:-}"; return $? ;;
        *) printf 'unknown option: %s\n' "$a1" >&2; bbdg_usage >&2; return 2 ;;
    esac
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    bbdg_cli_main "$@"
    exit $?
fi
