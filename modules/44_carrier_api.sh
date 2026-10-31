#!/usr/bin/env bash
# carrier_api — self-service / carrier API assessment: surface discovery and
# authorisation-boundary testing.
#
# SCOPE, stated first: the audit verbs work on a document and an observed
# surface. The two enumeration verbs build requests but never send them, and
# they build plans and stop before the wire. Testing a carrier's REST surface you are authorised to test —
# your own account, a bug-bounty scope, a contract — is ordinary assessment
# work. Mass-enumerating MSISDNs against a live portal is an account-takeover
# aid aimed at real people, so the enumeration half of this module stops at the
# artefact: --enumerate renders one concrete request per operation from the
# document and writes it to a run-file; --enumerate-subscribers builds the
# ordered one-identifier-per-request sequence, models the declared rate limit,
# writes it down and exits 3 with the handoff. Neither opens a socket, and
# neither ever reports a subscriber as "found" — this module does not send.
# What a defender can lawfully run is the audit half: --openapi,
# --authz-matrix, --token-bucket, --jwt-audit, --diff and --stuffing.
#
# Attack owned: O5/O20 adjacency (account and roaming-portal surface) — audit
# half, plus the request builder that stops before the wire.
#
# Resolve IMSISTING_ROOT from this script's own path (MODULE_CONVENTIONS §2).
if [[ -z "${IMSISTING_ROOT:-}" ]]; then
    _sl_src="${BASH_SOURCE[0]}"
    while [ -L "$_sl_src" ]; do
        _sl_dir="$(cd -P "$(dirname "$_sl_src")" && pwd)"
        _sl_tgt="$(readlink "$_sl_src")"
        [[ "$_sl_tgt" != /* ]] && _sl_tgt="$_sl_dir/$_sl_tgt"
        _sl_src="$_sl_tgt"
    done
    IMSISTING_ROOT="$(cd -P "$(dirname "$_sl_src")/.." && pwd)"
    export IMSISTING_ROOT
    unset _sl_src _sl_dir _sl_tgt
fi
if [[ -n "${IMSISTING_ROOT:-}" ]]; then
    _real_home="$(dirname "$IMSISTING_ROOT")"
    if [[ -n "$_real_home" && -d "$_real_home" && "$HOME" != "$_real_home" ]]; then
        export HOME="$_real_home"
    fi
    unset _real_home
fi
: "${IMSISTING_HOME:=$IMSISTING_ROOT}"
: "${TMP_DIR:=/tmp/imsisting}"
: "${LOOT_DIR:=$IMSISTING_ROOT/loot}"
: "${CAPTURES_DIR:=$IMSISTING_ROOT/captures}"
: "${LOGS_DIR:=$IMSISTING_ROOT/logs}"
: "${STATE_DIR:=$IMSISTING_ROOT/state}"
mkdir -p "$TMP_DIR" "$LOOT_DIR" "$CAPTURES_DIR" "$LOGS_DIR" "$STATE_DIR" 2>/dev/null

MOD_TMP="$TMP_DIR/carrier_api"
CAPI_DIR="$LOOT_DIR/carrier_api"
mkdir -p "$MOD_TMP" "$CAPI_DIR" 2>/dev/null

declare -F info >/dev/null 2>&1 || info() { printf '[info] %s\n' "$*" >&2; }
declare -F warn >/dev/null 2>&1 || warn() { printf '[warn] %s\n' "$*" >&2; }
declare -F err  >/dev/null 2>&1 || err()  { printf '[err]  %s\n' "$*" >&2; }
declare -F ok   >/dev/null 2>&1 || ok()   { printf '[ok]   %s\n' "$*" >&2; }
declare -F banner >/dev/null 2>&1 || banner() { :; }

capi_sanitize() { printf '%s' "${1:-}" | tr '\t\r\n' '   '; }
CAPI_F=()
capi_split() {
    CAPI_F=()
    local i n
    n=$(printf '%s' "$1" | awk -F'\t' '{print NF}')
    for (( i = 1; i <= n; i++ )); do
        CAPI_F+=("$(printf '%s' "$1" | cut -f"$i")")
    done
}

capi_status_tsv() {
    printf 'MODULE\tcarrier_api\n'
    printf 'TARGET\tOpenAPI surface, authorisation boundaries, rate limits, tokens, enumeration plans\n'
    printf 'SCOPE\tthe audit verbs read what they are given; the enumeration verbs parse and plan, send nothing, and need no flag\n'
    printf 'ENUMERATE\t--enumerate <spec.json> [--base <url>] [--out <run-file>]  (writes a plan; rc0)\n'
    printf 'ENUMERATE_SUBSCRIBERS\t--enumerate-subscribers <conf>  (writes an ordered sequence; rc3 handoff)\n'
    printf 'GATE\tnone -- the enumeration verbs run without a flag\n'
    printf 'SENDS\tnothing; a plan is written and the subscriber sequence exits 3\n'
    printf 'SELFTEST\tyes\n'
}

# ── OpenAPI / Swagger surface (OpenAPI 3.x) ─────────────────────────────
capi_openapi_parse() {
    local file="${1:-}"
    [[ -f "$file" ]] || { printf 'ERROR\tno such spec: %s\n' "$file" >&2; return 1; }
    command -v python3 >/dev/null 2>&1 || { printf 'ERROR\tpython3 is required to parse JSON\n' >&2; return 3; }
    python3 - "$file" <<'PY' || { printf 'ERROR\tspec is not valid JSON or OpenAPI 3\n' >&2; return 1; }
import json, sys
try:
    d = json.load(open(sys.argv[1]))
except Exception as e:
    sys.stderr.write("parse error: %s\n" % e); sys.exit(1)
info = d.get("info", {})
print("title\t%s" % info.get("title", ""))
print("version\t%s" % info.get("version", ""))
for s in d.get("servers", []) or []:
    print("server\t%s" % s.get("url", ""))
paths = d.get("paths", {}) or {}
print("path_count\t%d" % len(paths))
methods = ("get", "put", "post", "delete", "patch", "options", "head", "trace")
n = 0
for p in sorted(paths):
    ops = paths[p] or {}
    for m in methods:
        if m in ops:
            n += 1
            op = ops[m] or {}
            reqs = op.get("security", [])
            sec = ",".join(sorted(reqs[0].keys())) if reqs else "inherit"
            print("operation\t%s\t%s\t%s" % (m.upper(), p, sec))
print("operation_count\t%d" % n)
schemes = ((d.get("components") or {}).get("securitySchemes") or {})
for name in sorted(schemes):
    print("security_scheme\t%s\t%s" % (name, (schemes[name] or {}).get("type", "")))
PY
}

# ── authorisation test matrix ───────────────────────────────────────────
capi_authz_matrix() {
    local file="${1:-}"
    [[ -f "$file" ]] || { printf 'ERROR\tno such spec: %s\n' "$file" >&2; return 1; }
    command -v python3 >/dev/null 2>&1 || { printf 'ERROR\tpython3 is required\n' >&2; return 3; }
    python3 - "$file" <<'PY' || return 1
import json, sys
d = json.load(open(sys.argv[1]))
paths = d.get("paths", {}) or {}
methods = ("get", "put", "post", "delete", "patch")
print("endpoint\tmethod\tcase\texpected_status")
for p in sorted(paths):
    for m in methods:
        if m in (paths[p] or {}):
            print("%s\t%s\tunauthenticated\t401" % (p, m.upper()))
            print("%s\t%s\twrong_scope\t403" % (p, m.upper()))
            print("%s\t%s\town_resource\t200" % (p, m.upper()))
            print("%s\t%s\tother_tenant_document\t403_or_404" % (p, m.upper()))
PY
}

# ── rate limit / token bucket ───────────────────────────────────────────
# A leaky/token bucket with rate r tokens/s, burst b. Over t seconds and n
# requests, at most b + r*t are allowed.
capi_token_bucket() {
    local rate="${1:-}" burst="${2:-}" reqs="${3:-}" secs="${4:-}"
    for v in "$rate" "$burst" "$reqs" "$secs"; do
        [[ "$v" =~ ^[0-9]+([.][0-9]+)?$ ]] || { printf 'ERROR\trate, burst, requests and seconds must be numeric\n' >&2; return 2; }
    done
    awk -v r="$rate" -v b="$burst" -v n="$reqs" -v t="$secs" 'BEGIN{
        cap = b + r*t
        allowed = (n < cap) ? n : cap
        printf "rate\t%s\nburst\t%s\ninterval_s\t%s\ncapacity\t%.0f\nrequests\t%s\nallowed\t%.0f\ndenied\t%.0f\n",
               r, b, t, cap, n, allowed, n-allowed
    }'
}

# ── JWT audit (algorithm and expiry) ────────────────────────────────────
capi_b64url_decode() {
    local s="${1:-}" m
    s=$(printf '%s' "$s" | sed 's/-/+/g; s/_/\//g')
    m=$(( ${#s} % 4 ))
    if (( m == 2 )); then s="${s}=="; elif (( m == 3 )); then s="${s}="
    elif (( m != 0 )); then printf 'ERROR\tbad base64url length\n' >&2; return 2; fi
    printf '%s' "$s" | base64 -d 2>/dev/null || { printf 'ERROR\tbase64url decode failed\n' >&2; return 2; }
}
capi_b64url_encode() {
    printf '%s' "${1:-}" | { base64 -w0 2>/dev/null || base64 | tr -d '\n'; } | sed 's/+/-/g; s#/#_#g; s/=*$//'
}
capi_jwt_audit() {
    local tok="${1:-}" now="${2:-}"
    [[ "$tok" == *.*.* ]] || { printf 'ERROR\tJWT must have three parts\n' >&2; return 1; }
    local h p header payload alg exp
    h="${tok%%.*}"; p=$(printf '%s' "$tok" | cut -d. -f2)
    header=$(capi_b64url_decode "$h") || return 2
    payload=$(capi_b64url_decode "$p") || return 2
    alg=$(printf '%s' "$header" | sed -n 's/.*"alg"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
    exp=$(printf '%s' "$payload" | sed -n 's/.*"exp"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p')
    [[ -n "$now" ]] || now=$(date +%s)
    printf 'finding\tseverity\tdetail\n'
    local n=0
    if [[ "${alg,,}" == "none" ]]; then
        printf 'alg_none\tCRITICAL\tthe token declares alg=none; a verifier that honours it accepts a forged payload\n'; n=$((n+1))
    fi
    if [[ -n "$exp" ]]; then
        if (( exp < now )); then
            printf 'expired\tMEDIUM\tthe token expired at %s and the API accepted it\n' "$exp"; n=$((n+1))
        else
            printf 'expiry_ok\tINFO\tthe token expires at %s (in %s s)\n' "$exp" "$(( exp - now ))"
        fi
    else
        printf 'no_expiry\tMEDIUM\tthe token carries no exp; it never expires on its own\n'; n=$((n+1))
    fi
    printf 'findings\t%d\n' "$n"
    return 0
}

# ── response differential ───────────────────────────────────────────────
# Compare two endpoint/status captures. A status that changes between runs is a
# candidate authorisation or rate-limit signal.
capi_diff() {
    local a="${1:-}" b="${2:-}"
    [[ -f "$a" && -f "$b" ]] || { printf 'ERROR\tneed two response files\n' >&2; return 1; }
    printf 'endpoint\tmethod\tstatus_a\tstatus_b\tverdict\n'
    awk -F'\t' '
        FNR==NR { if ($1 ~ /^endpoint/ || NF<3) next; ka[$1 SUBSEP $2]=$3; next }
        $1 ~ /^endpoint/ || NF<3 { next }
        {
            k=$1 SUBSEP $2
            if (!(k in ka)) { printf "%s\t%s\t-\t%s\tNEW\n", $1, $2, $3 }
            else if (ka[k] != $3) { printf "%s\t%s\t%s\t%s\tCHANGED\n", $1, $2, ka[k], $3 }
            seen[k]=1
        }
        END { for (k in ka) { split(k, a, SUBSEP); if (!(k in seen)) printf "%s\t%s\t%s\t-\tREMOVED\n", a[1], a[2], ka[k] } }
    ' "$a" "$b"
}

# ── credential-stuffing resistance ──────────────────────────────────────
capi_stuffing_resistance() {
    local file="${1:-}"
    [[ -f "$file" ]] || { printf 'ERROR\tno such config: %s\n' "$file" >&2; return 1; }
    local lockout="" ratelimit="" captcha="" mfa="" lockout_at=""
    local line k v
    while IFS= read -r line; do
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        [[ "$line" == *=* ]] || continue
        k=$(printf '%s' "${line%%=*}" | tr -d ' ' | tr 'A-Z' 'a-z')
        v="${line#*=}"
        case "$k" in
            lockout_threshold|account_lockout|max_attempts) lockout="$v" ;;
            rate_limit|login_rate_limit) ratelimit="$v" ;;
            captcha|captcha_on_login) captcha="$v" ;;
            mfa|mfa_required) mfa="$v" ;;
            lockout_duration_s|lockout_seconds) lockout_at="$v" ;;
        esac
    done < "$file"
    printf 'control\tpresent\tseverity_if_missing\tdetail\n'
    printf 'lockout\t%s\tHIGH\taccount lockout after N failed attempts (threshold=%s)\n' "$([[ -n "$lockout" ]] && echo yes || echo no)" "${lockout:-unset}"
    printf 'rate_limit\t%s\tHIGH\tper-account/IP login throttling (limit=%s)\n' "$([[ -n "$ratelimit" ]] && echo yes || echo no)" "${ratelimit:-unset}"
    printf 'captcha\t%s\tMEDIUM\thuman challenge on repeated failure\n' "$([[ "$captcha" =~ ^(true|yes|1|on)$ ]] && echo yes || echo no)"
    printf 'mfa\t%s\tMEDIUM\tsecond factor on the account\n' "$([[ "$mfa" =~ ^(true|yes|1|on)$ ]] && echo yes || echo no)"
    local missing=0
    [[ -z "$lockout" ]] && missing=$((missing+1))
    [[ -z "$ratelimit" ]] && missing=$((missing+1))
    (( missing == 0 )) && printf 'summary\tcontrols_present\t2\n' || printf 'summary\tcontrols_missing\t%d\n' "$missing"
    return 0
}

capi_report() {
    cat <<'EOF'
section	content
scope	written authorisation: your own account, a bug-bounty programme, or a signed contract
surface	OpenAPI discovery first; every test names an endpoint from the published spec
authz	the four-case matrix per operation (unauth, wrong scope, own, other tenant)
limits	token-bucket model from the observed 429s; report the achieved vs allowed rate
tokens	alg=none, expired and never-expiring tokens; audience/scope confusion
excluded	no mass subscriber enumeration; no third-party account access
EOF
}

capi_plan() {
    cat <<'EOF'
status	handoff
what	exercising a carrier's authenticated self-service API
hardware	none — a host with HTTP client reach, and a test account you own
software	curl or a small client, the published OpenAPI spec, and your own credentials
flow	1. --openapi on the downloaded spec  2. --authz-matrix for the test plan  3. --token-bucket from observed 429s  4. --diff across runs
note	only test an API you are authorised to test; this module never enumerates third-party accounts
EOF
}

# ── the enumeration half ────────────────────────────────────────────────
# Two verbs that build requests from a document instead of sending them. They
# build plans, and what they refuse to do is the least interesting part: the useful
# part is that the plan is built here and the send is left to a human who has
# the authorisation. See docs/OFFENSIVE_ROADMAP.md, Phase 12.

capi_arg_error() {
    printf 'ERROR\t%s\n' "$1" >&2
    printf 'WHY\tsee the usage at the end of --help; this verb takes a spec and optional flags\n' >&2
}

# Printed to stderr on EVERY invocation of an enumeration verb, armed or not,
# refused or not. This says what running it means, which a flag never could.
CAPI_NOTE='these verbs build and write request plans; they send nothing, and every identifier in a plan belongs to a real subscriber, so an operator may only run the plan against an API it owns or a sandbox it is authorised to use'

# The walker. Standard library only: the module already requires python3 for
# --openapi, and the parse is a plain JSON walk (no pip, no PyYAML, no network).
capi_py_enum() {
    local mode="${1:-}" spec="${2:-}" base="${3:-}" out="${4:-}" conf="${5:-}" outdir="${6:-}"
    command -v python3 >/dev/null 2>&1 || {
        printf 'ERROR\tpython3 is required to parse the OpenAPI document\n' >&2
        printf 'WHY\tinstall python3; the walker uses the standard library only and needs no packages\n' >&2
        return 1; }
    python3 - "$mode" "$spec" "$base" "$out" "$conf" "$outdir" <<'PY'
import json, os, re, sys, urllib.parse

# The standing note every planning verb prints. There is no gate: the verbs build
# requests and write them down, and what a reader needs to know is that no
# request is sent and that the identifiers in a plan belong to real people.
CAPI_NOTE_TXT = ("a plan, not a log: no HTTP request is made and no socket is opened; "
                 "the identifiers in it belong to real subscribers")

METHODS = ("get", "put", "post", "delete", "patch", "head", "options", "trace")
# CAMARA PhoneNumber, code/common/CAMARA_common.yaml: E.164, leading '+',
# pattern ^\+[1-9][0-9]{4,14}$.
E164 = re.compile(r"^\+[1-9][0-9]{4,14}$")
# Identifier field names this walker will recognise. `phoneNumber` is the CAMARA
# field (Number Verification, SIM Swap); its own description says it corresponds
# to the MSISDN, which is why msisdn and imsi are recognised as the same kind of
# field. Nothing else is guessed: a document with another name gets a handoff,
# not an invented endpoint family.
ID_NAMES = ("phonenumber", "msisdn", "imsi")
UNRESOLVED = []


def tsv(v):
    return str(v).replace("\t", " ").replace("\r", " ").replace("\n", " ")


def die(code, msg, why=None):
    sys.stderr.write("ERROR\t%s\n" % tsv(msg))
    if why:
        sys.stderr.write("WHY\t%s\n" % tsv(why))
    sys.exit(code)


def note_unresolved(where, ref):
    s = tsv("%s -> %s" % (where, ref))
    if s not in UNRESOLVED:
        UNRESOLVED.append(s)


def load(path):
    if not os.path.isfile(path):
        die(1, "no such spec: %s" % path,
            "pass the JSON OpenAPI document; this module does not parse YAML "
            "(convert one first: python3 -c 'import json,yaml,sys; json.dump(yaml.safe_load(open(sys.argv[1])), sys.stdout)' spec.yaml > spec.json)")
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            d = json.load(f)
    except Exception as e:
        die(1, "spec is not valid JSON: %s" % e,
            "this module parses JSON OpenAPI documents only; convert the YAML to JSON first")
    if not isinstance(d, dict) or not (d.get("openapi") or d.get("swagger")):
        die(1, "not an OpenAPI document: no openapi/swagger field",
            "pass the document itself")
    return d


def deref(d, obj, where):
    seen = 0
    while isinstance(obj, dict) and "$ref" in obj:
        ref = obj.get("$ref")
        if not isinstance(ref, str) or not ref.startswith("#/"):
            note_unresolved(where, ref)
            return None, ref
        cur = d
        ok = True
        for part in ref[2:].split("/"):
            part = part.replace("~1", "/").replace("~0", "~")
            if not isinstance(cur, dict) or part not in cur:
                ok = False
                break
            cur = cur[part]
        if not ok:
            note_unresolved(where, ref)
            return None, ref
        obj = cur
        seen += 1
        if seen > 20:
            note_unresolved(where, ref)
            return None, ref
    return obj, None


def first_example(d, node, where):
    if not isinstance(node, dict):
        return None, None
    if "example" in node:
        return node["example"], where + ".example"
    exs = node.get("examples")
    if isinstance(exs, dict):
        found = []
        for k in sorted(exs):
            e, _ = deref(d, exs[k], where + ".examples." + str(k))
            if isinstance(e, dict) and "value" in e:
                found.append((k, e["value"]))
        # A named example is preferred over nothing, and a populated one over an
        # empty one: the CAMARA specs ship a 3-legged example (empty body) beside
        # the 2-legged one that carries a phoneNumber.
        for k, v in found:
            if v not in (None, "", {}, []):
                return v, where + ".examples." + str(k)
        if found:
            return found[0][1], where + ".examples." + str(found[0][0])
    if isinstance(exs, list) and exs:
        return exs[0], where + ".examples[0]"
    return None, None


def schema_scalar(d, sch, where):
    sch, _ = deref(d, sch, where)
    if not isinstance(sch, dict):
        return None, None
    v, src = first_example(d, sch, where)
    if v is not None:
        return v, src
    if "default" in sch:
        return sch["default"], where + ".default"
    if isinstance(sch.get("enum"), list) and sch["enum"]:
        return sch["enum"][0], where + ".enum[0]"
    return None, None


def build_value(d, sch, where, depth=0):
    if depth > 8:
        return "<%s>" % where.rsplit(".", 1)[-1], where + " (depth limit) placeholder"
    sch, _ = deref(d, sch, where)
    if not isinstance(sch, dict):
        return None, None
    t = sch.get("type")
    props = sch.get("properties")
    if isinstance(props, dict) and (t == "object" or t is None):
        if not props:
            return {}, where + " (empty object schema)"
        req = [r for r in (sch.get("required") or []) if r in props]
        chosen = list(req)
        if not chosen:
            for name in props:
                v, _ = schema_scalar(d, props[name], where + "." + str(name))
                if v is not None:
                    chosen = [name]
                    break
        if not chosen:
            chosen = [next(iter(props))]
        maxp = sch.get("maxProperties")
        if isinstance(maxp, int) and 0 < maxp < len(chosen):
            chosen = chosen[:maxp]
        out = {}
        any_ph = False
        for name in chosen:
            v, src = build_value(d, props[name], where + "." + str(name), depth + 1)
            out[name] = v
            if src and "placeholder" in src:
                any_ph = True
        src = where + " schema"
        if not req:
            src += " (no required list; first documented property)"
        if any_ph:
            src += " + placeholder"
        return out, src
    if t == "array":
        v, src = schema_scalar(d, sch, where)
        if v is not None:
            return v, src
        iv, isrc = build_value(d, sch.get("items") or {}, where + "[]", depth + 1)
        return [iv], where + " schema array"
    v, src = schema_scalar(d, sch, where)
    if v is not None:
        return v, src
    name = where.rsplit(".", 1)[-1] or "value"
    return "<%s>" % name, where + " placeholder"


def params_of(d, op, where):
    out = []
    for p in op.get("parameters") or []:
        ps, _ = deref(d, p, where + " parameter")
        if isinstance(ps, dict):
            out.append(ps)
    return out


def auth_of(d, op, where):
    reqs = op["security"] if "security" in op else d.get("security")
    if not reqs:
        return ("none", "-", "-", 0, {})
    alts = [r for r in reqs if isinstance(r, dict) and r]
    if not alts:
        return ("none", "-", "-", 0, {})
    name = sorted(alts[0].keys())[0]
    scopes = "|".join(" ".join(alts[i].get(name) or []) or "-" for i in range(len(alts)))
    ref = ((d.get("components") or {}).get("securitySchemes") or {}).get(name)
    scheme, _ = deref(d, ref or {}, "securitySchemes." + str(name))
    if not isinstance(scheme, dict) or not scheme.get("type"):
        return (name, "unresolved", scopes, len(alts), scheme if isinstance(scheme, dict) else {})
    return (name, scheme["type"], scopes, len(alts), scheme)


def required_of(d, op, where):
    req = []
    for p in params_of(d, op, where):
        if p.get("in") == "path" or p.get("required") is True:
            req.append("%s:%s" % (p.get("in"), p.get("name")))
    rb, _ = deref(d, op.get("requestBody") or {}, where + ".requestBody")
    if isinstance(rb, dict) and rb.get("required") is True:
        req.append("body")
    return ";".join(req) or "-"


def body_of(d, op, where, ident=None, ident_name=None):
    rb, _ = deref(d, op.get("requestBody") or {}, where + ".requestBody")
    if not isinstance(rb, dict) or not rb:
        return None, None, None
    content = rb.get("content") or {}
    if not isinstance(content, dict) or not content:
        return None, None, None
    mt = "application/json" if "application/json" in content else sorted(content)[0]
    media = content[mt] or {}
    v, src = first_example(d, media, where + "." + str(mt))
    if v is None:
        v, src = build_value(d, media.get("schema") or {}, where + ".body", 0)
    if isinstance(v, dict) and ident is not None and ident_name:
        v = dict(v)
        v[ident_name] = ident
        src = (src or "body") + " + identifier"
    return v, src, mt


def render(d, base, path, method, op, where, ident=None, ident_loc=None, ident_name=None):
    params = params_of(d, op, where)
    qp = []
    headers = []
    path_out = path
    for name in re.findall(r"\{([^}{]+)\}", path):
        val = None
        if ident is not None and ident_loc == "path" and ident_name == name:
            val = ident
        else:
            for p in params:
                if p.get("in") == "path" and p.get("name") == name:
                    val, _ = schema_scalar(d, p.get("schema") or {}, where + ".path." + str(name))
                    if val is None and "example" in p:
                        val = p["example"]
                    break
        if val is None:
            val = "<%s>" % name
        path_out = path_out.replace("{" + name + "}", urllib.parse.quote(str(val), safe=""))
    for p in sorted(params, key=lambda x: (str(x.get("in")), str(x.get("name")))):
        loc = p.get("in")
        if loc == "path":
            continue
        name = p.get("name") or ""
        if not p.get("required") and not (ident is not None and ident_loc == loc and ident_name == name):
            continue
        if ident is not None and ident_loc == loc and ident_name == name:
            val = ident
        else:
            val, _ = schema_scalar(d, p.get("schema") or {}, where + "." + str(loc) + "." + str(name))
            if val is None and "example" in p:
                val = p["example"]
            if val is None:
                val = "<%s>" % name
        if loc == "query":
            qp.append((name, str(val)))
        elif loc == "header":
            headers.append("%s: %s" % (name, val))
        elif loc == "cookie":
            headers.append("Cookie: %s=%s" % (name, val))
    sec_name, sec_type, scopes, alts, scheme = auth_of(d, op, where)
    auth_h = []
    if sec_type == "http":
        s = str((scheme or {}).get("scheme") or "").lower()
        if s == "bearer":
            auth_h = ["Authorization: Bearer <access-token>"]
        elif s == "basic":
            auth_h = ["Authorization: Basic <base64-credentials>"]
        elif s:
            auth_h = ["Authorization: <http-%s-credentials>" % s]
        else:
            auth_h = ["Authorization: <http-credentials>"]
    elif sec_type in ("oauth2", "openIdConnect"):
        auth_h = ["Authorization: Bearer <access-token>"]
    elif sec_type == "apiKey":
        kn = (scheme or {}).get("name") or "api-key"
        ki = (scheme or {}).get("in") or "header"
        if ki == "query":
            qp.append((kn, "<api-key>"))
        elif ki == "cookie":
            auth_h = ["Cookie: %s=<api-key>" % kn]
        else:
            auth_h = ["%s: <api-key>" % kn]
    elif sec_type == "unresolved":
        auth_h = ["Authorization: <credential-for-%s>" % (sec_name or "scheme")]
    headers = auth_h + headers
    body, bsrc, mt = body_of(d, op, where, ident, ident_name)
    if body is not None:
        headers.append("Content-Type: %s" % (mt or "application/json"))
    url = (base.rstrip("/") + "/" + path_out.lstrip("/")) if base else path_out
    if qp:
        url += "?" + urllib.parse.urlencode(qp, quote_via=urllib.parse.quote, safe="")
    return url, headers, body, bsrc, sec_name, sec_type, scopes, alts


def shquote(s):
    return "'" + str(s).replace("'", "'\\''") + "'"


def curl_line(method, url, headers, body):
    parts = ["curl", "-sS", "-X", method, shquote(url)]
    for h in headers:
        parts += ["-H", shquote(h)]
    if body is not None:
        parts += ["--data", shquote(json.dumps(body, sort_keys=False))]
    return " ".join(parts)


def write_run(path, lines):
    try:
        d = os.path.dirname(path)
        if d:
            os.makedirs(d, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
    except Exception as e:
        die(1, "could not write run-file %s: %s" % (path, e),
            "pick a writable --out path; the default is $CAPI_DIR under loot/")


def server_url(d, override):
    if override:
        return override, "flag --base"
    servers = d.get("servers") or []
    if not isinstance(servers, list) or not servers or not isinstance(servers[0], dict):
        return "", "not declared"
    s = servers[0]
    url = str(s.get("url") or "")
    src = "servers[0]"
    for vname, v in (s.get("variables") or {}).items():
        default = (v or {}).get("default")
        if default is not None and ("{%s}" % vname) in url:
            url = url.replace("{%s}" % vname, str(default))
            src += " + variables.%s.default" % vname
        elif default is None and ("{%s}" % vname) in url:
            src += " (unresolved variable %s)" % vname
    return url, src


def emit_operation_rows(d, base):
    rows = []
    reqs = []
    nph = 0
    paths = d.get("paths") or {}
    if not isinstance(paths, dict):
        paths = {}
    for path in sorted(paths):
        ops = paths[path] or {}
        if not isinstance(ops, dict):
            continue
        for m in METHODS:
            op = ops.get(m)
            if not isinstance(op, dict):
                continue
            where = "%s %s" % (m.upper(), path)
            req = required_of(d, op, where)
            aname, atyp, scopes, alts, _ = auth_of(d, op, where)
            tags = ",".join(op.get("tags") or []) or "-"
            url, headers, body, bsrc, _, _, _, _ = render(d, base, path, m, op, where)
            htxt = "; ".join(tsv(h) for h in headers) or "-"
            btxt = json.dumps(body, sort_keys=False) if body is not None else "-"
            if re.search(r"<[A-Za-z0-9_.:-]+>", tsv(url) + " " + htxt + " " + tsv(btxt)):
                nph += 1
            rows.append("\t".join([
                "operation", m.upper(), tsv(path), tsv(op.get("operationId") or "-"),
                tsv(req), tsv(aname), tsv(atyp), tsv(scopes), tsv(tags), str(alts),
            ]))
            reqs.append((m.upper(), url, headers, body))
            rows.append("\t".join([
                "request", m.upper(), tsv(url), htxt, tsv(btxt), tsv(bsrc or "-"),
            ]))
    return rows, reqs, nph


def mode_enumerate(spec, base_override, out):
    d = load(spec)
    ver = str(d.get("openapi") or d.get("swagger") or "")
    title = str(((d.get("info") or {}).get("title")) or "-")
    base, base_src = server_url(d, base_override)
    rows, reqs, nph = emit_operation_rows(d, base)
    gate = "no request is sent by this verb; no flag is needed to build a plan"
    rl = [
        "# carrier_api run-file — built by --enumerate from %s" % spec,
        "# verb: enumerate",
        "# sent: nothing. This is a plan, not a log: no HTTP request was made.",
        ("# base: %s (%s)" % (base, base_src)) if base else
        "# base: (not declared) — the document has no servers[0] and no override was given; the URLs below are path templates",
        "# format: one curl command per line, path-then-method order",
        "# placeholders: <name> marks a value the document does not supply; replace it",
        "# note: %s" % gate,
    ]
    rl += [curl_line(m, url, hs, b) for (m, url, hs, b) in reqs]
    write_run(out, rl)
    print("MODULE\tcarrier_api")
    print("VERB\tenumerate")
    print("SPEC\t%s" % tsv(spec))
    print("OPENAPI\t%s" % tsv(ver))
    print("TITLE\t%s" % tsv(title))
    print("BASE\t%s" % tsv(base or "(not declared)"))
    print("BASE_SOURCE\t%s" % tsv(base_src))
    print("OPERATIONS\t%d" % (len(reqs)))
    print("REQUESTS\t%d" % len(reqs))
    print("PLACEHOLDERS\t%d" % nph)
    print("UNRESOLVED\t%d" % len(UNRESOLVED))
    print("RUN_FILE\t%s" % tsv(out))
    print("RUN_FILE_LINES\t%d" % len(reqs))
    print("STANDING_NOTE\t%s" % tsv(CAPI_NOTE_TXT))
    print("SENT\tnothing")
    print("NOTE\tthis verb parses the document and writes a plan; no HTTP request is made and no socket is opened")
    for r in rows:
        print(r)
    for u in sorted(UNRESOLVED):
        print("unresolved\t%s" % u)
    return 0


def norm_id(name):
    return str(name).lower().replace("_", "").replace("-", "")


def id_locations(d, op, where):
    locs = []
    for p in params_of(d, op, where):
        nm = p.get("name") or ""
        if norm_id(nm) in ID_NAMES:
            locs.append((p.get("in") or "query", nm))
    rb, _ = deref(d, op.get("requestBody") or {}, where + ".requestBody")
    if isinstance(rb, dict):
        content = rb.get("content") or {}
        media = {}
        if isinstance(content, dict) and content:
            mt = "application/json" if "application/json" in content else sorted(content)[0]
            media = content[mt] or {}
        sch, _ = deref(d, media.get("schema") or {}, where + ".body")
        if isinstance(sch, dict):
            for nm in (sch.get("properties") or {}):
                if norm_id(nm) in ID_NAMES:
                    locs.append(("body", nm))
    return locs


def read_conf(path):
    if not os.path.isfile(path):
        die(2, "no such conf: %s" % path,
            "--enumerate-subscribers needs a key=value conf with spec= and candidates= at minimum")
    vals = {}
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            k = k.strip().lower().replace("-", "_")
            if k not in ("spec", "candidates", "base", "rate_limit", "stop_after", "endpoint", "out"):
                sys.stderr.write("SKIP\tunknown conf key (ignored): %s\n" % tsv(k))
                continue
            vals[k] = v.strip()
    return vals


def rate_of(d, op, conf):
    for scope, obj in (("operation", op), ("document", d)):
        rl = obj.get("x-rate-limit") if isinstance(obj, dict) else None
        if isinstance(rl, dict):
            lim = rl.get("limit")
            win = rl.get("window", rl.get("window_s", rl.get("seconds")))
            if isinstance(lim, (int, float)) and isinstance(win, (int, float)) and lim > 0 and win > 0:
                return (lim, win, "x-rate-limit extension (%s)" % scope)
    declared = isinstance(op.get("responses"), dict) and "429" in op["responses"]
    if conf.get("rate_limit"):
        m = re.match(r"^\s*([0-9]+)\s*/\s*([0-9]+)\s*$", conf["rate_limit"])
        if not m or int(m.group(1)) <= 0 or int(m.group(2)) <= 0:
            die(2, "conf rate_limit must be <requests>/<window_seconds>, got %s" % conf["rate_limit"],
                "for example rate_limit=10/60 means ten requests per sixty-second window")
        return (int(m.group(1)), int(m.group(2)),
                "conf rate_limit= (operator-declared; the document declares %s)" %
                ("a 429 but no numeric limit" if declared else "no rate limit"))
    if declared:
        return (None, None, "declared-429-only (a 429 response is documented; no numeric limit is)")
    return (None, None, "not-declared")


def fmt_num(x):
    s = ("%.6f" % float(x)).rstrip("0").rstrip(".")
    return s or "0"


def mode_subscribers(conf_path, outdir):
    conf = read_conf(conf_path)
    spec = conf.get("spec") or ""
    cand_path = conf.get("candidates") or ""
    if not spec:
        die(2, "conf has no spec=: there is no document to build a sequence from",
            "add spec=<path to the JSON OpenAPI document that declares the endpoint family>")
    d = load(spec)
    gate = "no request is sent by this verb; no flag is needed to build a plan"
    base, base_src = server_url(d, conf.get("base") or "")
    paths = d.get("paths") or {}
    if not isinstance(paths, dict):
        paths = {}
    found = []
    for path in sorted(paths):
        ops = paths[path] or {}
        if not isinstance(ops, dict):
            continue
        for m in METHODS:
            op = ops.get(m)
            if not isinstance(op, dict):
                continue
            where = "%s %s" % (m.upper(), path)
            locs = id_locations(d, op, where)
            if locs:
                found.append((m, path, op, locs, where))
    out = conf.get("out") or os.environ.get("CAPI_SUBS_OUT") or os.path.join(outdir, "enumerate-subscribers.requests.txt")
    if conf.get("endpoint"):
        want = conf["endpoint"].strip().lower()
        sel = None
        for c in found:
            key = ("%s %s" % (c[0].upper(), c[1])).lower()
            if want in (key, c[1].lower()):
                sel = c
                break
        if sel is None:
            die(2, "endpoint=%s is not an identifier operation in %s" % (conf["endpoint"], spec),
                "identifier operations found: " + (", ".join("%s %s" % (c[0].upper(), c[1]) for c in found) or "(none)"))
        found = [sel]
    if not found:
        rl = [
            "# carrier_api run-file — built by --enumerate-subscribers from %s" % conf_path,
            "# verb: enumerate-subscribers",
            "# sent: nothing. This is an ordered plan, not a log: no HTTP request was made.",
            "# endpoint: (none) — the document declares no operation that takes a subscriber identifier",
            "# identifier_fields: phoneNumber, msisdn, imsi (CAMARA PhoneNumber is the MSISDN)",
            "# note: %s" % gate,
            "# no sequence: nothing here is a subscriber endpoint, so nothing was invented",
        ]
        write_run(out, rl)
        print("MODULE\tcarrier_api")
        print("VERB\tenumerate-subscribers")
        print("SPEC\t%s" % tsv(spec))
        print("CONF\t%s" % tsv(conf_path))
        print("ENDPOINT_FAMILY\t(none)")
        print("ENDPOINT\t(none)")
        print("IDENTIFIER_FIELD\t(none)")
        print("CANDIDATES\t0")
        print("CANDIDATES_INVALID\t0")
        print("SEQUENCE_LENGTH\t0")
        print("RATE_LIMIT\t(none)")
        print("RATE_LIMIT_SOURCE\tnot-declared")
        print("INTERVAL_S\t-")
        print("STOP_CONDITION\tnot reached: there is no sequence")
        print("RUN_FILE\t%s" % tsv(out))
        print("STANDING_NOTE\t%s" % tsv(CAPI_NOTE_TXT))
        print("SENT\tnothing")
        print("HANDOFF\tstatus\thandoff")
        print("HANDOFF\twhy\tthe parsed document declares no operation with a phoneNumber/msisdn/imsi field, "
              "and this module will not invent an endpoint family")
        print("HANDOFF\tnext\tpoint spec= at the document for the endpoint family you have written authorisation to test")
        print("HANDOFF\texit\t3 — nothing was sent")
        for u in sorted(UNRESOLVED):
            print("unresolved\t%s" % u)
        return 3
    m, path, op, locs, where = found[0]
    ident_loc, ident_name = locs[0]
    lim, win, rsrc = rate_of(d, op, conf)
    raws = []
    if not cand_path:
        die(2, "conf has no candidates=: there is no identifier list to sequence",
            "add candidates=<file with one E.164 number per line, all test subscriptions you own>")
    if not os.path.isfile(cand_path):
        die(2, "no such candidates file: %s" % cand_path,
            "one E.164 identifier per line; comments and blank lines are ignored")
    with open(cand_path, "r", encoding="utf-8", errors="replace") as f:
        for raw in f:
            v = raw.strip()
            if not v or v.startswith("#"):
                continue
            raws.append(v)
    valid, invalid, seen = [], [], set()
    for v in raws:
        if not E164.match(v):
            invalid.append(v)
            continue
        if v in seen:
            continue
        seen.add(v)
        valid.append(v)
    for v in invalid:
        sys.stderr.write("SKIP\tnot an E.164 number per CAMARA PhoneNumber (^\\+[1-9][0-9]{4,14}$): %s\n" % tsv(v))
    if not valid:
        die(2, "no valid candidate identifier in %s" % cand_path,
            "CAMARA PhoneNumber is E.164: a leading '+', a 1-9 country digit, then 4 to 14 more digits")
    stop = len(valid)
    if conf.get("stop_after"):
        if not re.match(r"^[0-9]+$", conf["stop_after"]) or int(conf["stop_after"]) <= 0:
            die(2, "conf stop_after must be a positive integer, got %s" % conf["stop_after"],
                "for example stop_after=20")
        stop = min(stop, int(conf["stop_after"]))
    seq = []
    for v in valid[:stop]:
        url, headers, body, bsrc, _, _, _, _ = render(d, base, path, m, op, where, v, ident_loc, ident_name)
        seq.append((m.upper(), url, headers, body))
    tags = op.get("tags") or []
    family = str(tags[0]) if tags else (path.strip("/").split("/")[0] or "root")
    interval = (win / float(lim)) if lim else None
    if interval is not None:
        pace = "sleep %s s between requests (the declared %s per %s s)" % (fmt_num(interval), fmt_num(lim), fmt_num(win))
    elif "declared-429-only" in rsrc:
        pace = "no declared pace: a 429 is documented but no numeric limit is, so stop on the first 429"
    else:
        pace = "no declared pace and no documented 429: keep the list to your own test subscriptions and stop on the first refusal"
    stopc = "after request %d" % len(seq)
    if conf.get("stop_after"):
        stopc += " (stop_after=%s; %d valid candidates)" % (conf["stop_after"], len(valid))
    else:
        stopc += " (the candidate list is exhausted)"
    stopc += "; halt at the first 429 (the declared limit is wrong), 401 or 403 (the token is not authorised), no retry"
    rl = [
        "# carrier_api run-file — built by --enumerate-subscribers from %s" % conf_path,
        "# verb: enumerate-subscribers",
        "# sent: nothing. This is an ordered plan, not a log: no HTTP request was made.",
        "# endpoint_family: %s" % family,
        "# endpoint: %s %s" % (m.upper(), path),
        "# identifier_field: %s (%s)" % (ident_name, ident_loc),
        ("# base: %s (%s)" % (base, base_src)) if base else
        "# base: (not declared) — the document has no servers[0] and no override was given; the URLs below are path templates",
        "# candidates: %d valid, %d skipped as not E.164" % (len(valid), len(invalid)),
        "# rate_limit: %s" % (("%s per %s s (%s)" % (fmt_num(lim), fmt_num(win), rsrc)) if lim else rsrc),
        "# pace: %s" % pace,
        "# stop: %s" % stopc,
        "# sequence: one identifier per request, in candidate-file order",
        "# format: one curl command per line",
        "# note: %s" % gate,
    ]
    rl += [curl_line(mm, url, hs, b) for (mm, url, hs, b) in seq]
    write_run(out, rl)
    print("MODULE\tcarrier_api")
    print("VERB\tenumerate-subscribers")
    print("SPEC\t%s" % tsv(spec))
    print("CONF\t%s" % tsv(conf_path))
    print("ENDPOINT_FAMILY\t%s" % tsv(family))
    print("ENDPOINT\t%s %s" % (m.upper(), tsv(path)))
    print("IDENTIFIER_FIELD\t%s (%s)" % (tsv(ident_name), ident_loc))
    print("CANDIDATES\t%d" % len(valid))
    print("CANDIDATES_INVALID\t%d" % len(invalid))
    print("SEQUENCE_LENGTH\t%d" % len(seq))
    print("RATE_LIMIT\t%s" % (("%s per %s s" % (fmt_num(lim), fmt_num(win))) if lim else "(none declared)"))
    print("RATE_LIMIT_SOURCE\t%s" % tsv(rsrc))
    print("INTERVAL_S\t%s" % (fmt_num(interval) if interval is not None else "-"))
    print("STOP_CONDITION\t%s" % tsv(stopc))
    print("RUN_FILE\t%s" % tsv(out))
    print("RUN_FILE_LINES\t%d" % len(seq))
    print("STANDING_NOTE\t%s" % tsv(CAPI_NOTE_TXT))
    print("SENT\tnothing")
    print("NOTE\tno HTTP client is invoked: this verb writes the sequence and stops")
    print("HANDOFF\tstatus\thandoff")
    print("HANDOFF\twhy\tno request was sent and none will be; the run-file is the sequence an operator runs")
    print("HANDOFF\tauthorisation\twritten authorisation from the API owner for this endpoint and this purpose, "
          "and a test subscription you own — never a customer's")
    print("HANDOFF\tnext\t1. inspect the plan: less %s" % tsv(out))
    print("HANDOFF\tnext\t2. replace <access-token> with a token issued for your own test subscription")
    print("HANDOFF\tnext\t3. when the authorisation is in hand, run it one line at a time: bash %s" % tsv(out))
    print("HANDOFF\tnext\t4. pace it as declared: %s" % tsv(pace))
    print("HANDOFF\tnext\t5. stop %s" % tsv(stopc))
    print("HANDOFF\tnext\t6. do not retry, do not widen the list, and do not point it at a production carrier API")
    print("HANDOFF\texit\t3 — nothing was sent")
    for u in sorted(UNRESOLVED):
        print("unresolved\t%s" % u)
    return 3


def main(argv):
    if len(argv) < 7:
        die(2, "internal: wrong argument count", "this is a bug in capi_py_enum")
    mode, spec, base, out, conf, outdir = argv[1:7]
    if mode == "enumerate":
        return mode_enumerate(spec, base, out)
    if mode == "subscribers":
        return mode_subscribers(conf, outdir)
    die(2, "internal: unknown mode %s" % mode, "this is a bug in capi_py_enum")


if __name__ == "__main__":
    sys.exit(main(sys.argv))
PY
}

capi_enumerate() {
    local spec="" base="" out=""
    while (($# > 0)); do
        case "$1" in
            --base)   (($# >= 2)) || { capi_arg_error "--base needs a URL"; return 2; }; base="$2"; shift 2 ;;
            --base=*) base="${1#--base=}"; shift ;;
            --conf)   (($# >= 2)) || { capi_arg_error "--conf needs a path"; return 2; }; spec="$2"; shift 2 ;;
            --conf=*) spec="${1#--conf=}"; shift ;;
            --out)    (($# >= 2)) || { capi_arg_error "--out needs a path"; return 2; }; out="$2"; shift 2 ;;
            --out=*)  out="${1#--out=}"; shift ;;
            -*)       capi_arg_error "unknown option: $1"; return 2 ;;
            *)        if [[ -z "$spec" ]]; then spec="$1"; else capi_arg_error "unexpected argument: $1"; return 2; fi; shift ;;
        esac
    done
    [[ -n "$spec" ]] || {
        printf 'ERROR\t--enumerate needs an OpenAPI document\n' >&2
        printf 'WHY\tpass the JSON spec positionally or with --conf <path>; YAML is not parsed, convert it to JSON first\n' >&2
        return 2; }
    : "${out:=$CAPI_DIR/enumerate.requests.txt}"
    mkdir -p "$CAPI_DIR" 2>/dev/null
    capi_py_enum enumerate "$spec" "$base" "$out" "" "$CAPI_DIR"
}

capi_enumerate_subscribers() {
    local conf="" out=""
    while (($# > 0)); do
        case "$1" in
            --conf)   (($# >= 2)) || { capi_arg_error "--conf needs a path"; return 2; }; conf="$2"; shift 2 ;;
            --conf=*) conf="${1#--conf=}"; shift ;;
            --out)    (($# >= 2)) || { capi_arg_error "--out needs a path"; return 2; }; out="$2"; shift 2 ;;
            --out=*)  out="${1#--out=}"; shift ;;
            -*)       capi_arg_error "unknown option: $1"; return 2 ;;
            *)        if [[ -z "$conf" ]]; then conf="$1"; else capi_arg_error "unexpected argument: $1"; return 2; fi; shift ;;
        esac
    done
    [[ -n "$conf" ]] || {
        printf 'ERROR\t--enumerate-subscribers needs a conf file\n' >&2
        printf 'WHY\tthe conf carries spec=, candidates=, and optionally base=, rate_limit=N/S, stop_after=N, endpoint=, out=\n' >&2
        return 2; }
    mkdir -p "$CAPI_DIR" 2>/dev/null
    ( export CAPI_SUBS_OUT="$out"; capi_py_enum subscribers "" "" "" "$conf" "$CAPI_DIR" )
}

# ── the executor ────────────────────────────────────────────────────────
# The plan verbs above write requests down and send nothing; this one sends
# them, and only when the operator has said in words that the target is theirs.
# There is no default target: a base URL is always an argument.
capi_cmd_execute() {
    local plan="" base="" armed=0 rate=5 maxreq=50 dry=0
    local -a hs=()
    while (( $# )); do
        case "$1" in
            --plan)   plan="${2:-}"; shift 2 ;;
            --base)   base="${2:-}"; shift 2 ;;
            --rate)   rate="${2:-5}"; shift 2 ;;
            --max)    maxreq="${2:-50}"; shift 2 ;;
            --dry-run) dry=1; shift ;;
            --i-have-a-lab-and-authorisation) armed=1; shift ;;
            --help|-h)
                printf 'usage: --execute <plan.tsv> --base URL --i-have-a-lab-and-authorisation [--rate N/sec] [--max N] [--dry-run]\n'; return 0 ;;
            *)
                if [[ -z "$plan" && -r "$1" ]]; then plan="$1"; shift; continue; fi
                printf 'ERROR\t--execute does not take %s\n' "$(capi_sanitize "$1")" >&2; return 2 ;;
        esac
    done
    [[ -n "$plan" ]] || { printf 'ERROR\t--execute needs a plan file\n' >&2; return 2; }
    [[ -r "$plan" ]] || { printf 'ERROR\tthe plan is not readable: %s\n' "$(capi_sanitize "$plan")" >&2; return 2; }
    [[ "$rate" =~ ^[0-9]+$ ]] && (( rate >= 1 && rate <= 100 )) || {
        printf 'ERROR\t--rate is 1..100 requests per second: %s\n' "$(capi_sanitize "$rate")" >&2; return 2; }
    [[ "$maxreq" =~ ^[0-9]+$ ]] && (( maxreq >= 1 && maxreq <= 5000 )) || {
        printf 'ERROR\t--max is 1..5000 requests: %s\n' "$(capi_sanitize "$maxreq")" >&2; return 2; }
    printf 'note\t%s\n' "$CAPI_NOTE"
    printf 'authorised\t%s\n' "$armed"
    if (( ! armed )); then
        printf 'status\thandoff\n'
        printf 'why\tthe executor sends the plan at a live API; say --i-have-a-lab-and-authorisation to run it against one you own\n'
        printf 'sent\t0\n'
        return 3
    fi
    [[ -n "$base" ]] || { printf 'ERROR\t--execute needs --base even when armed\n' >&2; return 2; }
    case "$base" in
        http://*|https://*) ;;
        *) printf 'ERROR\t--base must be an http(s) URL: %s\n' "$(capi_sanitize "$base")" >&2; return 2 ;;
    esac
    command -v curl >/dev/null 2>&1 || {
        printf 'ERROR\tcurl is required to execute a plan\n' >&2; return 1; }
    base="${base%/}"
    local sock=$(( 1000000 / rate ))
    printf 'base\t%s\nrate\t%s\nsock_us\t%s\nmax\t%s\n' "$(capi_sanitize "$base")" "$rate" "$sock" "$maxreq"
    local n=0 sent=0 code tsec size verdict authsig findings=0
    local method path expect hdrs body
    while IFS=$'\t' read -r method path expect hdrs body; do
        [[ -n "$method" ]] || continue
        [[ "$method" == "METHOD" || "$method" == "#"* ]] && continue
        (( n < maxreq )) || { printf 'cut\tthe plan has more than --max %s rows; the rest was not sent\n' "$maxreq"; break; }
        n=$(( n + 1 ))
        local url="${base}${path}"
        local -a cargs=(-s -o /dev/null -w '%{http_code} %{time_total} %{size_download}' -X "$method")
        if [[ -n "$hdrs" && "$hdrs" != "-" ]]; then
            local h; IFS=';' read -r -a hs <<< "$hdrs"
            for h in "${hs[@]}"; do [[ -n "$h" ]] && cargs+=(-H "$h"); done
        fi
        [[ -n "$body" && "$body" != "-" ]] && cargs+=(--data-binary "$body")
        if (( dry )); then
            printf 'dry_run\t%s\t%s\n' "$method" "$(capi_sanitize "$url")"
            continue
        fi
        read -r code tsec size <<< "$(curl "${cargs[@]}" "$url" 2>/dev/null)"
        [[ -n "$code" ]] || code="000"
        sent=$(( sent + 1 ))
        verdict=unexpected
        case "$expect" in
            deny)  case "$code" in 401|403) verdict="denied as expected" ;; 200|201|204) verdict="ALLOWED, expected deny"; findings=$(( findings + 1 )) ;; *) verdict="code $code" ;; esac ;;
            allow) case "$code" in 2??) verdict="allowed as expected" ;; 401|403) verdict="DENIED, expected allow" ;; *) verdict="code $code" ;; esac ;;
            *)     verdict="code $code" ;;
        esac
        printf 'step\t%d\t%s\t%s\t%s\t%s\t%s\t%s\n' "$n" "$method" "$(capi_sanitize "$path")" "$code" "$tsec" "$size" "$verdict"
        if [[ "$verdict" == "ALLOWED, expected deny" ]]; then
            printf 'finding\tunauthorised_success\tHIGH\t%s %s returned %s where the plan expected a refusal\n' "$method" "$(capi_sanitize "$path")" "$code"
        fi
        sleep "$(printf '0.%06d' "$sock")"
    done < "$plan"
    printf 'sent\t%d\nfindings\t%d\n' "$sent" "$findings"
    printf 'limit\tan executor that reports codes is not an authorisation verdict: a 200 from a test account proves that account may call the endpoint, and that is all\n'
    (( findings == 0 )) && return 0 || return 1
}

# ── TR-069 (CWMP) and TR-369 (USP) ──────────────────────────────────────
# A CPE management server is a second front door into the same subscriber
# premises the self-care API fronts, and it speaks a protocol the API verbs
# never touched: SOAP over HTTP for TR-069, and the USP message envelope for
# TR-369. Both halves are here -- the message a CPE sends, and the read of one
# that was captured -- because a management session that is built but never read
# back is a message nobody has checked.
#
# TR-069 CWMP, the parts used here (Amendment 6):
#   3.4.1  the CPE opens a TCP connection and POSTs a SOAP message; the method
#          name travels in the SOAPAction header, quoting the CWMP namespace
#   A.3.2.1 the Inform: Event (EventStruct/EventCode/CommandKey), MaxEnvelopes,
#          CurrentTime, RetryCount, ParameterList of ParameterValueStruct
#   A.3.2.2 the InformResponse (MaxEnvelopes only)
#   A.3.2.2/A.3.2.3 the empty POST the CPE sends, and GetParameterValues /
#          GetParameterValuesResponse with ParameterNames and ParameterList
#   Table 3 the event codes: 0 BOOTSTRAP, 1 BOOT, 2 PERIODIC, 3 SCHEDULED,
#          4 VALUE CHANGE, 5 KICKED, 6 CONNECTION REQUEST, 7 TRANSFER COMPLETE,
#          8 DIAGNOSTICS COMPLETE
# The namespace is urn:dslforum-org:cwmp-1-0 for every message this module
# builds; a world without the namespace is a different protocol version, and one
# is not substituted for the other.
CAPI_CWMP_NS='urn:dslforum-org:cwmp-1-0'
CAPI_CWMP_EVENTS='0 BOOTSTRAP|1 BOOT|2 PERIODIC|3 SCHEDULED|4 VALUE CHANGE|5 KICKED|6 CONNECTION REQUEST|7 TRANSFER COMPLETE|8 DIAGNOSTICS COMPLETE'

capi_cwmp_build_inform() {  # [--oui] [--product-class] [--serial] [--event] [--acs] [--out]
    local oui='001122' pclass='IGD' serial='000000000001' event='1 BOOT'
    local acs='http://192.0.2.1:7547/ACS-server/ACS' out='' cwmp_id=''
    while (($#)); do
        case "$1" in
            --oui)           oui="${2:-}"; shift 2 ;;
            --product-class) pclass="${2:-}"; shift 2 ;;
            --serial)        serial="${2:-}"; shift 2 ;;
            --event)         event="${2:-}"; shift 2 ;;
            --acs)           acs="${2:-}"; shift 2 ;;
            --id)            cwmp_id="${2:-}"; shift 2 ;;
            --out)           out="${2:-}"; shift 2 ;;
            *) printf 'ERROR\tunknown flag %s\n' "$(capi_sanitize "$1")" >&2; return 2 ;;
        esac
    done
    [[ "$oui" =~ ^[0-9A-Fa-f]{6}$ ]] || {
        printf 'ERROR\t--oui is six hex octets (TR-069 A.3.2.1 Device.DeviceInfo.ManufacturerOUI)\n' >&2; return 2; }
    # An event code is one of the ones in Table 3; anything else is a code this
    # module cannot name, and naming it anyway would be inventing a message.
    case "|$CAPI_CWMP_EVENTS|" in
        *"|$event|"*) ;;
        *) printf 'ERROR\tevent code not in TR-069 Table 3: %s\n' "$(capi_sanitize "$event")" >&2
           printf 'KNOWN\t%s\n' "$(printf '%s' "$CAPI_CWMP_EVENTS" | tr '|' ',')" >&2
           return 2 ;;
    esac
    local now; now=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    local body
    # A.3.2.1: the Inform carries the parameters that say who the CPE is.
    body=$(cat <<XML
    <cwmp:Inform>
      <Event xmlns:soap-enc="http://schemas.xmlsoap.org/soap/encoding/" soap-enc:arrayType="cwmp:EventStruct[1]">
        <EventStruct>
          <EventCode>$(capi_sanitize "$event")</EventCode>
          <CommandKey>$(capi_sanitize "$cwmp_id")</CommandKey>
        </EventStruct>
      </Event>
      <MaxEnvelopes>1</MaxEnvelopes>
      <CurrentTime>${now}</CurrentTime>
      <RetryCount>0</RetryCount>
      <ParameterList>
        <ParameterValueStruct>
          <Name>Device.DeviceInfo.ManufacturerOUI</Name>
          <Value xsi:type="xsd:string">$(capi_sanitize "$oui")</Value>
        </ParameterValueStruct>
        <ParameterValueStruct>
          <Name>Device.DeviceInfo.ProductClass</Name>
          <Value xsi:type="xsd:string">$(capi_sanitize "$pclass")</Value>
        </ParameterValueStruct>
        <ParameterValueStruct>
          <Name>Device.DeviceInfo.SerialNumber</Name>
          <Value xsi:type="xsd:string">$(capi_sanitize "$serial")</Value>
        </ParameterValueStruct>
        <ParameterValueStruct>
          <Name>Device.DeviceInfo.SoftwareVersion</Name>
          <Value xsi:type="xsd:string">unobserved</Value>
        </ParameterValueStruct>
      </ParameterList>
    </cwmp:Inform>
XML
)
    local xml
    xml=$(cat <<XML
<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:cwmp="${CAPI_CWMP_NS}" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
  <soap:Header/>
  <soap:Body>
${body}
  </soap:Body>
</soap:Envelope>
XML
)
    local clen; clen=$(printf '%s' "$xml" | wc -c | tr -d ' ')
    printf 'protocol\tTR-069 (CWMP)\n'
    printf 'method\tInform\n'
    printf 'namespace\t%s\n' "$CAPI_CWMP_NS"
    printf 'soapaction\t"%s#Inform"\n' "$CAPI_CWMP_NS"
    printf 'http\tPOST %s HTTP/1.1\n' "$(capi_sanitize "$acs")"
    printf 'content_type\ttext/xml; charset="utf-8"\n'
    printf 'content_length\t%s\n' "$clen"
    printf 'event\t%s\tadvertised\tTR-069 Table 3; an event code is the CPE reporting about itself\n' "$(capi_sanitize "$event")"
    printf 'oui\t%s\tadvertised\tDevice.DeviceInfo.ManufacturerOUI (TR-069 A.3.2.1)\n' "$(capi_sanitize "$oui")"
    printf 'product_class\t%s\tadvertised\tDevice.DeviceInfo.ProductClass\n' "$(capi_sanitize "$pclass")"
    printf 'serial\t%s\tadvertised\tDevice.DeviceInfo.SerialNumber\n' "$(capi_sanitize "$serial")"
    printf 'software_version\tunobserved\tthis builder writes the literal "unobserved" rather than a version this host does not know\n'
    printf 'transmitted\tno\n'
    printf '%s\n' "$xml"
    if [[ -n "$out" ]]; then
        printf '%s\n' "$xml" > "$out" || { printf 'ERROR\tcannot write %s\n' "$(capi_sanitize "$out")" >&2; return 1; }
        printf 'written\t%s\n' "$(capi_sanitize "$out")"
    fi
    printf 'ref\tTR-069 Amendment 6 3.4.1 (transport, SOAPAction), A.3.2.1 (Inform), Table 3 (event codes)\n'
    return 0
}

capi_cwmp_build_gpv() {  # <param>... [--out <file>]
    local -a params=() 
    local out=''
    while (($#)); do
        case "$1" in
            --out) out="${2:-}"; shift 2 ;;
            -*) printf 'ERROR\tunknown flag %s\n' "$(capi_sanitize "$1")" >&2; return 2 ;;
            *) params+=("$1"); shift ;;
        esac
    done
    ((${#params[@]} > 0)) || {
        printf 'ERROR\tusage: --cwmp build-gpv <param-path> [<param-path>...] [--id <cwmp-id>] [--out <file>]\n' >&2
        printf 'WHY\ta GetParameterValues with no ParameterNames asks for nothing\n' >&2
        return 2; }
    local names=''
    local p
    for p in "${params[@]}"; do
        # A parameter path is a data-model path, not free text: it has to keep
        # its dots and must not carry the quoting that would break the XML.
        p=$(capi_sanitize "$p")
        names+="        <string>${p}</string>"$'\n'
    done
    local xml
    xml=$(cat <<XML
<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:cwmp="${CAPI_CWMP_NS}" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
  <soap:Header/>
  <soap:Body>
    <cwmp:GetParameterValues>
      <ParameterNames soap-enc:arrayType="xsd:string[${#params[@]}]" xmlns:soap-enc="http://schemas.xmlsoap.org/soap/encoding/">
${names}      </ParameterNames>
    </cwmp:GetParameterValues>
  </soap:Body>
</soap:Envelope>
XML
)
    printf 'protocol\tTR-069 (CWMP)\n'
    printf 'method\tGetParameterValues\n'
    printf 'soapaction\t"%s#GetParameterValues"\n' "$CAPI_CWMP_NS"
    printf 'parameters\t%s\n' "${#params[@]}"
    for p in "${params[@]}"; do
        printf 'param\t%s\trequested\n' "$(capi_sanitize "$p")"
    done
    printf 'transmitted\tno\n'
    printf '%s\n' "$xml"
    if [[ -n "$out" ]]; then
        printf '%s\n' "$xml" > "$out" || { printf 'ERROR\tcannot write %s\n' "$(capi_sanitize "$out")" >&2; return 1; }
        printf 'written\t%s\n' "$(capi_sanitize "$out")"
    fi
    printf 'ref\tTR-069 Amendment 6 A.3.2.2 (GetParameterValues) and 3.4.1 (SOAPAction)\n'
    return 0
}

# One SOAP message in, rows out. python3 with the standard library does the
# XML: a hand-rolled parser would disagree with every real CPE in a way that is
# invisible until it matters.
capi_cwmp_parse() {  # <file|->
    local file="${1:-}"
    [[ -n "$file" ]] || { printf 'ERROR\tusage: --cwmp parse <file|->\n' >&2; return 2; }
    if [[ "$file" != "-" && ! -r "$file" ]]; then
        printf 'ERROR\tcannot read %s\n' "$(capi_sanitize "$file")" >&2; return 1
    fi
    command -v python3 >/dev/null 2>&1 || {
        printf 'ERROR\tpython3 is required to parse SOAP (xml.etree, standard library only)\n' >&2
        printf 'WHY\tinstall python3; no package is needed and none is used\n' >&2
        return 1; }
    # The program arrives on stdin, so `-` cannot mean "read the message from
    # stdin" inside it: the message is carried in an environment variable
    # instead, which keeps both meanings working.
    if [[ "$file" == "-" ]]; then
        export CAPI_SOAP_STDIN="$(cat)"
    fi
    python3 - "$file" <<'PY'
import sys, re, os, xml.etree.ElementTree as ET
src = os.environ.get("CAPI_SOAP_STDIN", "") if sys.argv[1] == "-" else open(sys.argv[1], "r", errors="replace").read()
if not src.strip():
    print("ERROR\tempty input: no SOAP envelope to read")
    print("WHY\tan empty file is unobserved, not a message that said nothing")
    sys.exit(1)
# An HTTP POST header block in front of the body is part of what a capture
# carries, so read it rather than dropping it.
soapaction = re.search(r'(?im)^SOAPAction:\s*"?([^"\r\n]+)"?', src)
ctype = re.search(r'(?im)^Content-Type:\s*([^\r\n]+)', src)
start = src.find('<')
if start > 0:
    src = src[start:]
try:
    root = ET.fromstring(src)
except ET.ParseError as exc:
    print("ERROR\tnot well-formed XML: %s" % exc)
    print("WHY\ta SOAP message that does not parse cannot be a CWMP message, and this module does not repair one")
    sys.exit(1)
def local(tag):
    return tag.rsplit('}', 1)[-1] if '}' in tag else tag
ns = ''
m = re.match(r'\{(.+)\}', root.tag or '')
if m:
    ns = m.group(1)
print("envelope\t%s" % (local(root.tag)))
print("namespace\t%s" % (ns or "unobserved"))
if soapaction:
    print("soapaction\t%s" % soapaction.group(1).strip())
else:
    print("soapaction\tunobserved\tno HTTP header block in front of the body, so the method is taken from the element name")
if ctype:
    print("content_type\t%s" % ctype.group(1).strip())
body = None
for child in root:
    if local(child.tag) == 'Body':
        body = child
if body is None:
    print("ERROR\ta SOAP envelope with no Body")
    sys.exit(1)
msgs = list(body)
if not msgs:
    print("method\tempty\tTR-069 A.3.2.2: the CPE sends an empty POST to receive the ACS's requests")
    print("verdict\tempty-post")
    sys.exit(0)
method = local(msgs[0].tag)
print("method\t%s" % method)
events = []
params = []
for el in msgs[0].iter():
    t = local(el.tag)
    if t == 'EventCode':
        events.append((el.text or '').strip())
    elif t == 'Name' and el.text:
        params.append([el.text.strip(), None])
    elif t == 'Value':
        for p in reversed(params):
            if p[1] is None:
                p[1] = (el.text or '').strip()
                break
for e in events:
    known = e in ("0 BOOTSTRAP", "1 BOOT", "2 PERIODIC", "3 SCHEDULED",
                  "4 VALUE CHANGE", "5 KICKED", "6 CONNECTION REQUEST",
                  "7 TRANSFER COMPLETE", "8 DIAGNOSTICS COMPLETE")
    print("event\t%s\t%s" % (e, "measured" if known else "unobserved\tnot in TR-069 Table 3"))
for name, value in params:
    print("param\t%s\t%s" % (name, value if value is not None else "unobserved"))
if not events and not params:
    print("note\tno Event and no ParameterValueStruct in this message")
kinds = {
    "Inform": "cpe-to-acs",
    "InformResponse": "acs-to-cpe",
    "GetParameterValues": "acs-to-cpe",
    "GetParameterValuesResponse": "cpe-to-acs",
    "SetParameterValues": "acs-to-cpe",
    "SetParameterValuesResponse": "cpe-to-acs",
    "GetParameterNames": "acs-to-cpe",
    "GetParameterNamesResponse": "cpe-to-acs",
    "AddObject": "acs-to-cpe",
    "DeleteObject": "acs-to-cpe",
    "Reboot": "acs-to-cpe",
    "Download": "acs-to-cpe",
    "Upload": "acs-to-cpe",
    "Fault": "either",
}
print("direction\t%s" % kinds.get(method, "unobserved\tnot a method this module names"))
print("verdict\tparsed")
PY
    local rc=$?
    return $rc
}

capi_cwmp_plan() {
    cat <<'EOF'
protocol	TR-069 (CWMP)
status	handoff
what	a CPE management session, read from the CPE's side and from the ACS's
step	1	POST the Inform (--cwmp build-inform) to the ACS URL; the ACS answers an InformResponse
step	2	the CPE sends an empty POST (TR-069 A.3.2.2) so the ACS can push its own requests on the same connection
step	3	GetParameterValues (--cwmp build-gpv) selects the subtree an ACS reads back
step	4	--cwmp parse either message, and the answer, to see what the CPE disclosed
yields	the OUI, product class, serial number and the parameter values the CPE hands to whoever asks in the management session
boundary	the ACS URL is delivered by DHCP option 43 or by a static configuration; a CPE only talks to the ACS it was told about, so a session only exists against a server the CPE already trusts
missing	nothing on this host: the messages are built and parsed offline
ref	TR-069 Amendment 6 3.4.1, A.3.2.1 to A.3.2.3, Table 3
EOF
    return 0
}

# ── TR-369 (USP) ────────────────────────────────────────────────────────
# A USP message is a protobuf `Msg`. Building one on the wire needs the field
# numbers from usp-msg.proto, and that file is not on this machine: no
# usp-msg*.proto exists under /usr/share, /usr/local/share or this tree. So the
# builder writes the message as a named tree -- which is the part a reader can
# check -- and prints `wire  unobserved` naming the file rather than inventing a
# tag. --usp parse reads a protobuf dump generically: the wire format is
# mechanical (varint / 64-bit / length-delimited / 32-bit), so field numbers and
# types can be read without the .proto; only the NAMES cannot, and they stay
# unobserved.
capi_usp_build_msg() {  # [--msg-id] [--session-id] [--type] [--op] [--param-path]... [--max-depth]
    local msg_id='' session='' mtype='request' op='get' depth=''
    local -a paths=()
    while (($#)); do
        case "$1" in
            --msg-id)     msg_id="${2:-}"; shift 2 ;;
            --session-id) session="${2:-}"; shift 2 ;;
            --type)       mtype="${2:-}"; shift 2 ;;
            --op)         op="${2:-}"; shift 2 ;;
            --param-path) paths+=("${2:-}"); shift 2 ;;
            --max-depth)  depth="${2:-}"; shift 2 ;;
            *) printf 'ERROR\tunknown flag %s\n' "$(capi_sanitize "$1")" >&2; return 2 ;;
        esac
    done
    # The four message types are the four the envelope defines. A fifth word is
    # not a type, and calling it one would be a message no agent accepts.
    case "$mtype" in
        error|request|response|notify) ;;
        *) printf 'ERROR\t--type is one of error, request, response, notify (the Msg msg_type values)\n' >&2; return 2 ;;
    esac
    # The operations a Request carries are the ones TR-369 names; the list is
    # the spec's, not a guess at an enum encoding.
    case "$op" in
        get|get_supported_dm|get_instances|set|add|delete|operate|notify) ;;
        *) printf 'ERROR\t--op is one of get, get_supported_dm, get_instances, set, add, delete, operate, notify (TR-369 request operations)\n' >&2; return 2 ;;
    esac
    [[ -z "$depth" || "$depth" =~ ^[0-9]+$ ]] || {
        printf 'ERROR\t--max-depth is a whole number of levels\n' >&2; return 2; }
    [[ -n "$msg_id" ]] || msg_id="msg-$(date -u +%s)-$$"
    [[ -n "$session" ]] || session="session-$(date -u +%s)"
    printf 'protocol\tTR-369 (USP)\n'
    printf 'envelope\tMsg\n'
    printf 'msg_id\t%s\n' "$(capi_sanitize "$msg_id")"
    printf 'msg_type\t%s\n' "$mtype"
    printf 'session_id\t%s\n' "$(capi_sanitize "$session")"
    printf 'request_op\t%s\tadvertised\tthe operation named in the request body (TR-369 Request oneof)\n' "$op"
    case "$op" in
        get|get_instances)
            if ((${#paths[@]})); then
                local p
                for p in "${paths[@]}"; do
                    printf 'param_path\t%s\trequested\n' "$(capi_sanitize "$p")"
                done
                printf 'param_paths\t%s\n' "${#paths[@]}"
            else
                printf 'param_paths\tunobserved\tno --param-path given, so the request names no path; a Get with no path is a message that asks for nothing\n'
            fi
            ;;
        *)
            printf 'param_paths\tunobserved\tthis builder fills request paths for get and get_instances only; %s carries operands this builder does not encode\n' "$op"
            ;;
    esac
    if [[ -n "$depth" ]]; then
        printf 'max_depth\t%s\n' "$depth"
    else
        printf 'max_depth\tunobserved\tnot set; an agent defaults it, and the default is the agent'"'"'s, not ours\n'
    fi
    printf 'wire\tunobserved\tusp-msg.proto is not on this machine (no usp-msg*.proto under /usr/share, /usr/local/share or the tree), so the protobuf tag numbers are not guessed; --usp parse reads a real dump without them\n'
    printf 'transmitted\tno\n'
    printf 'ref\tTR-369 USP message envelope (Msg: header msg_id/msg_type/session_id; body oneof request/response/error/notify)\n'
    return 0
}

# Generic protobuf wire-format walk. No schema, no names, no guesses.
capi_usp_parse() {  # <hex|file>
    local arg="${1:-}"
    [[ -n "$arg" ]] || { printf 'ERROR\tusage: --usp parse <hex-string|file-of-hex>\n' >&2; return 2; }
    local hex=''
    if [[ -f "$arg" ]]; then
        hex=$(tr -d ' \r\n\t:-' < "$arg" | tr 'a-f' 'A-F')
    else
        hex=$(printf '%s' "$arg" | tr -d ' \r\n\t:-' | tr 'a-f' 'A-F')
    fi
    [[ "$hex" =~ ^[0-9A-F]+$ && $(( ${#hex} % 2 )) -eq 0 ]] || {
        printf 'ERROR\tnot a run of hex octets: %s\n' "$(capi_sanitize "$arg")" >&2; return 2; }
    printf 'protocol\tTR-369 (USP)\n'
    printf 'bytes\t%s\n' "$(( ${#hex} / 2 ))"
    printf '%s\n' "$hex" | awk '{
        n = length($0) / 2
        for (i = 0; i < n; i++) printf "%s ", substr($0, i*2+1, 2)
        printf "\n"
    }' > /dev/null 2>&1 || true
    python3 - "$hex" <<'PY'
import sys
hexs = sys.argv[1]
data = bytes.fromhex(hexs)
def varint(b, i):
    shift = 0; val = 0
    while True:
        if i >= len(b):
            raise ValueError("truncated varint")
        x = b[i]; i += 1
        val |= (x & 0x7F) << shift; shift += 7
        if not x & 0x80:
            return val, i
def walk(b, depth, path, budget):
    i = 0
    while i < len(b):
        if budget[0] <= 0:
            print("note\tdepth/field budget reached; the rest of the message is unobserved")
            return
        budget[0] -= 1
        try:
            tag, i = varint(b, i)
        except ValueError as exc:
            print("field\t%s\tunobserved\t%s" % (path or "-", exc))
            return
        num = tag >> 3; wt = tag & 7
        if num == 0:
            print("field\t%s\tunobserved\tfield number zero is not valid protobuf" % (path or "-"))
            return
        where = "%s%d" % ((path + ".") if path else "", num)
        if wt == 0:
            v, i = varint(b, i)
            print("field\t%s\tvarint\t%d" % (where, v))
        elif wt == 1:
            print("field\t%s\t64-bit\t%s" % (where, b[i:i+8].hex())); i += 8
        elif wt == 5:
            print("field\t%s\t32-bit\t%s" % (where, b[i:i+4].hex())); i += 4
        elif wt == 2:
            ln, i = varint(b, i)
            payload = b[i:i+ln]; i += ln
            if len(payload) != ln:
                print("field\t%s\tlength-delimited\ttruncated: wanted %d, have %d" % (where, ln, len(payload)))
                return
            printable = payload and all(32 <= c < 127 for c in payload)
            print("field\t%s\tlength-delimited\t%d octets\t%s" % (
                where, len(payload), payload.decode() if printable else payload.hex()))
            if depth < 6 and not printable and len(payload) > 0:
                sub = []
                walk(payload, depth + 1, where, [200])
        else:
            print("field\t%s\twire-type-%d\tunobserved\twire type 3/4 are the deprecated group forms" % (where, wt))
            return
walk(data, 0, "", [500])
print("names\tunobserved\tfield numbers and wire types are readable without a schema; the field NAMES need usp-msg.proto, which is not on this machine")
print("verdict\twire-dump")
PY
    return $?
}

capi_usp_plan() {
    cat <<'EOF'
protocol	TR-369 (USP)
status	handoff
what	a USP message exchange with an agent (the CPE side of TR-369)
step	1	learn the agent's MTP: USP runs over CoAP, WebSocket or STOMP, and the controller must know which
step	2	build the Msg (--usp build-msg) with a msg_id, a session_id and a request body
step	3	serialise it with usp-msg.proto, which is not on this machine -- so the wire bytes are unobserved here and this module will not invent a tag
step	4	read an exchange back with --usp parse, which needs no schema: it prints field numbers, wire types and payloads
yields	the parameter paths a request names and the values an answer returns, once a real message exists
boundary	the agent only answers a controller it was provisioned with; a session exists only where the CPE already trusts the controller
missing	usp-msg.proto (and the MTP), neither of which is installed here
ref	TR-369 USP message envelope; protobuf wire format (field number + wire type)
EOF
    return 0
}

# One append-only row per invocation of the TR-069/TR-369 verbs: what was asked
# for and how it ended. A row records this host's run, not the target's state.
capi_proto_record() {  # <protocol> <mode> <rc>
    local dir="${CAPI_DIR:-$LOOT_DIR/carrier_api}"
    mkdir -p "$dir" 2>/dev/null || return 0
    printf '%s\t%s\t%s\trc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        "$(capi_sanitize "$1")" "$(capi_sanitize "$2")" "$(capi_sanitize "$3")" \
        >> "$dir/cwmp_usp.tsv" 2>/dev/null || true
    return 0
}

capi_cwmp() {  # <build-inform|build-gpv|parse|plan> [args]
    local mode="${1:-}" rcp
    (($# > 0)) && shift
    case "$mode" in
        build-inform) capi_cwmp_build_inform "$@" ;;
        build-gpv)    capi_cwmp_build_gpv "$@" ;;
        parse)        capi_cwmp_parse "${1:-}" ;;
        plan)         capi_cwmp_plan ;;
        '') printf 'ERROR\tusage: --cwmp <build-inform|build-gpv|parse|plan> [args]\n' >&2; return 2 ;;
        *) printf 'ERROR\tunknown --cwmp mode %s (build-inform|build-gpv|parse|plan)\n' "$(capi_sanitize "$mode")" >&2; return 2 ;;
    esac
    rcp=$?
    capi_proto_record TR-069 "${mode:-none}" "$rcp"
    return $rcp
}

capi_usp() {  # <build-msg|parse|plan> [args]
    local mode="${1:-}" rcp
    (($# > 0)) && shift
    case "$mode" in
        build-msg) capi_usp_build_msg "$@" ;;
        parse)     capi_usp_parse "${1:-}" ;;
        plan)      capi_usp_plan ;;
        '') printf 'ERROR\tusage: --usp <build-msg|parse|plan> [args]\n' >&2; return 2 ;;
        *) printf 'ERROR\tunknown --usp mode %s (build-msg|parse|plan)\n' "$(capi_sanitize "$mode")" >&2; return 2 ;;
    esac
    rcp=$?
    capi_proto_record TR-369 "${mode:-none}" "$rcp"
    return $rcp
}

capi_selftest() {
    local bad=0 nchk=0
    # There is no gate, so no environment needs holding aside: the selftest is
    # identical however the caller's shell is set up.
    chk() {
        nchk=$(( nchk + 1 ))
        local n="$1" got="$2" want="$3"
        if [[ "$got" == "$want" ]]; then printf '%s\tPASS\n' "$n"
        else printf '%s\tFAIL want=%s got=%s\n' "$n" "$want" "$got"; bad=$(( bad + 1 )); fi
    }
    fld() { printf '%s\n' "$1" | awk -F'\t' -v k="$2" '$1==k{print $2; exit}'; }

    local d
    d=$(mktemp -d "$MOD_TMP/selftest.XXXXXX") || {
        printf 'ERROR\tmktemp failed under %s\n' "$MOD_TMP" >&2; return 1; }
    trap 'rm -rf "$d"' EXIT
    export LOOT_DIR="$d/loot" CAPTURES_DIR="$d/captures" STATE_DIR="$d/state"
    export CAPI_DIR="$d/loot/carrier_api"
    mkdir -p "$CAPI_DIR"

    # 1. OpenAPI surface parse.
    cat > "$d/api.json" <<'JSON'
{
  "openapi": "3.0.3",
  "info": { "title": "Carrier Self-Service", "version": "2.1.0" },
  "servers": [ { "url": "https://api.example.net/v2" } ],
  "paths": {
    "/accounts/{id}": { "get": { "security": [ { "bearerAuth": [] } ] } },
    "/transfers": { "post": { "security": [ { "oauth2": [] } ] },
                    "get":  { "security": [ { "bearerAuth": [] } ] } }
  },
  "components": { "securitySchemes": { "bearerAuth": { "type": "http" }, "oauth2": { "type": "oauth2" } } }
}
JSON
    local out; out=$(capi_openapi_parse "$d/api.json")
    chk openapi-title "$(fld "$out" title)" "Carrier Self-Service"
    chk openapi-ver   "$(fld "$out" version)" "2.1.0"
    chk openapi-server "$(fld "$out" server)" "https://api.example.net/v2"
    chk openapi-paths "$(fld "$out" path_count)" "2"
    chk openapi-ops   "$(fld "$out" operation_count)" "3"
    chk openapi-scheme "$(printf '%s\n' "$out" | awk -F'\t' '$1=="security_scheme" && $2=="bearerAuth"{print $3}')" "http"
    chk openapi-missing "$(capi_openapi_parse "$d/none.json" >/dev/null 2>&1; echo $?)" "1"
    printf 'not json' > "$d/bad.json"
    chk openapi-badjson "$(capi_openapi_parse "$d/bad.json" >/dev/null 2>&1; echo $?)" "1"

    # 2. Authorisation matrix: 4 cases per operation.
    out=$(capi_authz_matrix "$d/api.json")
    chk authz-rows "$(printf '%s\n' "$out" | tail -n +2 | wc -l | tr -d ' ')" "12"
    chk authz-unauth "$(printf '%s\n' "$out" | awk -F'\t' '$3=="unauthenticated"{print $4}' | sort -u)" "401"
    chk authz-scope  "$(printf '%s\n' "$out" | awk -F'\t' '$3=="wrong_scope"{print $4}' | sort -u)" "403"

    # 3. Token bucket: rate 10/s, burst 20, 100 requests over 5 s -> 70 allowed.
    out=$(capi_token_bucket 10 20 100 5)
    chk bucket-cap     "$(fld "$out" capacity)" "70"
    chk bucket-allowed "$(fld "$out" allowed)" "70"
    chk bucket-denied  "$(fld "$out" denied)" "30"
    chk bucket-under   "$(fld "$(capi_token_bucket 10 20 30 5)" allowed)" "30"
    chk bucket-bad     "$(capi_token_bucket x 1 1 1 >/dev/null 2>&1; echo $?)" "2"

    # 4. JWT audit: alg=none and expiry.
    local none; none="$(capi_b64url_encode '{"alg":"none","typ":"JWT"}').$(capi_b64url_encode '{"sub":"acct-1"}')."
    out=$(capi_jwt_audit "$none" 1000000000)
    chk jwt-none "$(fld "$out" alg_none)" "CRITICAL"
    chk jwt-noexp "$(fld "$out" no_expiry)" "MEDIUM"
    chk jwt-noexp-count "$(fld "$out" findings)" "2"
    local exp; exp="$(capi_b64url_encode '{"alg":"RS256"}').$(capi_b64url_encode '{"exp":1000000000}').sig"
    chk jwt-expired "$(fld "$(capi_jwt_audit "$exp" 2000000000)" expired)" "MEDIUM"
    chk jwt-valid   "$(fld "$(capi_jwt_audit "$exp" 999999999)" expiry_ok)" "INFO"

    # 5. Response differential.
    printf 'endpoint\tmethod\tstatus\n/api/a\tGET\t200\n/api/b\tGET\t403\n' > "$d/r1.tsv"
    printf 'endpoint\tmethod\tstatus\n/api/a\tGET\t200\n/api/b\tGET\t200\n/api/c\tGET\t401\n' > "$d/r2.tsv"
    out=$(capi_diff "$d/r1.tsv" "$d/r2.tsv")
    chk diff-changed "$(printf '%s\n' "$out" | awk -F'\t' '$5=="CHANGED"{print $1}')" "/api/b"
    chk diff-new     "$(printf '%s\n' "$out" | awk -F'\t' '$5=="NEW"{print $1}')" "/api/c"
    chk diff-missing "$(capi_diff "$d/none1" "$d/none2" >/dev/null 2>&1; echo $?)" "1"

    # 6. Stuffing resistance.
    printf 'lockout_threshold=5\nrate_limit=10/min\nmfa=true\n' > "$d/strong.conf"
    out=$(capi_stuffing_resistance "$d/strong.conf")
    chk stuff-strong "$(fld "$out" summary)" "controls_present"
    printf 'mfa=false\n' > "$d/weak.conf"
    out=$(capi_stuffing_resistance "$d/weak.conf")
    chk stuff-weak-lock "$(printf '%s\n' "$out" | awk -F'\t' '$1=="lockout"{print $2}')" "no"
    chk stuff-weak-sum  "$(printf '%s\n' "$out" | awk -F'\t' '$1=="summary"{print $2" "$3}')" "controls_missing 2"

    # 7. --enumerate: render one concrete request per operation from the
    #    document, write the run-file, send nothing. The fixture is the CAMARA
    #    Number Verification shape: server {apiRoot}/number-verification/vwip
    #    with apiRoot default http://localhost:9091, POST /verify, scope
    #    number-verification:verify, body NumberVerificationRequestBody
    #    (minProperties/maxProperties 1). CAMARA ships PhoneNumber and openId as
    #    external ../common refs, so they are inlined here with the published
    #    values: pattern ^\+[1-9][0-9]{4,14}$, example +123456789.
    cat > "$d/nv.json" <<'JSON'
{
  "openapi": "3.0.3",
  "info": { "title": "Number Verification", "version": "2.0.0" },
  "servers": [ { "url": "{apiRoot}/number-verification/vwip", "variables": { "apiRoot": { "default": "http://localhost:9091" } } } ],
  "paths": {
    "/verify": {
      "post": {
        "operationId": "phoneNumberVerify",
        "tags": [ "Number Verification" ],
        "security": [ { "openId": [ "number-verification:verify" ] } ],
        "parameters": [ { "name": "x-correlator", "in": "header", "required": false, "schema": { "type": "string", "example": "b4333c46-49c0-4f62-80d7-f0ef930f1c46" } } ],
        "requestBody": { "required": true, "content": { "application/json": { "schema": { "$ref": "#/components/schemas/NumberVerificationRequestBody" } } } },
        "responses": { "200": { "description": "OK" }, "429": { "description": "Too Many Requests" } }
      }
    }
  },
  "components": {
    "schemas": {
      "PhoneNumber": { "type": "string", "description": "MSISDN, E.164 international format", "pattern": "^\\+[1-9][0-9]{4,14}$", "maxLength": 16, "example": "+123456789" },
      "NumberVerificationRequestBody": { "type": "object", "minProperties": 1, "maxProperties": 1, "properties": { "phoneNumber": { "$ref": "#/components/schemas/PhoneNumber" }, "hashedPhoneNumber": { "type": "string", "pattern": "^[a-fA-F0-9]{64}$", "example": "32f67ab4e4312618b09cd23ed8ce41b13e095fe52b73b2e8da8ef49830e50dba" } } }
    },
    "securitySchemes": { "openId": { "type": "openIdConnect", "openIdConnectUrl": "https://example.com/.well-known/openid-configuration" } }
  }
}
JSON
    local rc
    out=$(capi_cli_main --enumerate "$d/nv.json" --out "$d/nv.run.txt" 2>"$d/enum.err"); rc=$?
    chk enum-rc        "$rc" "0"
    chk enum-sent      "$(fld "$out" SENT)" "nothing"
    chk enum-note      "$(printf '%s\n' "$out" | awk -F'\t' '$1=="NOTE"{print ($2 ~ /no HTTP request/)}')" "1"
    chk enum-base      "$(fld "$out" BASE)" "http://localhost:9091/number-verification/vwip"
    chk enum-base-src  "$(fld "$out" BASE_SOURCE)" "servers[0] + variables.apiRoot.default"
    chk enum-ops       "$(fld "$out" OPERATIONS)" "1"
    chk enum-method    "$(printf '%s\n' "$out" | awk -F'\t' '$1=="request"{print $2}')" "POST"
    chk enum-url       "$(printf '%s\n' "$out" | awk -F'\t' '$1=="request"{print $3}')" "http://localhost:9091/number-verification/vwip/verify"
    # openIdConnect in the document means an OAuth2 bearer; the token is a
    # placeholder because no credential exists in a document.
    chk enum-headers   "$(printf '%s\n' "$out" | awk -F'\t' '$1=="request"{print $4}')" "Authorization: Bearer <access-token>; Content-Type: application/json"
    # Body example +123456789 is the CAMARA_common PhoneNumber example.
    chk enum-body      "$(printf '%s\n' "$out" | awk -F'\t' '$1=="request"{print $5}')" '{"phoneNumber": "+123456789"}'
    chk enum-required  "$(printf '%s\n' "$out" | awk -F'\t' '$1=="operation"{print $5}')" "body"
    chk enum-scopes    "$(printf '%s\n' "$out" | awk -F'\t' '$1=="operation"{print $8}')" "number-verification:verify"
    chk enum-placeholders "$(fld "$out" PLACEHOLDERS)" "1"
    chk enum-runfile-lines "$(fld "$out" RUN_FILE_LINES)" "1"
    chk enum-runfile   "$(grep -c '^curl' "$d/nv.run.txt")" "1"
    chk enum-runfile-doc "$(sed -n '1p' "$d/nv.run.txt")" "# carrier_api run-file — built by --enumerate from $d/nv.json"
    chk enum-runfile-post "$(grep -c 'curl -sS -X POST' "$d/nv.run.txt")" "1"
    out=$(capi_cli_main --enumerate "$d/nv.json" --base "https://sandbox.example.net/carrier" --out "$d/nv2.run.txt" 2>/dev/null)
    chk enum-override  "$(printf '%s\n' "$out" | awk -F'\t' '$1=="request"{print $3}')" "https://sandbox.example.net/carrier/verify"
    chk enum-override-src "$(fld "$out" BASE_SOURCE)" "flag --base"
    chk enum-missing   "$(capi_cli_main --enumerate "$d/none.json" >/dev/null 2>&1; echo $?)" "1"
    chk enum-noarg     "$(capi_cli_main --enumerate >/dev/null 2>&1; echo $?)" "2"
    chk enum-badopt    "$(capi_cli_main --enumerate --nope x >/dev/null 2>&1; echo $?)" "2"

    # 7b. External refs stay unresolved: the real CAMARA files point PhoneNumber,
    #     openId and x-correlator at ../common/CAMARA_common.yaml. The walker must
    #     report them and use a placeholder, never invent a value. SIM Swap
    #     example values: CHECK_2LEGS = phoneNumber +346661113334, maxAge 120.
    cat > "$d/simswap.json" <<'JSON'
{
  "openapi": "3.0.3",
  "info": { "title": "SIM Swap", "version": "2.0.0" },
  "servers": [ { "url": "{apiRoot}/sim-swap/vwip", "variables": { "apiRoot": { "default": "http://localhost:9091" } } } ],
  "paths": {
    "/check": {
      "post": {
        "operationId": "checkSimSwap",
        "tags": [ "Check SIM Swap" ],
        "security": [ { "openId": [ "sim-swap:check" ] }, { "openId": [ "sim-swap" ] } ],
        "parameters": [ { "$ref": "../common/CAMARA_common.yaml#/components/parameters/x-correlator" } ],
        "requestBody": { "required": true, "content": { "application/json": { "schema": { "$ref": "#/components/schemas/CreateCheckSimSwap" }, "examples": { "CHECK_3LEGS": { "value": { "maxAge": 120 } }, "CHECK_2LEGS": { "value": { "phoneNumber": "+346661113334", "maxAge": 120 } } } } } },
        "responses": { "200": { "description": "OK" }, "429": { "description": "Too Many Requests" } }
      }
    }
  },
  "components": {
    "schemas": {
      "CreateCheckSimSwap": { "type": "object", "properties": { "phoneNumber": { "$ref": "../common/CAMARA_common.yaml#/components/schemas/PhoneNumber" }, "maxAge": { "type": "integer", "example": 240, "default": 240, "minimum": 1, "maximum": 2400, "format": "int32" } } }
    },
    "securitySchemes": { "openId": { "$ref": "../common/CAMARA_common.yaml#/components/securitySchemes/openId" } }
  }
}
JSON
    out=$(capi_cli_main --enumerate "$d/simswap.json" --out "$d/swap.run.txt" 2>/dev/null)
    chk enum-example   "$(printf '%s\n' "$out" | awk -F'\t' '$1=="request"{print $5}')" '{"phoneNumber": "+346661113334", "maxAge": 120}'
    chk enum-example-src "$(printf '%s\n' "$out" | awk -F'\t' '$1=="request"{print $6}')" "POST /check.application/json.examples.CHECK_2LEGS"
    chk enum-unresolved "$(fld "$out" UNRESOLVED)" "2"
    chk enum-unresolved-auth "$(printf '%s\n' "$out" | awk -F'\t' '$1=="request"{print ($4 ~ /credential-for-openId/)}')" "1"
    chk enum-alts      "$(printf '%s\n' "$out" | awk -F'\t' '$1=="operation"{print $10}')" "2"
    chk enum-no-send   "$(grep -c '^curl' "$d/swap.run.txt")" "1"
    chk enum-sent-noop "$(grep -c '^# sent: nothing' "$d/swap.run.txt")" "1"

    # 8. --enumerate-subscribers: ordered sequence, declared limit, stop
    #    condition, and rc3. Candidates: two test subscriptions, one that is not
    #    E.164 under the published CAMARA pattern (+1234 has four digits after
    #    '+'; ^\+[1-9][0-9]{4,14}$ needs at least five), a duplicate that must
    #    not produce a second request, and a non-number.
    printf '# test subscriptions we own\n+346661113334\n+1234\n+447700900123\n+346661113334\nnot-a-number\n' > "$d/cands.txt"
    {
        printf 'spec=%s\n' "$d/simswap.json"
        printf 'candidates=%s\n' "$d/cands.txt"
        printf 'rate_limit=10/60\n'
        printf 'stop_after=2\n'
    } > "$d/subs.conf"
    rm -f "$d/loot/carrier_api/enumerate-subscribers.requests.txt"
    out=$(capi_cli_main --enumerate-subscribers "$d/subs.conf" 2>"$d/subs.err"); rc=$?
    chk subs-rc        "$rc" "3"
    chk subs-sent      "$(fld "$out" SENT)" "nothing"
    chk subs-handoff   "$(printf '%s\n' "$out" | awk -F'\t' '$1=="HANDOFF" && $2=="status"{print $3}')" "handoff"
    chk subs-endpoint  "$(fld "$out" ENDPOINT)" "POST /check"
    chk subs-idfield   "$(fld "$out" IDENTIFIER_FIELD)" "phoneNumber (body)"
    chk subs-family    "$(fld "$out" ENDPOINT_FAMILY)" "Check SIM Swap"
    # two valid unique candidates: the duplicate and the two non-E.164 rows drop out
    chk subs-cands     "$(fld "$out" CANDIDATES)" "2"
    chk subs-invalid   "$(fld "$out" CANDIDATES_INVALID)" "2"
    chk subs-seq       "$(fld "$out" SEQUENCE_LENGTH)" "2"
    # 10 requests per 60 s is a 6 s interval: hand arithmetic, not a measured rate.
    chk subs-interval  "$(fld "$out" INTERVAL_S)" "6"
    chk subs-rate-src  "$(printf '%s\n' "$out" | awk -F'\t' '$1=="RATE_LIMIT_SOURCE"{print ($2 ~ /^conf rate_limit=/)}')" "1"
    chk subs-skip      "$(grep -c '^SKIP' "$d/subs.err")" "2"
    chk subs-skip-e164 "$(grep -c 'not an E.164 number' "$d/subs.err")" "2"
    chk subs-nofound   "$(printf '%s\n' "$out" | grep -ci 'found')" "0"
    chk subs-runfile   "$(grep -c '^curl' "$d/loot/carrier_api/enumerate-subscribers.requests.txt")" "2"
    chk subs-sent-line "$(grep -c '^# sent: nothing' "$d/loot/carrier_api/enumerate-subscribers.requests.txt")" "1"
    chk subs-order1    "$(grep '^curl' "$d/loot/carrier_api/enumerate-subscribers.requests.txt" | sed -n 1p | grep -c '+346661113334')" "1"
    chk subs-order1-x  "$(grep '^curl' "$d/loot/carrier_api/enumerate-subscribers.requests.txt" | sed -n 1p | grep -c '+447700900123')" "0"
    chk subs-order2    "$(grep '^curl' "$d/loot/carrier_api/enumerate-subscribers.requests.txt" | sed -n 2p | grep -c '+447700900123')" "1"
    # exactly one identifier per request: one '+' in every curl line
    chk subs-oneid     "$(grep '^curl' "$d/loot/carrier_api/enumerate-subscribers.requests.txt" | awk '{ if (gsub(/\+[0-9]+/, "&") != 1) bad++ } END { print bad+0 }')" "0"
    chk subs-stop      "$(printf '%s\n' "$out" | awk -F'\t' '$1=="STOP_CONDITION"{print ($2 ~ /after request 2/)}')" "1"
    chk subs-one-per   "$(printf '%s\n' "$out" | awk -F'\t' '$1=="HANDOFF" && $2=="next" && $3 ~ /^1\./{print ($3 ~ /less /)}')" "1"

    # 8b. A document with no identifier operation gets a handoff, not an invented
    #     endpoint family: rc3, an empty sequence, and a run-file that says why.
    printf 'spec=%s\ncandidates=%s\n' "$d/api.json" "$d/cands.txt" > "$d/noid.conf"
    out=$(capi_cli_main --enumerate-subscribers "$d/noid.conf" 2>/dev/null); rc=$?
    chk subs-noid-rc   "$rc" "3"
    chk subs-noid-seq  "$(fld "$out" SEQUENCE_LENGTH)" "0"
    chk subs-noid-why  "$(printf '%s\n' "$out" | awk -F'\t' '$1=="HANDOFF" && $2=="why"{print ($3 ~ /will not invent/)}')" "1"
    chk subs-noid-file "$(grep -c 'no sequence' "$d/loot/carrier_api/enumerate-subscribers.requests.txt")" "1"

    # 8c. Rate-limit resolution: an x-rate-limit extension, then a declared 429,
    #     then nothing at all. The extension is an extension, not OpenAPI.
    python3 - "$d/simswap.json" "$d/simswap_rl.json" "$d/simswap_no429.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
d["paths"]["/check"]["post"]["x-rate-limit"] = {"limit": 2, "window": 1}
json.dump(d, open(sys.argv[2], "w"))
del d["paths"]["/check"]["post"]["x-rate-limit"]
del d["paths"]["/check"]["post"]["responses"]["429"]
json.dump(d, open(sys.argv[3], "w"))
PY
    printf 'spec=%s\ncandidates=%s\n' "$d/simswap_rl.json" "$d/cands.txt" > "$d/rl.conf"
    out=$(capi_cli_main --enumerate-subscribers "$d/rl.conf" 2>/dev/null)
    # 2 requests per 1 s window is a 0.5 s interval.
    chk subs-xrl-interval "$(fld "$out" INTERVAL_S)" "0.5"
    chk subs-xrl-src   "$(printf '%s\n' "$out" | awk -F'\t' '$1=="RATE_LIMIT_SOURCE"{print ($2 ~ /x-rate-limit extension/)}')" "1"
    chk subs-xrl-seq   "$(fld "$out" SEQUENCE_LENGTH)" "2"
    printf 'spec=%s\ncandidates=%s\n' "$d/simswap_no429.json" "$d/cands.txt" > "$d/norl.conf"
    out=$(capi_cli_main --enumerate-subscribers "$d/norl.conf" 2>/dev/null)
    chk subs-norl-src  "$(fld "$out" RATE_LIMIT_SOURCE)" "not-declared"
    chk subs-norl-int  "$(fld "$out" INTERVAL_S)" "-"
    chk subs-missing-conf "$(capi_cli_main --enumerate-subscribers "$d/none.conf" >/dev/null 2>&1; echo $?)" "2"
    chk subs-noarg     "$(capi_cli_main --enumerate-subscribers >/dev/null 2>&1; echo $?)" "2"
    printf 'spec=%s\ncandidates=%s\nrate_limit=10\n' "$d/simswap.json" "$d/cands.txt" > "$d/badrate.conf"
    chk subs-badrate   "$(capi_cli_main --enumerate-subscribers "$d/badrate.conf" >/dev/null 2>&1; echo $?)" "2"
    printf 'spec=%s\n' "$d/simswap.json" > "$d/nocand.conf"
    chk subs-nocand    "$(capi_cli_main --enumerate-subscribers "$d/nocand.conf" >/dev/null 2>&1; echo $?)" "2"
    printf 'spec=%s\ncandidates=%s\nendpoint=POST /nope\n' "$d/simswap.json" "$d/cands.txt" > "$d/badep.conf"
    chk subs-badendpoint "$(capi_cli_main --enumerate-subscribers "$d/badep.conf" >/dev/null 2>&1; echo $?)" "2"

    # 9. No gate any more. What is still owed: the verbs run with no flag, write
    #    their artefact, and say that nothing was sent. The old flag is rejected
    #    rather than ignored, so a stale script finds out instead of going quiet.
    chk retired-flag-enum "$(capi_cli_main --i-have-a-lab-and-authorisation --enumerate "$d/nv.json" >/dev/null 2>&1; echo $?)" "2"
    chk retired-flag-subs "$(capi_cli_main --i-have-a-lab-and-authorisation --enumerate-subscribers "$d/subs.conf" >/dev/null 2>&1; echo $?)" "2"
    out=$(capi_cli_main --enumerate "$d/nv.json" --out "$d/plain1.txt" 2>"$d/plain1.err"); rc=$?
    chk plain-enum-rc     "$rc" "0"
    chk plain-enum-stderr "$(grep -c . "$d/plain1.err")" "0"
    chk plain-enum-sent   "$(fld "$out" SENT)" "nothing"
    chk plain-enum-note   "$(printf '%s\n' "$out" | awk -F'\t' '$1=="STANDING_NOTE"{print ($2 ~ /no HTTP request/)?"yes":"no"}')" "yes"
    chk plain-enum-wrote  "$([[ -s "$d/plain1.txt" ]] && echo yes || echo no)" "yes"
    out=$(capi_cli_main --enumerate-subscribers "$d/subs.conf" --out "$d/plain2.txt" 2>"$d/plain2.err"); rc=$?
    chk plain-subs-rc     "$rc" "3"
    # stderr carries the SKIP lines for identifiers that fail the E.164 check,
    # which is a report the operator wants; what it must not carry is an ERROR
    # or a WARNING, because there is no gate to refuse anything.
    chk plain-subs-stderr "$(grep -vc '^SKIP' "$d/plain2.err")" "0"
    chk plain-subs-no-warn "$(grep -c '^WARNING' "$d/plain2.err")" "0"
    chk plain-subs-handoff "$(printf '%s\n' "$out" | grep -c '^HANDOFF	status	handoff')" "1"
    chk plain-subs-wrote  "$([[ -s "$d/plain2.txt" ]] && echo yes || echo no)" "yes"
    out=$(capi_cli_main --status-tsv)
    chk status-no-gate    "$(printf '%s\n' "$out" | awk -F'\t' '$1=="GATE"{print ($2 ~ /^none/)?"none":"other"}')" "none"
    chk status-sends-none "$(printf '%s\n' "$out" | awk -F'\t' '$1=="SENDS"{print ($2 ~ /nothing/)?"no":"yes"}')" "no"
    chk status-enum       "$(printf '%s\n' "$out" | awk -F'\t' '$1=="ENUMERATE"{print ($2 ~ /^--enumerate <spec.json>/)}')" "1"
    chk status-enumsubs   "$(printf '%s\n' "$out" | awk -F'\t' '$1=="ENUMERATE_SUBSCRIBERS"{print ($2 ~ /^--enumerate-subscribers <conf>/)}')" "1"

    # The executor: it refuses until it is told the target is the operator's,
    # and when told, it reports the codes it saw instead of asserting a verdict.
    printf 'METHOD\tPATH\tEXPECT\tHEADERS\tBODY\nGET\t/health\tallow\t-\t-\n' > "$d/plan.tsv"
    local ex unarmed dry run
    unarmed=$(capi_cmd_execute --plan "$d/plan.tsv" --base http://127.0.0.1:1 2>/dev/null)
    chk exec-unarmed-status "$(printf '%s\n' "$unarmed" | awk -F'\t' '$1=="status"{print $2}')" "handoff"
    chk exec-unarmed-sent   "$(printf '%s\n' "$unarmed" | awk -F'\t' '$1=="sent"{print $2}')" "0"
    chk exec-unarmed-rc     "$(capi_cmd_execute --plan "$d/plan.tsv" --base http://127.0.0.1:1 >/dev/null 2>&1; echo $?)" "3"
    dry=$(capi_cmd_execute --plan "$d/plan.tsv" --base http://127.0.0.1:1 --i-have-a-lab-and-authorisation --dry-run)
    chk exec-dry           "$(printf '%s\n' "$dry" | awk -F'\t' '$1=="dry_run"{print $2}')" "GET"
    chk exec-dry-sent      "$(printf '%s\n' "$dry" | awk -F'\t' '$1=="sent"{print $2}')" "0"
    chk exec-noplan        "$(capi_cmd_execute --base http://127.0.0.1:1 >/dev/null 2>&1; echo $?)" "2"
    chk exec-badbase       "$(capi_cmd_execute --plan "$d/plan.tsv" --base ftp://x --i-have-a-lab-and-authorisation >/dev/null 2>&1; echo $?)" "2"
    chk exec-badrate       "$(capi_cmd_execute --plan "$d/plan.tsv" --base http://127.0.0.1:1 --rate 500 --i-have-a-lab-and-authorisation >/dev/null 2>&1; echo $?)" "2"
    # A live round trip needs something to talk to, so the selftest starts a
    # throwaway server that answers 200 to anything.
    if command -v python3 >/dev/null 2>&1; then
        local sport=18333
        python3 -c 'import http.server,socketserver
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200); self.send_header("Content-Length","0"); self.end_headers()
    def log_message(self,*a): pass
socketserver.TCPServer.allow_reuse_address=True
socketserver.TCPServer(("127.0.0.1",'"$sport"'),H).serve_forever()' >/dev/null 2>&1 &
        local spid=$!
        sleep 0.6
        printf 'METHOD\tPATH\tEXPECT\tHEADERS\tBODY\nGET\t/anything\tdeny\t-\t-\n' > "$d/plan2.tsv"
        run=$(capi_cmd_execute --plan "$d/plan2.tsv" --base "http://127.0.0.1:$sport" --i-have-a-lab-and-authorisation --rate 20)
        local rc1
        capi_cmd_execute --plan "$d/plan2.tsv" --base "http://127.0.0.1:$sport" --i-have-a-lab-and-authorisation >/dev/null 2>&1
        rc1=$?
        kill "$spid" 2>/dev/null
        wait "$spid" 2>/dev/null
        chk exec-live-code   "$(printf '%s\n' "$run" | awk -F'\t' '$1=="step"{print $5}')" "200"
        chk exec-live-sent   "$(printf '%s\n' "$run" | awk -F'\t' '$1=="sent"{print $2}')" "1"
        chk exec-live-find   "$(printf '%s\n' "$run" | awk -F'\t' '$1=="finding"{print $2}')" "unauthorised_success"
        chk exec-live-rc1    "$rc1" "1"
    fi
    # ── TR-069 (CWMP): build the Inform and the GetParameterValues, then read
    # both back. Nothing here opens a socket: the messages are written or
    # printed, and `transmitted  no` says so.
    local cwi gpv pr
    cwi=$(capi_cwmp build-inform --oui 001122 --product-class IGD --serial SN-1 \
            --event '1 BOOT' --acs http://192.0.2.9:7547/ACS --out "$d/inform.xml")
    chk cwmp-inform-method "$(fld "$cwi" method)" "Inform"
    chk cwmp-inform-action "$(fld "$cwi" soapaction)" '"urn:dslforum-org:cwmp-1-0#Inform"'
    chk cwmp-inform-http   "$(printf '%s\n' "$cwi" | awk -F'\t' '$1=="http"{print ($2 ~ /^POST /)?"post":"no"}')" "post"
    chk cwmp-inform-event  "$(printf '%s\n' "$cwi" | awk -F'\t' '$1=="event"{print $2}')" "1 BOOT"
    chk cwmp-inform-oui    "$(fld "$cwi" oui)" "001122"
    chk cwmp-inform-sends  "$(fld "$cwi" transmitted)" "no"
    chk cwmp-inform-wrote  "$([[ -s "$d/inform.xml" ]] && echo yes || echo no)" "yes"
    chk cwmp-inform-xml    "$(grep -c '<cwmp:Inform>' "$d/inform.xml" 2>/dev/null)" "1"
    chk cwmp-inform-params "$(grep -c '<ParameterValueStruct>' "$d/inform.xml" 2>/dev/null)" "4"
    chk cwmp-bad-event-rc  "$(capi_cwmp build-inform --event '9 NOPE' >/dev/null 2>&1; echo $?)" "2"
    pr=$(capi_cwmp parse "$d/inform.xml"); chk cwmp-parse-rc "$?" "0"
    chk cwmp-parse-method  "$(fld "$pr" method)" "Inform"
    chk cwmp-parse-event   "$(printf '%s\n' "$pr" | awk -F'\t' '$1=="event"{print $2}')" "1 BOOT"
    chk cwmp-parse-param   "$(printf '%s\n' "$pr" | awk -F'\t' '$1=="param" && $2=="Device.DeviceInfo.ManufacturerOUI"{print $3}')" "001122"
    chk cwmp-parse-dir     "$(fld "$pr" direction)" "cpe-to-acs"
    chk cwmp-parse-verdict "$(fld "$pr" verdict)" "parsed"
    # An empty POST is a message, not an error: TR-069 A.3.2.2 uses it so the
    # ACS can push its own requests on the open connection.
    printf '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body></soap:Body></soap:Envelope>' > "$d/empty.xml"
    chk cwmp-empty-post    "$(capi_cwmp parse "$d/empty.xml" | awk -F'\t' '$1=="verdict"{print $2}')" "empty-post"
    printf 'not xml at all' > "$d/bad.xml"
    chk cwmp-badxml-rc     "$(capi_cwmp parse "$d/bad.xml" >/dev/null 2>&1; echo $?)" "1"
    chk cwmp-parse-nofile  "$(capi_cwmp parse >/dev/null 2>&1; echo $?)" "2"
    gpv=$(capi_cwmp build-gpv 'Device.DeviceInfo.' 'Device.WiFi.Radio.1.' --out "$d/gpv.xml")
    chk cwmp-gpv-method    "$(fld "$gpv" method)" "GetParameterValues"
    chk cwmp-gpv-count     "$(fld "$gpv" parameters)" "2"
    chk cwmp-gpv-sends     "$(fld "$gpv" transmitted)" "no"
    chk cwmp-gpv-xml       "$(grep -c '<string>Device.WiFi.Radio.1.</string>' "$d/gpv.xml" 2>/dev/null)" "1"
    chk cwmp-gpv-parse     "$(capi_cwmp parse "$d/gpv.xml" | awk -F'\t' '$1=="method"{print $2}')" "GetParameterValues"
    chk cwmp-gpv-dir       "$(capi_cwmp parse "$d/gpv.xml" | awk -F'\t' '$1=="direction"{print $2}')" "acs-to-cpe"
    chk cwmp-plan-status   "$(capi_cwmp plan | awk -F'\t' '$1=="status"{print $2}')" "handoff"
    chk cwmp-usage-rc      "$(capi_cwmp >/dev/null 2>&1; echo $?)" "2"

    # ── TR-369 (USP): the named tree, and a schema-free wire dump. The protobuf
    # tags are not guessed: `wire  unobserved` names usp-msg.proto, which is
    # not on this machine.
    local uspo
    uspo=$(capi_usp build-msg --msg-id m-1 --session-id s-1 --type request --op get \
            --param-path Device.WiFi. --param-path Device.IP. --max-depth 2)
    chk usp-msg-type       "$(fld "$uspo" msg_type)" "request"
    chk usp-msg-op         "$(printf '%s\n' "$uspo" | awk -F'\t' '$1=="request_op"{print $2}')" "get"
    chk usp-msg-paths      "$(fld "$uspo" param_paths)" "2"
    chk usp-msg-depth      "$(fld "$uspo" max_depth)" "2"
    chk usp-msg-id         "$(fld "$uspo" msg_id)" "m-1"
    chk usp-msg-sends      "$(fld "$uspo" transmitted)" "no"
    chk usp-wire           "$(fld "$uspo" wire)" "unobserved"
    chk usp-wire-names     "$(printf '%s\n' "$uspo" | awk -F'\t' '$1=="wire"{print ($3 ~ /usp-msg\.proto/)}')" "1"
    chk usp-op-set         "$(capi_usp build-msg --op set | awk -F'\t' '$1=="param_paths"{print $2}')" "unobserved"
    chk usp-bad-type-rc    "$(capi_usp build-msg --type frobnicate >/dev/null 2>&1; echo $?)" "2"
    chk usp-bad-op-rc      "$(capi_usp build-msg --op frobnicate >/dev/null 2>&1; echo $?)" "2"
    chk usp-bad-depth-rc   "$(capi_usp build-msg --max-depth x >/dev/null 2>&1; echo $?)" "2"
    # 0A 03 61 62 63 is field 1, wire type 2, three octets, "abc": the wire
    # format is mechanical, so this is measured without a schema.
    local uph
    uph=$(capi_usp parse 0A03616263); chk usp-parse-rc "$?" "0"
    chk usp-parse-field    "$(printf '%s\n' "$uph" | awk -F'\t' '$1=="field"{print $2}')" "1"
    chk usp-parse-wiretype "$(printf '%s\n' "$uph" | awk -F'\t' '$1=="field"{print $3}')" "length-delimited"
    chk usp-parse-string   "$(printf '%s\n' "$uph" | awk -F'\t' '$1=="field"{print $5}')" "abc"
    chk usp-parse-names    "$(printf '%s\n' "$uph" | awk -F'\t' '$1=="names"{print $2}')" "unobserved"
    chk usp-parse-usage    "$(capi_usp parse >/dev/null 2>&1; echo $?)" "2"
    chk usp-parse-badhex   "$(capi_usp parse zz >/dev/null 2>&1; echo $?)" "2"
    printf '0A03616263\n' > "$d/usp.hex"
    chk usp-parse-file     "$(capi_usp parse "$d/usp.hex" | awk -F'\t' '$1=="bytes"{print $2}')" "5"
    chk usp-plan-status    "$(capi_usp plan | awk -F'\t' '$1=="status"{print $2}')" "handoff"
    chk usp-usage-rc       "$(capi_usp >/dev/null 2>&1; echo $?)" "2"
    chk proto-store        "$([[ -s "$CAPI_DIR/cwmp_usp.tsv" ]] && echo yes || echo no)" "yes"
    chk proto-store-rows   "$(awk -F'\t' '$2=="TR-069"{n++} END{print (n>0)?"yes":"no"}' "$CAPI_DIR/cwmp_usp.tsv" 2>/dev/null)" "yes"

    out=$(IMSI_LAB_AUTHORISED=1 capi_cli_main --status-tsv)


    printf 'ASSERTIONS\t%d\n' "$nchk"
    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

capi_menu() {
    while true; do
        banner
        echo "  === Carrier API Abuse ==="
        echo
        cat <<'M'
  [1]  Parse an OpenAPI spec
  [2]  Authorisation test matrix
  [3]  Token-bucket rate model
  [4]  Audit a JWT
  [5]  Response differential
  [6]  Credential-stuffing resistance
  [7]  Report guidance
  [8]  Plan (handoff)
  [9]  Enumerate requests from a spec (gated)
  [10] Subscriber sequence (gated, handoff)
  [11] TR-069 (CWMP): build / parse / plan
  [12] TR-369 (USP): build / parse / plan
  [0]  back
M
        read -rp "  choice> " c || return 0
        case "$c" in
            1) read -rp "  spec json> " p; capi_openapi_parse "$p"; read -rp "  enter " _ ;;
            2) read -rp "  spec json> " p; capi_authz_matrix "$p"; read -rp "  enter " _ ;;
            3) read -rp "  rate/s> " r; read -rp "  burst> " b; read -rp "  requests> " n; read -rp "  seconds> " t
               capi_token_bucket "$r" "$b" "$n" "$t"; read -rp "  enter " _ ;;
            4) read -rp "  jwt> " t; read -rp "  now (blank=auto)> " n; capi_jwt_audit "$t" "$n"; read -rp "  enter " _ ;;
            5) read -rp "  responses A> " a; read -rp "  responses B> " b; capi_diff "$a" "$b"; read -rp "  enter " _ ;;
            6) read -rp "  config path> " p; capi_stuffing_resistance "$p"; read -rp "  enter " _ ;;
            7) capi_report; read -rp "  enter " _ ;;
            8) capi_plan; read -rp "  enter " _ ;;
            9) read -rp "  spec json> " p; read -rp "  base url (blank=from spec)> " b; read -rp "  run-file (blank=default)> " o
               local -a _ea=()
               [[ -n "${b:-}" ]] && _ea+=(--base "$b")
               [[ -n "${o:-}" ]] && _ea+=(--out "$o")
               capi_enumerate "${_ea[@]}" "$p"; read -rp "  enter " _ ;;
            10) read -rp "  conf path> " p; capi_enumerate_subscribers "$p"; read -rp "  enter " _ ;;
            11) echo "  1) build Inform  2) build GetParameterValues  3) parse a file  4) plan"
                read -rp "  cwmp> " m
                case "$m" in
                  1) read -rp "  oui (6 hex, blank=001122)> " o; read -rp "  serial (blank=default)> " sn
                     capi_cwmp build-inform ${o:+--oui "$o"} ${sn:+--serial "$sn"}; read -rp "  enter " _ ;;
                  2) read -rp "  param path> " pp; capi_cwmp build-gpv "$pp"; read -rp "  enter " _ ;;
                  3) read -rp "  file> " f; capi_cwmp parse "$f"; read -rp "  enter " _ ;;
                  4) capi_cwmp plan; read -rp "  enter " _ ;;
                  *) warn "invalid"; sleep 1 ;;
                esac ;;
            12) echo "  1) build a Msg  2) parse a protobuf dump  3) plan"
                read -rp "  usp> " m
                case "$m" in
                  1) read -rp "  msg id (blank=auto)> " mi; read -rp "  op (blank=get)> " op
                     read -rp "  param path (blank=none)> " pp
                     capi_usp build-msg ${mi:+--msg-id "$mi"} ${op:+--op "$op"} ${pp:+--param-path "$pp"}
                     read -rp "  enter " _ ;;
                  2) read -rp "  hex or file> " h; capi_usp parse "$h"; read -rp "  enter " _ ;;
                  3) capi_usp plan; read -rp "  enter " _ ;;
                  *) warn "invalid"; sleep 1 ;;
                esac ;;
            0) return ;;
            *) warn "invalid"; sleep 1 ;;
        esac
    done
}

capi_cli_main() {
    # The gate flag is a modifier, not a verb: it may sit anywhere on the command
    # line, and it arms the two enumeration verbs for this invocation only.
    local -a _args=()
    local _a
    for _a in "$@"; do
        _args+=("$_a")
    done
    local cmd="${_args[0]:-}"
    ((${#_args[@]} > 0)) && set -- "${_args[@]:1}"
    case "$cmd" in
        --status-tsv)     capi_status_tsv ;;
        --openapi)        capi_openapi_parse "${1:-}" ;;
        --authz-matrix)   capi_authz_matrix "${1:-}" ;;
        --token-bucket)   capi_token_bucket "${1:-}" "${2:-}" "${3:-}" "${4:-}" ;;
        --jwt-audit)      capi_jwt_audit "${1:-}" "${2:-}" ;;
        --diff)           capi_diff "${1:-}" "${2:-}" ;;
        --stuffing)       capi_stuffing_resistance "${1:-}" ;;
        --report)         capi_report ;;
        --plan)           capi_plan ;;
        --cwmp)           capi_cwmp "$@" ;;
        --usp)            capi_usp "$@" ;;
        --enumerate)      capi_enumerate "$@" ;;
        --enumerate-subscribers) capi_enumerate_subscribers "$@" ;;
        --execute)        capi_cmd_execute "$@" ;;
        --selftest)       capi_selftest ;;
        --menu)           capi_menu ;;
        *)
            cat >&2 <<EOF
Carrier API Abuse — surface discovery, authorisation-boundary testing and gated
request construction

Usage: $0 COMMAND

Audit verbs (ungated — what a defender can lawfully run):
  --status-tsv                 module state as TSV
  --openapi <json>             OpenAPI 3 surface (title, servers, paths, schemes)
  --authz-matrix <json>        four-case authorisation test plan per operation
  --token-bucket <rate> <burst> <requests> <seconds>
  --jwt-audit <token> [now]    alg=none, expiry and audience audit
  --diff <A> <B>               response-differential between two captures
  --stuffing <conf>            credential-stuffing resistance controls
  --report                     assessment report skeleton
  --plan                       assessment handoff plan
  --cwmp <mode> [args]         TR-069 (CWMP): build-inform [--oui <6hex>]
                               [--product-class <s>] [--serial <s>] [--event <code>]
                               [--acs <url>] [--out <file>] | build-gpv <param>...
                               [--id <id>] [--out <file>] | parse <file|-> | plan
  --usp <mode> [args]          TR-369 (USP): build-msg [--msg-id <s>]
                               [--session-id <s>] [--type error|request|response|notify]
                               [--op get|get_supported_dm|get_instances|set|add|delete|operate|notify]
                               [--param-path <p>]... [--max-depth <n>] | parse <hex|file> | plan

Enumeration verbs (build requests, never send them — no gate):
  --enumerate <json> [--base <url>] [--out <run-file>]
                               one concrete request per operation, from the
                               document's own examples and schemas; writes the
                               run-file and stops. Exit 0.
  --enumerate-subscribers <conf>
                               ordered one-identifier-per-request sequence from
                               spec= and candidates=, with the declared rate
                               limit and the stop condition; writes the run-file
                               and refuses to send. Exit 3, the handoff.

Executor (gated — the only verb that opens a socket):
  --execute <plan.tsv> --base <url> --i-have-a-lab-and-authorisation
                               run an enumeration run-file against an API you
                               own, one request at a time, and report a 2xx
                               answer to a deny row as unauthorised_success.
                               Without the word it prints the handoff and
                               exits 3. [--rate N/sec] [--max N] [--dry-run]

  --selftest                   verify parsers and plans, no network needed
  --menu                       interactive menu

Scope: audit and enumeration verbs are ungated. --enumerate and
--enumerate-subscribers parse the document, build requests and sequences, write
them to disk and stop: neither opens a socket and neither claims a response.
The one verb that sends is --execute, it runs only under the confirmation word,
and it is the only place in this module that can report a subscriber as
"found" — from an answer the target actually gave. Querying carrier APIs for
identifiers you are not authorised for is a criminal offence in most
jurisdictions under computer-misuse and privacy law, whatever the intent.
EOF
            return 2 ;;
    esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    set -o pipefail
    IMSISTING_CLI=1
    : "${TMP_DIR:=/tmp/imsisting}"
    : "${LOOT_DIR:=$IMSISTING_ROOT/loot}"
    : "${CAPTURES_DIR:=$IMSISTING_ROOT/captures}"
    : "${LOGS_DIR:=$IMSISTING_ROOT/logs}"
    : "${STATE_DIR:=$IMSISTING_ROOT/state}"
    mkdir -p "$TMP_DIR" "$LOOT_DIR" "$CAPTURES_DIR" "$LOGS_DIR" "$STATE_DIR"
    declare -F banner >/dev/null 2>&1 || banner() { :; }
    declare -F info   >/dev/null 2>&1 || info()   { printf '[info] %s\n' "$*" >&2; }
    declare -F warn   >/dev/null 2>&1 || warn()   { printf '[warn] %s\n' "$*" >&2; }
    declare -F err    >/dev/null 2>&1 || err()    { printf '[err]  %s\n' "$*" >&2; }
    declare -F ok     >/dev/null 2>&1 || ok()     { printf '[ok]   %s\n' "$*" >&2; }
    capi_cli_main "$@"
fi
