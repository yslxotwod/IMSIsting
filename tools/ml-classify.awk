# ml-classify.awk — the scorer behind --ml-classify (23_traffic_analysis, 17_pcap_analysis).
#
# Reads the weighted feature table (tools/ml-classify-table.tsv) and a flow table
# on stdin, and prints one row per flow:
#
#   flow_id  class  score  confidence  runner_up  margin  features_used
#   features_unobserved  verdict
#
# verdict is one of:
#   classified   margin >= MIN-MARGIN and at least MIN-OBSERVED features present
#   weak         a class won but by less than MIN-MARGIN
#   unobserved   fewer than MIN-OBSERVED features could be derived for the flow
#
# `unobserved` is the doctrine, not an error: a flow table that carries no
# timing columns says nothing about rate, and the scorer says so by name instead
# of scoring the missing feature as a zero. Nothing here is trained; see the
# header of tools/ml-classify-table.tsv.
#
# Usage: awk -v model=<table.tsv> -v model_src=<label> -f ml-classify.awk flows.tsv
# Both options are optional; model defaults to tools/ml-classify-table.tsv beside
# this file, which the caller resolves through $IMSISTING_ROOT.

function trim(s) { gsub(/^[ \t\r]+|[ \t\r]+$/, "", s); return s }
function low(s)  { return tolower(trim(s)) }

# A feature is observed only when the table actually carries a value. An empty
# cell, a dash and the word unobserved are all the same thing here: absent.
function present(v) {
    v = low(v)
    return (v != "" && v != "-" && v != "na" && v != "n/a" && v != "?" && v != "unobserved")
}

function num(v) { return (v ~ /^-?[0-9]+([.][0-9]+)?$/) ? v + 0 : "" }

# ── buckets ────────────────────────────────────────────────────────────
# proto: IP protocol number (RFC 791 §3.1); a name is accepted because a flow
# exporter may print either.
function bucket_proto(v) {
    v = low(v)
    if (v == "6"   || v == "tcp")  return "tcp"
    if (v == "17"  || v == "udp")  return "udp"
    if (v == "132" || v == "sctp") return "sctp"
    return "other"
}

# port: the server port is the lower of the two transport ports — a client port
# is ephemeral above 32768 (RFC 6335 §6), so the lower number is the service.
# Assignments: SIP 5060/5061 (RFC 3261 §7.1, RFC 5630), DNS 53/5353 (RFC 1035,
# RFC 6762), HTTP 80/8080/8000, TLS 443/8443/993/995/465 (RFC 9110, RFC 9112),
# GTP-U 2152 and GTP-C 2123 (TS 29.281), Diameter 3868 (RFC 6733 §3.1), RTP
# dynamic port range 16384-32767 (RFC 3550 §11).
function bucket_port(p) {
    if (p == "") return ""
    if (p == 5060 || p == 5061)              return "sip"
    if (p == 53   || p == 5353)              return "dns"
    if (p == 80   || p == 8080 || p == 8000) return "http"
    if (p == 443  || p == 8443 || p == 993 || p == 995 || p == 465) return "tls"
    if (p == 2152 || p == 2123)              return "gtp"
    if (p == 3868)                           return "diameter"
    if (p >= 16384 && p <= 32767)            return "rtp-range"
    if (p > 1023)                            return "high"
    return "other"
}

# size_mean: anchors are the smallest useful segment (128), a TLS record with
# its header (512), the 1024-octet small-buffer line, and the 1400-octet
# payload of a 1500-octet Ethernet frame (RFC 894 MTU minus IPv4+TCP headers).
function bucket_size(v) {
    v = num(v); if (v == "") return ""
    if (v < 128)  return "tiny"
    if (v < 512)  return "small"
    if (v < 1024) return "medium"
    if (v < 1400) return "large"
    return "mtu"
}

function bucket_rate(v) {
    v = num(v); if (v == "") return ""
    if (v < 0.5) return "sparse"
    if (v < 10)  return "low"
    if (v < 100) return "medium"
    return "high"
}

function bucket_dur(v) {
    v = num(v); if (v == "") return ""
    if (v < 1)   return "very-short"
    if (v < 60)  return "short"
    if (v < 600) return "medium"
    return "long"
}

function bucket_cv(v) {
    v = num(v); if (v == "") return ""
    if (v < 0.10) return "flat"
    if (v < 0.40) return "low"
    return "mixed"
}

function norm(s) { s = low(s); gsub(/[^a-z0-9_]/, "", s); return s }

# Column aliases. A flow table is whatever the exporter printed; the scorer
# resolves names instead of demanding a byte layout.
function slot(name) {
    if (name == "flow_id" || name == "idx" || name == "flow" || name == "id" ||
        name == "flow_idx" || name == "flowid") return "id"
    if (name == "proto" || name == "protocol" || name == "ip_proto" || name == "ipproto") return "proto"
    if (name == "sport" || name == "src_port" || name == "source_port") return "sport"
    if (name == "dport" || name == "dst_port" || name == "dest_port" || name == "destination_port") return "dport"
    if (name == "packets" || name == "pkts" || name == "pkt" || name == "frames") return "packets"
    if (name == "bytes" || name == "octets" || name == "total_bytes") return "bytes"
    if (name == "dur_s" || name == "dur" || name == "duration" || name == "duration_s") return "dur"
    if (name == "mean_size" || name == "meansize" || name == "avg_size" || name == "mean_bytes") return "mean_size"
    if (name == "size_cv" || name == "cv_size" || name == "cv") return "size_cv"
    return ""
}

# Record one observed feature into the per-flow list.
function addfeat(f, b) { nused++; uf[nused] = f; ub[nused] = b }

BEGIN {
    if (model == "") model = "ml-classify-table.tsv"
    FS = "\t"
    minobs = 3; minmargin = 2; minconf = 0.30
    ncls = 0
    while ((getline line < model) > 0) {
        if (line ~ /^[ \t]*#/ || line ~ /^[ \t]*$/) continue
        n = split(line, f, "\t")
        if (n < 4) continue
        c = trim(f[1]); feat = trim(f[2]); bkt = trim(f[3]); w = num(f[4])
        if (c == "class" && feat == "feature") continue        # header row
        if (w == "") continue
        if (c == "mins") {
            if (bkt == "MIN-OBSERVED") minobs = w
            if (bkt == "MIN-MARGIN")   minmargin = w
            if (bkt == "MIN-CONF")     minconf = w
            continue
        }
        classes[c] = 1
        if (!(c in seen)) { seen[c] = 1; order[++ncls] = c }
        W[c SUBSEP feat SUBSEP bkt] = w
        if (w < 0) w = -w
        if (w > wmax[feat]) wmax[feat] = w
    }
    close(model)
    if (ncls == 0) { print "ERROR\tno model rows read from " model > "/dev/stderr"; exit 2 }
    printf "flow_id\tclass\tscore\tconfidence\trunner_up\tmargin\tfeatures_used\tfeatures_unobserved\tverdict\n"
    hdr = 0
}

# The header is the first non-comment, non-empty row of the flow table.
!hdr {
    if ($0 ~ /^[ \t]*#/ || $0 ~ /^[ \t]*$/) next
    nc = split($0, h, "\t")
    for (i = 1; i <= nc; i++) {
        s = slot(norm(h[i]))
        if (s != "") col[s] = i
    }
    hdr = 1
    if (!("packets" in col) || !("bytes" in col)) {
        print "ERROR\tflow table has no packets/bytes column; the model needs them" > "/dev/stderr"
        exit 2
    }
    next
}

{
    nf++
    delete uf; delete ub; nused = 0; nunobs = 0; used = ""; unob = ""
    id = ("id" in col) ? trim($(col["id"])) : nf

    # proto
    b = ""
    if (present(("proto" in col) ? $(col["proto"]) : "")) b = bucket_proto($(col["proto"]))
    if (b != "") { addfeat("proto", b); used = used (nused > 1 ? "," : "") "proto" }
    else { nunobs++; unob = unob (nunobs > 1 ? "," : "") "proto" }

    # port: the lower transport port of the pair, when either is carried
    sp = present(("sport" in col) ? $(col["sport"]) : "") ? num($(col["sport"])) : ""
    dp = present(("dport" in col) ? $(col["dport"]) : "") ? num($(col["dport"])) : ""
    b = ""
    if (sp != "" && dp != "")   b = bucket_port(sp < dp ? sp : dp)
    else if (dp != "")          b = bucket_port(dp)
    else if (sp != "")          b = bucket_port(sp)
    if (b != "") { addfeat("port", b); used = used (nused > 1 ? "," : "") "port" }
    else { nunobs++; unob = unob (nunobs > 1 ? "," : "") "port" }

    # size_mean: carried directly, or derived from bytes/packets — derivation is
    # still an observation, both counters came from the table.
    ms = present(("mean_size" in col) ? $(col["mean_size"]) : "") ? num($(col["mean_size"])) : ""
    npk = num($(col["packets"])); nb = num($(col["bytes"]))
    if (ms == "" && npk != "" && nb != "" && npk > 0) ms = nb / npk
    b = (ms != "") ? bucket_size(ms) : ""
    if (b != "") { addfeat("size_mean", b); used = used (nused > 1 ? "," : "") "size_mean" }
    else { nunobs++; unob = unob (nunobs > 1 ? "," : "") "size_mean" }

    # rate_pps = packets / duration
    du = present(("dur" in col) ? $(col["dur"]) : "") ? num($(col["dur"])) : ""
    b = (npk != "" && du != "" && du > 0) ? bucket_rate(npk / du) : ""
    if (b != "") { addfeat("rate_pps", b); used = used (nused > 1 ? "," : "") "rate_pps" }
    else { nunobs++; unob = unob (nunobs > 1 ? "," : "") "rate_pps" }

    # duration_s
    b = (du != "") ? bucket_dur(du) : ""
    if (b != "") { addfeat("duration_s", b); used = used (nused > 1 ? "," : "") "duration_s" }
    else { nunobs++; unob = unob (nunobs > 1 ? "," : "") "duration_s" }

    # size_cv is never derived: it is a property of the packet-size sequence and
    # cannot be recovered from a mean. Absent means unobserved, full stop.
    cvv = present(("size_cv" in col) ? $(col["size_cv"]) : "") ? num($(col["size_cv"])) : ""
    b = (cvv != "") ? bucket_cv(cvv) : ""
    if (b != "") { addfeat("size_cv", b); used = used (nused > 1 ? "," : "") "size_cv" }
    else { nunobs++; unob = unob (nunobs > 1 ? "," : "") "size_cv" }

    if (nunobs == 0) unob = "-"

    # Score every class over the observed features only. best/second are tracked
    # with strict/non-strict comparisons so a two-way tie lands in `weak`.
    best = ""; bests = -1e9; second = ""; seconds = -1e9
    for (i = 1; i <= ncls; i++) {
        c = order[i]; s = 0
        for (j = 1; j <= nused; j++) {
            k = c SUBSEP uf[j] SUBSEP ub[j]
            if (k in W) s += W[k]
        }
        if (s > bests) { seconds = bests; second = best; bests = s; best = c }
        else if (s > seconds) { seconds = s; second = c }
    }

    # Normaliser: the largest score any class could have earned from exactly
    # these buckets, so confidence is comparable across flows with different
    # feature coverage instead of flattering a one-feature flow.
    maxabs = 0
    for (j = 1; j <= nused; j++) maxabs += wmax[uf[j]]
    conf = (maxabs > 0) ? bests / maxabs : 0
    margin = (second == "") ? bests : bests - seconds
    verdict = "classified"
    if (nused < minobs)          verdict = "unobserved"
    else if (margin < minmargin || conf < minconf) verdict = "weak"
    printf "%s\t%s\t%.0f\t%.3f\t%s\t%.0f\t%s\t%s\t%s\n", \
        id, (verdict == "unobserved" ? "unobserved" : best), bests, conf, \
        (second == "" ? "-" : second), margin, used, unob, verdict
    nver[verdict]++
}

END {
    if (nf == 0) {
        print "ERROR\tno flow rows read; nothing to classify (the header, if any, was consumed)" > "/dev/stderr"
        exit 1
    }
    printf "summary\tflows\t%d\n", nf
    printf "summary\tclassified\t%d\n", nver["classified"] + 0
    printf "summary\tweak\t%d\n", nver["weak"] + 0
    printf "summary\tunobserved\t%d\n", nver["unobserved"] + 0
    printf "summary\tmodel\t%s\n", (model_src == "" ? model : model_src)
    printf "summary\tmin_observed\t%d\n", minobs
    printf "summary\tmin_margin\t%d\n", minmargin
    printf "summary\tmin_conf\t%.2f\n", minconf
    printf "note\tmodel_type\thand-set weighted feature table, not a trained model\n"
}
