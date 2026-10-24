#!/usr/bin/env python3
"""Stats index: one row per statistic, each naming the file or verb it came from.

The GUI Stats page and the TUI Stats page both read the single table this tool
writes, so a number on screen can always be traced back to the artifact that
produced it. Every module contributes what its own loot store can answer; a
module whose only honest number needs an operator-supplied input file simply
contributes nothing rather than inventing a zero.

Output: TSV with the columns
    scope  module  key  label  value  unit  source

`scope` is "fleet" or "module". `source` is the path or command the value was
read from, printed on the page next to the number.
"""
from __future__ import annotations

import argparse
import os
import re
import shlex
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(os.environ.get("IMSISTING_ROOT", Path(__file__).resolve().parent.parent))
INDEX = ROOT / "loot" / "stats" / "index.tsv"
VERB_TIMEOUT = 8

PREDICATE = re.compile(r"^(.+?)\s*(==|!=|=~|>=|<=|>|<)\s*(.*)$")


# ── reading helpers ───────────────────────────────────────────────────

def lines_of(path: Path) -> list[str]:
    try:
        return path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []


def table(paths: list[Path]) -> list[dict[str, str]]:
    """Read TSVs as dicts, keyed by the header when one is present.

    A file whose first row is not a header is keyed by 1-based column number, so
    a spec can name either "status" or "4" without the caller caring which kind
    of file it opened. Multi-file specs concatenate: killchain writes one report
    per run and the fleet number is over all of them.
    """
    rows: list[dict[str, str]] = []
    for path in paths:
        lines = [line for line in lines_of(path) if line.strip()]
        if not lines:
            continue
        cells = lines[0].split("\t")
        headered = any(re.fullmatch(r"[A-Za-z][A-Za-z0-9_. /-]*", cell) for cell in cells)
        keys = cells if headered else [str(i + 1) for i in range(len(cells))]
        for line in lines[1:] if headered else lines:
            values = line.split("\t")
            rows.append({key: (values[i] if i < len(values) else "")
                         for i, key in enumerate(keys)})
    return rows


def matches(row: dict[str, str], predicate: str) -> bool:
    match = PREDICATE.match(predicate.strip())
    if match is None:
        raise ValueError(f"bad predicate: {predicate}")
    field, operator, wanted = match.group(1).strip(), match.group(2), match.group(3)
    actual = row.get(field, "")

    if operator == "==":
        return actual == wanted
    if operator == "!=":
        return actual != wanted
    if operator == "=~":
        return re.search(wanted, actual) is not None
    try:
        left, right = float(actual), float(wanted)
    except ValueError:
        return False
    return {"<": left < right, ">": left > right,
            "<=": left <= right, ">=": left >= right}[operator]


def number(text: str) -> float | None:
    try:
        return float(text)
    except (TypeError, ValueError):
        return None


def tidy(value: float | int | str | bool) -> str:
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, float):
        return f"{value:.1f}".rstrip("0").rstrip(".")
    return str(value)


# ── evaluators ────────────────────────────────────────────────────────

def spec_rows(spec: dict, sources: list[Path]) -> float:
    return len(table(sources))


def spec_distinct(spec: dict, sources: list[Path]) -> float:
    columns = spec["columns"]
    seen = {tuple(row.get(column, "") for column in columns) for row in table(sources)}
    return len({item for item in seen if any(item)})


def spec_sum(spec: dict, sources: list[Path]) -> float:
    return sum(number(row.get(spec["column"], "")) or 0 for row in table(sources))


def spec_mean(spec: dict, sources: list[Path]) -> float:
    values = [number(row.get(spec["column"], "")) for row in table(sources)]
    kept = [value for value in values if value is not None]
    return sum(kept) / len(kept) if kept else 0


def spec_count_where(spec: dict, sources: list[Path]) -> float:
    predicates = spec["where"] if isinstance(spec["where"], list) else [spec["where"]]
    return sum(1 for row in table(sources) if all(matches(row, p) for p in predicates))


def spec_ratio(spec: dict, sources: list[Path]) -> float:
    rows = table(sources)
    numerator = sum(1 for row in rows if all(matches(row, p) for p in spec["num"]))
    denominator = sum(1 for row in rows if all(matches(row, p) for p in spec["den"])) if spec.get("den") else len(rows)
    return 100.0 * numerator / denominator if denominator else 0


def spec_kv(spec: dict, sources: list[Path]) -> float:
    wanted = spec["key"]
    for path in sources:
        for line in lines_of(path):
            key, _, value = line.partition("\t")
            if key.strip() == wanted:
                return number(value) if number(value) is not None else value
    return 0


def spec_kv_diff(spec: dict, sources: list[Path]) -> float:
    first, second = spec["keys"]
    values = [spec_kv({"key": key}, sources) for key in (first, second)]
    if all(isinstance(value, float) for value in values):
        return values[0] - values[1]
    return 0


def spec_grep(spec: dict, sources: list[Path]) -> float:
    pattern = re.compile(spec["pattern"], re.I)
    return sum(1 for path in sources for line in lines_of(path) if pattern.search(line))


def spec_boolean(spec: dict, sources: list[Path]) -> str:
    if spec.get("grep") is not None:
        return spec_grep({"pattern": spec["grep"]}, sources) > 0
    return any(any(line.strip() for line in lines_of(path)) for path in sources)


def spec_pid(spec: dict, sources: list[Path]) -> str:
    for path in sources:
        text = " ".join(lines_of(path)).strip().split()
        if not text:
            continue
        try:
            os.kill(int(text[0]), 0)
            return True
        except (ValueError, ProcessLookupError, PermissionError):
            return False
    return False


def spec_glob(spec: dict, sources: list[Path]) -> float:
    if spec["op"] == "bytes":
        return sum(path.stat().st_size for path in sources if path.is_file())
    return len([path for path in sources if path.is_file()])


def table_text(text: str) -> list[dict[str, str]]:
    """Read TSV the caller already holds, same header rule as `table`."""
    rows: list[dict[str, str]] = []
    lines = [line for line in text.splitlines() if line.strip()]
    if not lines:
        return rows
    cells = lines[0].split("\t")
    headered = any(re.fullmatch(r"[A-Za-z][A-Za-z0-9_. /-]*", cell) for cell in cells)
    keys = cells if headered else [str(i + 1) for i in range(len(cells))]
    for line in lines[1:] if headered else lines:
        values = line.split("\t")
        rows.append({key: (values[i] if i < len(values) else "")
                     for i, key in enumerate(keys)})
    return rows


def spec_verb(spec: dict, sources: list[Path]) -> float:
    """Run a module verb that needs no input and read one number back.

    Only verbs that answer from the tree itself belong here: a verb that wants a
    capture or a config is an operator action, not a statistic. `op` says how to
    read the answer: a key<TAB>value pair (the default), the row count of a
    table the verb prints, or its line count when it prints bare paths.
    """
    module = spec["module"]
    command = ["bash", str(ROOT / "modules" / f"{module}.sh"), *spec["verb"]]
    try:
        done = subprocess.run(command, cwd=ROOT, capture_output=True, text=True,
                              timeout=VERB_TIMEOUT, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return 0
    output = done.stdout
    operation = spec.get("op", "value")
    if operation == "rows":
        return len(table_text(output))
    if operation == "lines":
        return len([line for line in output.splitlines()
                    if line.strip() and line.strip().lower() != "none"])
    for line in output.splitlines():
        key, _, value = line.partition("\t")
        if key.strip() == spec["key"]:
            found = number(value.strip())
            return found if found is not None else value.strip()
    return 0


EVALUATORS = {
    "rows": spec_rows, "distinct": spec_distinct, "sum": spec_sum, "mean": spec_mean,
    "count_where": spec_count_where, "ratio": spec_ratio, "kv": spec_kv,
    "kv_diff": spec_kv_diff, "grep": spec_grep, "boolean": spec_boolean,
    "pid": spec_pid, "glob": spec_glob, "verb": spec_verb,
}


def resolve(spec: dict) -> list[Path]:
    if "glob" in spec:
        return sorted(ROOT.glob(spec["glob"]))
    if "path" in spec:
        return [ROOT / spec["path"]]
    return []


# ── the statistics ────────────────────────────────────────────────────
#
# One entry per module: the number that moves with use and answers a question.
# `source` is printed verbatim on the page, so it has to be true.
#
# Spec keys: kind (which evaluator), path or glob, and the evaluator's own
# arguments. MODULES below is the curated set from docs/stats-proposals.md —
# catalogue sizes and structurally-zero counters are deliberately absent.

MODULES: dict[str, list[tuple[str, str, str, dict]]] = {
    # SYSTEM
    "00_deps": [
        ("required_gaps", "Required tools missing", "tools",
         {"kind": "count_where", "path": "loot/deps/deps_report.tsv",
          "where": ["required==yes", "state!=installed"]}),
        ("installed_ratio", "Toolchain installed", "%",
         {"kind": "ratio", "path": "loot/deps/deps_report.tsv",
          "num": ["state==installed"]}),
    ],
    "01_radio": [
        ("devices", "SDR devices attached", "devices",
         {"kind": "rows", "path": "tmp/radio/roster.tsv"}),
        ("tx_share", "TX-capable devices", "%",
         {"kind": "ratio", "path": "tmp/radio/roster.tsv", "num": ["direction==RX/TX"]}),
    ],
    "05_field_kit": [
        ("honesty_rate", "Honest-fail rate", "%",
         {"kind": "ratio", "path": "loot/field_kit/guard-check.tsv", "num": ["status==honest-fail"]}),
        ("fabricated", "Fabricated verbs", "verbs",
         {"kind": "count_where", "path": "loot/field_kit/guard-check.tsv", "where": ["status==FABRICATED"]}),
    ],
    "25_killchain": [
        ("step_pass_rate", "Step pass rate", "%",
         {"kind": "ratio", "glob": "loot/killchain/runs/*.tsv", "num": ["status==PASS"]}),
        ("runs", "Runs recorded", "runs",
         {"kind": "glob", "glob": "loot/killchain/runs/*.tsv", "op": "count"}),
        ("unfinished", "Run unfinished", "", {"kind": "boolean", "path": "state/killchain/active.tsv"}),
    ],
    # RECON
    "02_cell_recon": [
        ("distinct_cells", "Cells surveyed", "cells",
         {"kind": "distinct", "path": "loot/cell_recon/cells.tsv",
          "columns": ["arfcn", "plmn", "cell_id"]}),
        ("rsrp_complete", "Rows carrying RSRP", "%",
         {"kind": "ratio", "path": "loot/cell_recon/cells.tsv", "num": ["rsrp_dbm!= "]}),
    ],
    "03_gsmtap": [
        ("frames", "Frames decoded", "frames",
         {"kind": "rows", "path": "loot/gsmtap/decoded.tsv"}),
        ("snr", "Mean SNR", "dB",
         {"kind": "mean", "path": "loot/gsmtap/decoded.tsv", "column": "snr_db"}),
    ],
    "04_tower_map": [
        ("fix_rate", "GPS fix rate", "%",
         {"kind": "ratio", "path": "loot/tower_map/points.tsv", "num": ["lat!= "] }),
        ("points", "Survey points", "points",
         {"kind": "rows", "path": "loot/tower_map/points.tsv"}),
    ],
    # RADIO
    "07_gsm_attack": [
        ("pairings", "TMSI-IMSI pairings", "pairings",
         {"kind": "distinct", "path": "loot/gsm_attack/deanon.tsv", "columns": ["1"]}),
        ("tx_bytes", "TX waveforms", "bytes",
         {"kind": "glob", "glob": "loot/gsm_attack/tx_*.cs8", "op": "bytes"}),
    ],
    "08_umts_air": [
        ("tx_bytes", "TX waveforms", "bytes",
         {"kind": "glob", "glob": "loot/umts_air/tx_*.cf32", "op": "bytes"}),
        ("waveforms", "Waveform files", "files",
         {"kind": "glob", "glob": "loot/umts_air/tx_*.cf32", "op": "count"}),
    ],
    "10_lte_air": [
        ("enb_live", "eNB running", "", {"kind": "pid", "path": "tmp/lte_air/srsenb.pid"}),
    ],
    "12_nr_air": [
        ("gnb_live", "gNB running", "", {"kind": "pid", "path": "tmp/nr_air/gnb.pid"}),
        ("ssb_files", "SSB waveforms", "files",
         {"kind": "glob", "glob": "loot/nr_air/nr_ssb_pci*", "op": "count"}),
    ],
    "33_jamming_detect": [
        ("floor_shift", "Noise-floor shift", "dB",
         {"kind": "kv_diff", "path": "loot/jamming_detect/features.tsv",
          "keys": ["noise_floor_second_half_dbfs", "noise_floor_first_half_dbfs"]}),
        ("duty_cycle", "Duty cycle", "",
         {"kind": "kv", "path": "loot/jamming_detect/features.tsv", "key": "activity_fraction"}),
        ("characterisation", "Characterisation", "",
         {"kind": "kv", "path": "loot/jamming_detect/features.tsv", "key": "characterisation"}),
    ],
    "57_evil_twin": [
        ("attach_seen", "Attach/registration seen", "",
         {"kind": "boolean", "glob": "loot/evil-twin-lab/logs/ue.log", "grep": "attach accept|Registration accept|RRC connected"}),
        ("configs", "Lab configs written", "files",
         {"kind": "glob", "glob": "loot/evil-twin-lab/*.conf", "op": "count"}),
    ],
    "45_iot": [
        ("plans", "Handoff plans", "plans",
         {"kind": "glob", "glob": "loot/iot/plans/plan_*.txt", "op": "count"}),
    ],
    "50_gprs": [
        ("gea_kat", "GEA known-answer failures", "of 9",
         {"kind": "verb", "module": "50_gprs", "verb": ["--gea-kat"], "key": "failed"}),
    ],
    "51_sidelink": [
        ("pool_use", "Pool utilisation", "",
         {"kind": "kv", "path": "loot/sidelink/pool.tsv", "key": "pool_use"}),
    ],
    "49_ntn": [
        ("ta_over_range", "TA over LTE ceiling", "",
         {"kind": "kv", "path": "loot/ntn/last.tsv", "key": "ta_over_range"}),
    ],
    "53_non3gpp": [
        ("weak_ciphers", "Weak cipher mechanisms", "mechanisms",
         {"kind": "count_where", "path": "loot/non3gpp/weakness.tsv", "where": ["1=~."]}),
    ],
    # ACCESS
    "09_lte_attach": [
        ("exposure_share", "Plain-NAS exposure", "%",
         {"kind": "ratio", "path": "loot/lte_attach/identities.tsv",
          "num": ["kind==identity-request"]}),
        ("identities", "Identities recorded", "rows",
         {"kind": "rows", "path": "loot/lte_attach/identities.tsv"}),
    ],
    "34_slicing": [
        ("plans", "Handoff plans", "plans",
         {"kind": "glob", "glob": "loot/slicing/plans/*.plan", "op": "count"}),
    ],
    "36_vowifi": [
        ("registry", "IKE attribute ids", "ids",
         {"kind": "glob", "glob": "loot/vowifi/*.tsv", "op": "count"}),
    ],
    "37_femtocell": [
        ("identities", "Distinct identities", "identities",
         {"kind": "distinct", "path": "loot/femtocell/subscribers.tsv", "columns": ["identity"]}),
        ("sightings", "Subscriber sightings", "rows",
         {"kind": "rows", "path": "loot/femtocell/subscribers.tsv"}),
    ],
    "43_ran_share": [
        ("cells", "Cells audited", "cells",
         {"kind": "rows", "path": "loot/ran_share/leak-check.tsv"}),
    ],
    "47_wifioff": [
        ("certs", "Certificates validated", "certs",
         {"kind": "glob", "glob": "loot/wifioff/*.txt", "op": "count"}),
    ],
    # CORE NETWORK
    "11_lte_core": [
        ("plans", "Handoff plans", "plans",
         {"kind": "glob", "glob": "loot/lte_core/plans/*.plan", "op": "count"}),
    ],
    "13_nr_core": [
        ("plans", "Plans written", "plans",
         {"kind": "glob", "glob": "loot/nr_core/plans/*.plan", "op": "count"}),
        ("core_tools", "Core tools present", "/4",
         {"kind": "count_where", "path": "state/nr_core/tools.tsv", "where": ["state==present"]}),
    ],
    "26_ss7_map": [
        ("plans", "Handoff plans", "plans",
         {"kind": "glob", "glob": "loot/ss7_map/plans/*.plan", "op": "count"}),
    ],
    "27_cellular_dns": [
        ("plans", "Handoff plans", "plans",
         {"kind": "glob", "glob": "loot/cellular_dns/plans/*.plan", "op": "count"}),
    ],
    "30_volte_ims": [
        ("plans", "Handoff plans", "plans",
         {"kind": "glob", "glob": "loot/volte_ims/plans/plan_*.txt", "op": "count"}),
    ],
    "32_nas_signaling": [
        ("plans", "Lab storm plans", "plans",
         {"kind": "glob", "glob": "loot/nas_signaling/plans/*.plan", "op": "count"}),
    ],
    "40_sba_pivot": [
        ("a1_bodies", "A1 policy bodies", "files",
         {"kind": "glob", "glob": "loot/sba_pivot/*", "op": "count"}),
    ],
    "48_oran": [
        ("a1_bodies", "A1 policy bodies", "files",
         {"kind": "glob", "glob": "loot/oran/a1-qos-policy-*.json", "op": "count"}),
    ],
    # SIM / IDENTITY
    "14_suci": [
        ("hn_ready", "Home-network key ready", "",
         {"kind": "boolean", "path": "state/suci_hn/hn_priv.key"}),
        ("keyfiles", "Key files", "files",
         {"kind": "glob", "glob": "loot/suci/keys/*.key", "op": "count"}),
    ],
    "16_sim": [
        ("apdus", "APDU exchanges logged", "exchanges",
         {"kind": "rows", "path": "loot/sim/apdus.tsv"}),
        ("success_rate", "Success status words", "%",
         {"kind": "ratio", "path": "loot/sim/apdus.tsv",
          "num": ["direction==R-APDU", "sw=~^9000"],
          "den": ["direction==R-APDU"]}),
        ("subscribers", "AKA subscribers stored", "subscribers",
         {"kind": "rows", "path": "state/sim_aka/subscribers.tsv"}),
    ],
    "18_imsi_exposure": [
        ("identities", "Identity rows stored", "rows",
         {"kind": "rows", "path": "loot/imsi_exposure/identities.tsv"}),
        ("mappings", "TEMP-IMSI bindings", "bindings",
         {"kind": "rows", "path": "loot/imsi_exposure/tmsi_imsi_map.tsv"}),
        ("reports", "Audit reports", "reports",
         {"kind": "glob", "glob": "loot/imsi_exposure/report_*.txt", "op": "count"}),
    ],
    "31_sim_defense": [
        ("history", "History rows supplied", "rows",
         {"kind": "glob", "glob": "loot/sim_defense/history/*.tsv", "op": "count"}),
    ],
    "52_stk": [
        ("audits", "Command logs audited", "logs",
         {"kind": "glob", "glob": "loot/stk/*.tsv", "op": "count"}),
    ],
    "58_suci_catcher": [
        ("catcher_live", "Catcher running", "",
         {"kind": "pid", "path": "state/suci_catcher/catcher.pid"}),
        ("capture_records", "Capture record files", "files",
         {"kind": "glob", "glob": "captures/suci_catcher/*.tsv", "op": "count"}),
        ("catch_sessions", "Catch sessions started", "sessions",
         {"kind": "count_where", "glob": "logs/suci_catcher.log", "where": ["1=~^start"]}),
    ],
    "41_ota_sms": [
        ("audits", "Packet audits stored", "files",
         {"kind": "glob", "glob": "loot/ota_sms/*", "op": "count"}),
    ],
    # ANALYSIS / TRACKING
    "17_pcap_analysis": [
        ("identities", "Identities catalogued", "identities",
         {"kind": "rows", "path": "loot/pcap_analysis/identities.tsv"}),
        ("captures", "Captures in scope", "files",
         {"kind": "glob", "glob": "captures/*.pcap*", "op": "count"}),
    ],
    "19_cipher_audit": [
        ("sessions", "Cipher sessions audited", "sessions",
         {"kind": "rows", "path": "loot/cipher_audit/sessions.tsv"}),
        ("null_share", "Null-cipher primary", "%",
         {"kind": "ratio", "path": "loot/cipher_audit/sessions.tsv", "num": ["enc_alg=~[Nn]ull"]}),
    ],
    "23_traffic_analysis": [
        ("fingerprints", "Reference fingerprints", "fingerprints",
         {"kind": "rows", "path": "loot/traffic_analysis/fingerprints.tsv"}),
        ("ref_packets", "Reference packets", "packets",
         {"kind": "sum", "path": "loot/traffic_analysis/fingerprints.tsv", "column": "n"}),
    ],
    "29_mac_layer": [
        ("rnti_store", "RNTI store rows", "rows",
         {"kind": "rows", "path": "loot/mac_layer/rnti.tsv"}),
    ],
    "24_rf_fingerprint": [
        ("signatures", "RF signatures stored", "signatures",
         {"kind": "rows", "path": "loot/rf_fingerprint/signatures.tsv"}),
        ("iq_files", "IQ files in scope", "files",
         {"kind": "glob", "glob": "captures/*.cs8", "op": "count"}),
    ],
    "28_paging_track": [
        ("plans", "Paging plans", "plans",
         {"kind": "glob", "glob": "loot/paging_track/plans/plan_*.txt", "op": "count"}),
        ("tx_bytes", "TX paging waves", "bytes",
         {"kind": "glob", "glob": "loot/paging_track/tx_*.cs8", "op": "bytes"}),
    ],
    "39_ta_geoloc": [
        ("fixes", "Positions fixed", "positions",
         {"kind": "glob", "glob": "loot/ta_geoloc/positions.tsv", "op": "count"}),
    ],
    "46_lpp": [
        ("positions", "Positions forged", "positions",
         {"kind": "glob", "glob": "loot/lpp/positions.tsv", "op": "count"}),
    ],
    # EXPLOIT KITS / BASEBAND / INTERCEPT
    "20_gsm_cve": [
        ("runs", "Runs recorded", "runs",
         {"kind": "rows", "path": "loot/gsm_cve/runs.tsv"}),
        ("plans", "Handoff plans", "plans",
         {"kind": "glob", "glob": "loot/gsm_cve/plans/plan_*.txt", "op": "count"}),
    ],
    "21_lte_cve": [
        ("runs", "Runs recorded", "runs",
         {"kind": "rows", "path": "loot/lte_cve/runs.tsv"}),
        ("plans", "Handoff plans", "plans",
         {"kind": "glob", "glob": "loot/lte_cve/plans/plan_*.txt", "op": "count"}),
    ],
    "22_nr_cve": [
        ("runs", "Runs recorded", "runs",
         {"kind": "rows", "path": "loot/nr_cve/runs.tsv"}),
        ("plans", "Handoff plans", "plans",
         {"kind": "glob", "glob": "loot/nr_cve/plans/plan_*.txt", "op": "count"}),
    ],
    "35_baseband": [
        ("payloads", "Payloads handed off", "payloads",
         {"kind": "glob", "glob": "loot/baseband/*/payload.bin", "op": "count"}),
        ("payload_bytes", "Bytes handed off", "bytes",
         {"kind": "glob", "glob": "loot/baseband/*/payload.bin", "op": "bytes"}),
    ],
    "54_baseband_exploit": [
        ("corpus", "L2 corpus vectors", "vectors",
         {"kind": "verb", "module": "54_baseband_exploit", "verb": ["--l2-corpus"], "op": "rows"}),
    ],
    "55_nr_inject": [
        ("auth_captures", "Auth requests captured", "captures",
         {"kind": "count_where", "path": "loot/nr_inject/auth_requests.tsv", "where": ["1=~^frame"]}),
    ],
    "56_baseband_diag": [
        ("ports", "DIAG ports present", "ports",
         {"kind": "verb", "module": "56_baseband_diag", "verb": ["--ports"], "op": "lines"}),
        ("kat", "Known-answer vectors", "vectors",
         {"kind": "verb", "module": "56_baseband_diag", "verb": ["--kat"], "op": "rows"}),
    ],
    "42_li_probe": [
        ("artefacts", "LI artefacts written", "files",
         {"kind": "glob", "glob": "loot/li_probe/*", "op": "count"}),
    ],
    "44_carrier_api": [
        ("plans", "Request plans written", "files",
         {"kind": "glob", "glob": "loot/carrier_api/*.txt", "op": "count"}),
    ],
}

CATEGORY_ORDER = ["SYSTEM", "RECON", "RADIO", "ACCESS", "CORE NETWORK", "SIM / IDENTITY",
                  "BASEBAND / DEVICE", "TRACKING", "ANALYSIS", "EXPLOIT KITS",
                  "INTERCEPT / CARRIER"]


# ── fleet ─────────────────────────────────────────────────────────────

def module_table() -> list[tuple[str, str, str]]:
    """(id, title, category) from the generated index, in launcher order."""
    found: list[tuple[str, str, str]] = []
    for line in lines_of(ROOT / "module_index.tsv")[1:]:
        fields = line.split("\t")
        if len(fields) >= 3:
            found.append((fields[0], fields[1], fields[2]))
    return found


def fleet_rows(mods: list[tuple[str, str, str]]) -> list[tuple[str, str, str, str, str]]:
    """(key, label, value, unit, source) — every number the page shows as a tile."""
    loot = ROOT / "loot"
    dirs = [path for path in loot.iterdir() if path.is_dir()] if loot.is_dir() else []
    files = [path for path in loot.rglob("*") if path.is_file()]
    empty = [path for path in dirs if not any(child.is_file() for child in path.rglob("*"))]
    presses: dict[str, int] = {}
    for line in lines_of(ROOT / "state" / "recent.tsv"):
        key, _, count = line.partition("\t")
        if key and count.strip().isdigit():
            presses[key] = int(count)
    cases = [path for path in (ROOT / "cases").iterdir() if path.is_dir()] if (ROOT / "cases").is_dir() else []
    evidence = sum(len(lines_of(case / "evidence.tsv")) - 1 for case in cases)
    timeline = sum(len(lines_of(case / "timeline.tsv")) - 1 for case in cases)
    captures = sorted(ROOT.glob("captures/*.pcap*"))
    scripts = [module for module, _, _ in mods if (ROOT / "modules" / f"{module}.sh").is_file()]
    selftests = [line for line in lines_of(ROOT / "module_index.tsv")[1:].__iter__()
                 if line.split("\t")[4:5] == ["1"]]

    return [
        ("modules", "Modules", str(len(mods)), "", "module_index.tsv"),
        ("installed", "Scripts present", str(len(scripts)), "", "modules/"),
        ("selftests", "With selftest", str(len(selftests)), "", "module_index.tsv"),
        ("loot_files", "Loot files", str(len(files)), "", "loot/"),
        ("loot_bytes", "Loot size", f"{sum(p.stat().st_size for p in files) / 1e6:.1f}", "MB", "loot/"),
        ("empty_shelves", "Empty shelves", str(len(empty)), "", "loot/"),
        ("warm_modules", "Modules pressed", str(len(presses)), "", "state/recent.tsv"),
        ("presses", "Runs recorded", str(sum(presses.values())), "", "state/recent.tsv"),
        ("cold_modules", "Never pressed", str(len(mods) - len(presses)), "", "state/recent.tsv"),
        ("cases", "Cases", str(len(cases)), "", "cases/"),
        ("evidence", "Evidence rows", str(max(0, evidence)), "", "cases/*/evidence.tsv"),
        ("timeline", "Timeline events", str(max(0, timeline)), "", "cases/*/timeline.tsv"),
        ("captures", "Captures", str(len(captures)), "", "captures/"),
        ("capture_bytes", "Capture size",
         f"{sum(p.stat().st_size for p in captures) / 1e3:.0f}", "kB", "captures/"),
    ]


# ── entry point ───────────────────────────────────────────────────────

@dataclass(frozen=True)
class Row:
    scope: str
    module: str
    key: str
    label: str
    value: str
    unit: str
    source: str

    def line(self) -> str:
        return "\t".join((self.scope, self.module, self.key, self.label,
                          self.value, self.unit, self.source))


def build(deep: bool) -> list[Row]:
    mods = module_table()
    rows = [Row("fleet", "-", key, label, value, unit, source)
            for key, label, value, unit, source in fleet_rows(mods)]
    for module, title, _category in mods:
        for key, label, unit, spec in MODULES.get(module, []):
            if spec["kind"] == "verb" and not deep:
                continue
            sources = ([ROOT / "modules" / f"{module}.sh"] if spec["kind"] == "verb"
                       else resolve(spec))
            if spec["kind"] != "verb" and not sources:
                continue
            try:
                value = EVALUATORS[spec["kind"]](spec, sources)
            except (ValueError, KeyError, OSError):
                continue
            text = tidy(value)
            # A zero here is the absence of an answer, not a measurement: the
            # store is empty or the module has not been used. Printing it would
            # fill the page with noise that looks like data.
            if text in ("0", "no", ""):
                continue
            # A verb is a shell word. The page names the script that answers
            # instead: nothing the interface prints is a flag to type.
            source = (f"modules/{module}.sh" if spec["kind"] == "verb"
                      else spec.get("glob") or spec.get("path", ""))
            rows.append(Row("module", module, key, label, text, unit, source))
    return rows


def main() -> int:
    global ROOT

    parser = argparse.ArgumentParser(description="Write the IMSIsting stats index")
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--fast", action="store_true",
                        help="skip the input-free module verbs (0.2 s against 0.3 s)")
    parser.add_argument("--print", action="store_true", help="write to stdout, not the index")
    arguments = parser.parse_args()

    ROOT = arguments.root.resolve()
    rows = build(not arguments.fast)
    text = "scope\tmodule\tkey\tlabel\tvalue\tunit\tsource\n" + "\n".join(row.line() for row in rows) + "\n"
    if arguments.print:
        sys.stdout.write(text)
        return 0
    INDEX.parent.mkdir(parents=True, exist_ok=True)
    INDEX.write_text(text, encoding="utf-8")
    print(f"{len(rows)} statistics -> {INDEX}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
