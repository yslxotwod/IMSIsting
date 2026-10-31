#!/usr/bin/env python3
"""Self-contained HTML report writer for the analysis modules.

The analysis kit produces TSV rows; a report is those rows plus a header,
and nothing else. This writer emits ONE file with the stylesheet inlined and
no external asset of any kind -- no CDN, no image, no font, no script, no
network fetch. A report written on an air-gapped machine therefore renders
the same way in any browser, and a reader can see that by reading the file.

Input (stdin or --in FILE), one row per line, tabs:
    <section>\t<key>\t<value>[\t<evidence>]

Output: the HTML document on --out PATH (default stdout), and one TSV status
line on stderr:
    html-report\t<path>\t<bytes>\tsections=<n>\trows=<n>\t<td class=...>none

Doctrine: a row whose value is the literal `unobserved` is rendered in the
"unobserved" class so a grey answer cannot be mistaken for a clean one in
the report. Nothing here judges a value; the module that produced the row
already did.

Exit codes: 0 written, 2 usage, 1 refused (unwritable output path).
"""
import argparse
import html
import os
import re
import sys

DOCTYPE = "<!DOCTYPE html>"

STYLE = """
:root { color-scheme: light dark; }
body { font: 14px/1.45 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
       margin: 0; padding: 24px 20px 48px; max-width: 1100px; }
h1 { font-size: 20px; margin: 0 0 4px; }
h2 { font-size: 15px; margin: 26px 0 8px; padding-bottom: 4px; border-bottom: 1px solid #8884; }
.meta { color: #777; font-size: 12px; margin: 0 0 18px; }
table { border-collapse: collapse; width: 100%; font-size: 13px; }
th, td { text-align: left; padding: 4px 8px; border-bottom: 1px solid #8883; vertical-align: top; }
th { font-weight: 600; color: #555; }
td.k { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; width: 26%; }
td.e { color: #777; font-size: 12px; }
tr.unobserved td.v { color: #8a6d00; font-style: italic; }
tr.measured td.v { font-weight: 600; }
.empty { color: #777; font-style: italic; padding: 8px 0; }
"""

ROW_RE = re.compile(r"^[^\t]*(\t|$)")


def esc(value):
    """Escape for HTML text. The report is data, never markup."""
    return html.escape("" if value is None else str(value), quote=True)


def read_rows(stream):
    """Parse TSV rows; a malformed line is kept as a row with a note."""
    rows = []
    for lineno, line in enumerate(stream, 1):
        line = line.rstrip("\n").rstrip("\r")
        if not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) < 3:
            ncols = len(parts)
            parts = parts + [""] * (3 - ncols)
            parts[3:] = ["line %d had %d columns, not 3 or 4" % (lineno, ncols)]
        rows.append((parts[0], parts[1], parts[2],
                     parts[3] if len(parts) > 3 else ""))
    return rows


def render(title, source, rows, generated):
    """One document: header, per-section tables, inlined style."""
    sections = []
    by_section = {}
    for (section, key, value, evidence) in rows:
        if section not in by_section:
            by_section[section] = []
            sections.append(section)
        by_section[section].append((key, value, evidence))

    out = [DOCTYPE, '<html lang="en"><head><meta charset="utf-8">',
           '<meta name="viewport" content="width=device-width, initial-scale=1">',
           "<title>%s</title>" % esc(title), "<style>", STYLE.strip(), "</style>",
           "</head><body>", "<h1>%s</h1>" % esc(title),
           '<p class="meta">generated %s &middot; source %s &middot; %d rows in %d sections'
           ' &middot; self-contained: no external asset, no script</p>'
           % (esc(generated), esc(source or "-"), len(rows), len(sections))]

    if not rows:
        out.append('<p class="empty">No rows. Nothing was measured, so this report '
                   'states nothing rather than reporting zero.</p>')

    for section in sections:
        out.append("<h2>%s</h2>" % esc(section))
        out.append("<table><thead><tr><th>%s</th><th>%s</th>"
                   "<th>%s</th></tr></thead><tbody>"
                   % ("key", "value", "evidence / reference"))
        for (key, value, evidence) in by_section[section]:
            lowered = (value or "").strip().lower()
            cls = "unobserved" if lowered == "unobserved" else (
                "measured" if lowered else "v")
            out.append('<tr class="%s"><td class="k">%s</td>'
                       '<td class="v">%s</td><td class="e">%s</td></tr>'
                       % (cls, esc(key), esc(value), esc(evidence)))
        out.append("</tbody></table>")

    out.append("</body></html>")
    return "\n".join(out) + "\n"


def selftest():
    """Prove the two properties that matter: escaped, and nothing external."""
    bad = 0

    def chk(name, ok, detail=""):
        nonlocal bad
        print("%s\t%s\t%s" % ("PASS" if ok else "FAIL", name, detail))
        if not ok:
            bad += 1

    rows = [("summary", "frames", "12", "measured"),
            ("summary", "sip", "unobserved", "no SIP frame in this capture"),
            ("evil", "<b>tag</b>", 'a"quote', "x")]
    doc = render("T & <t>", "/tmp/a&b", rows, "1970-01-01T00:00:00Z")
    chk("doctype", doc.startswith(DOCTYPE))
    chk("escaped-key", "<b>tag</b>" not in doc)
    chk("escaped-text", "&lt;b&gt;tag&lt;/b&gt;" in doc)
    chk("escaped-title", "T &amp; &lt;t&gt;" in doc)
    chk("escaped-source", "/tmp/a&amp;b" in doc)
    chk("unobserved-class", 'class="unobserved"' in doc)
    chk("measured-class", 'class="measured"' in doc)
    chk("no-script", "<script" not in doc.lower())
    chk("no-http", "http://" not in doc and "https://" not in doc)
    chk("no-src", "src=" not in doc.lower() and "<img" not in doc.lower())
    chk("no-link", "<link" not in doc.lower() and "@import" not in doc)
    chk("inline-style", "<style>" in doc and "</style>" in doc)
    chk("row-count", doc.count('<tr class=') == 3, "3 data rows")
    chk("section-headings", doc.count("<h2>") == 2, "2 sections")
    empty = render("empty", "", [], "t")
    chk("empty-note", "No rows." in empty)
    chk("empty-rows", empty.count('<tr class=') == 0)
    chk("short-line", read_rows(["a\tb"])[0][3].startswith("line 1 had 2 columns"))
    chk("blank-skipped", read_rows(["", "\t\t\n"]) == [])
    print("RESULT\t%s" % ("PASS" if bad == 0 else "FAIL(%d)" % bad))
    return 0 if bad == 0 else 1


def main(argv):
    ap = argparse.ArgumentParser(add_help=True)
    ap.add_argument("--title", default="report")
    ap.add_argument("--source", default="")
    ap.add_argument("--in", dest="infile")
    ap.add_argument("--out")
    ap.add_argument("--generated", default="")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args(argv)

    if a.selftest:
        return selftest()

    if a.infile:
        try:
            with open(a.infile, "r", encoding="utf-8", errors="replace") as fh:
                rows = read_rows(fh)
        except OSError as exc:
            sys.stderr.write("ERROR\tcannot read %s: %s\n" % (a.infile, exc))
            return 1
    else:
        rows = read_rows(sys.stdin)

    generated = a.generated or "unobserved"
    doc = render(a.title, a.source, rows, generated)

    if a.out:
        try:
            parent = os.path.dirname(os.path.abspath(a.out))
            if parent and not os.path.isdir(parent):
                os.makedirs(parent, exist_ok=True)
            with open(a.out, "w", encoding="utf-8") as fh:
                fh.write(doc)
        except OSError as exc:
            sys.stderr.write("ERROR\trefused: cannot write %s: %s\n" % (a.out, exc))
            return 1
        sys.stderr.write("html-report\t%s\t%d\tsections=%d\trows=%d\texternal=none\n"
                         % (a.out, len(doc.encode()), len({r[0] for r in rows}), len(rows)))
    else:
        sys.stdout.write(doc)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
