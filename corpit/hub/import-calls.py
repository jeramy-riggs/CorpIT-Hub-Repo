#!/usr/bin/env python3
# =====================================================================
# import-calls.py  —  Vonage "Call Queues Report" PDF -> sdops_call upserts
#
#   python3 import-calls.py <report.pdf>
#
# Prints one `INSERT INTO sdops_call ... ON DUPLICATE KEY UPDATE ...`
# statement per call to STDOUT, one per line. Everything else -- warnings,
# counts, parse diagnostics -- goes to STDERR.
#
# CONTRACT (set by sdops-routes.js POST /api/sdops/calls/import):
#   * The route runs this with execFile('python3', [script, tmpPath]).
#   * It keeps only stdout lines starting exactly with 'INSERT INTO sdops_call'
#     and executes each one against corpit_hub. Nothing else on stdout is read.
#   * Therefore: one statement per line, no embedded newlines, and NOTHING
#     untrusted may reach stdout unescaped. Every value below goes through
#     sqlstr()/sqlint(), and call_id is additionally shape-checked.
#   * A 501 from the route means this file is missing. Its presence at
#     /var/www/corpit-hub-api/import-calls.py is what re-enables the page's
#     Import button (importCallsAvailable() is an fs.existsSync check).
#
# WHY POSITIONAL PARSING, NOT extract_tables():
#   The report draws no ruling lines around data rows, so pdfplumber's table
#   extractor returns the header and nothing else. The generator also emits a
#   doubled text layer for bold headings ("CCaallll QQuueeuueess"), so naive
#   text scraping is unusable. Words carry correct coordinates, though, and
#   the eleven columns are left-aligned at stable x0 positions, so columns are
#   recovered from the header's own x0 anchors and each word is assigned to
#   the nearest anchor at or left of it.
#
#   One logical record spans several text lines, because Call ID, Call Queue,
#   Date/Time and From all wrap. A record therefore begins at each Call-ID
#   fragment shaped like the head of a UUID (8 hex + '-') and runs until the
#   next one.
#
# TIMEZONE — READ THIS BEFORE TRUSTING THE NUMBERS:
#   The PDF prints wall-clock time in the Vonage account's timezone.
#   sdops_call.started_at stores UTC: the existing row 2026-08-27 17:23:18
#   renders as "Aug 27, 10:23 AM" on the portal, i.e. UTC-7. So local times
#   are converted to UTC on the way in. If your Vonage account is not set to
#   US/Pacific, override it:  SDOPS_CALLS_TZ=America/New_York
#
# NOT CAPTURED: the report's Extension, Custom Tag and Answered Date/Time
# columns have no corresponding sdops_call fields. They are parsed and
# reported in the stderr summary but not written. Say the word and they can
# be added to the schema.
# =====================================================================
import os
import re
import sys
from datetime import datetime
from zoneinfo import ZoneInfo

try:
    import pdfplumber
except ImportError:
    sys.exit("FATAL: pdfplumber is not installed. On corpit:\n"
             "  sudo -H python3 -m pip install --break-system-packages pdfplumber")

LOCAL_TZ = ZoneInfo(os.environ.get("SDOPS_CALLS_TZ", "America/Los_Angeles"))
UTC = ZoneInfo("UTC")

# Header label -> sdops_call handling. Order is irrelevant; columns are found
# by matching these labels in the header, so a Vonage column reshuffle is
# survivable. A missing REQUIRED label aborts rather than guessing.
REQUIRED = ["Call ID", "Date/Time", "Disposition", "Talk Time", "Wait Time"]
OPTIONAL = ["Call Queue", "Agent Name", "Custom Tag", "Answered Date/Time",
            "Extension", "From"]

# A record begins at its Call ID. The ID wraps across lines in every report
# seen so far ('E54b5f78-' / '0ea1-48cf-' / ...), but this deliberately
# matches any fragment STARTING with 8 hex digits and a hyphen, so a report
# that wraps at a different point -- or not at all, if the column widens --
# is still detected instead of silently dropping the row.
UUID_HEAD = re.compile(r"^[0-9A-Fa-f]{8}-")
UUID_FULL = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
DATE_RE = re.compile(r"\d{2}/\d{2}/\d{4}")
FOOTER_RE = re.compile(r"^(Page|\d+/\d+)$")


def warn(*a):
    print(*a, file=sys.stderr)


def sqlstr(v):
    """Quote for MySQL, or NULL. Control characters are stripped, not escaped:
    nothing in this report legitimately contains them, and a newline would
    split the statement across lines and break the route's line filter."""
    if v is None:
        return "NULL"
    s = str(v)
    s = "".join(ch for ch in s if ch >= " " and ch != "\x7f")
    s = s.replace("\\", "\\\\").replace("'", "''")
    return "'" + s + "'"


def sqlint(v):
    return str(int(v))


def hhmmss_to_sec(txt):
    """'00:01:23' -> 83. Also accepts 'MM:SS'. Unparseable -> 0."""
    if not txt:
        return 0
    parts = txt.strip().split(":")
    try:
        parts = [int(p) for p in parts]
    except ValueError:
        return 0
    if len(parts) == 3:
        return parts[0] * 3600 + parts[1] * 60 + parts[2]
    if len(parts) == 2:
        return parts[0] * 60 + parts[1]
    if len(parts) == 1:
        return parts[0]
    return 0


def norm_phone(txt):
    """'(865) 933- 8148' (wrapped across lines) -> '(865) 933-8148'.
    Matches the format already stored in sdops_call. Anything that is not a
    plain 10- or 11-digit US number is passed through with whitespace
    collapsed, rather than mangled."""
    if not txt:
        return None
    raw = " ".join(txt.split())
    digits = re.sub(r"\D", "", raw)
    if len(digits) == 11 and digits.startswith("1"):
        digits = digits[1:]
    if len(digits) == 10:
        return f"({digits[0:3]}) {digits[3:6]}-{digits[6:]}"
    return raw or None


def parse_started_at(txt):
    """'09/16/2026 09:21:16 AM' (account-local) -> '2026-09-16 16:21:16' UTC."""
    if not txt:
        return None
    s = " ".join(txt.split())
    for fmt in ("%m/%d/%Y %I:%M:%S %p", "%m/%d/%Y %H:%M:%S",
                "%m/%d/%Y %I:%M %p", "%m/%d/%Y"):
        try:
            naive = datetime.strptime(s, fmt)
        except ValueError:
            continue
        return (naive.replace(tzinfo=LOCAL_TZ)
                     .astimezone(UTC)
                     .strftime("%Y-%m-%d %H:%M:%S"))
    warn(f"  ! unparseable Date/Time: {s!r}")
    return None


def header_anchors(words):
    """Locate the column header and return [(x0, label), ...] left to right.
    The header occupies up to three stacked lines; 'Disposition' is a
    single-line label and is used to find the block."""
    disp = [w for w in words if w["text"] == "Disposition"]
    if not disp:
        return None
    y = disp[0]["top"]
    band = [w for w in words if abs(w["top"] - y) <= 10]

    # Two-stage clustering, because a header label can be BOTH multi-word on
    # one line ("Call ID", "Talk Time") AND stacked over two lines
    # ("Call"/"Queue", "Wait"/"Time"). Clustering on x0 alone splits the
    # first kind; clustering on line alone splits the second.
    #
    # 1. group each line's words into runs separated by more than a word gap
    lines = {}
    for w in band:
        key = round(w["top"], 1)
        match = next((k for k in lines if abs(k - key) <= 2.0), None)
        lines.setdefault(match if match is not None else key, []).append(w)

    tokens = []  # (x0, line_top, text)
    for top, ws in lines.items():
        ws.sort(key=lambda w: w["x0"])
        run = [ws[0]]
        for w in ws[1:]:
            if w["x0"] - run[-1]["x1"] <= 8.0:
                run.append(w)
            else:
                tokens.append((run[0]["x0"], top, " ".join(x["text"] for x in run)))
                run = [w]
        tokens.append((run[0]["x0"], top, " ".join(x["text"] for x in run)))

    # 2. merge tokens across lines into columns by shared left edge
    cols = {}
    for x0, top, text in tokens:
        match = next((k for k in cols if abs(k - x0) <= 3.0), None)
        cols.setdefault(match if match is not None else x0, []).append((top, text))

    out = []
    for x0, parts in sorted(cols.items()):
        label = " ".join(t for _, t in sorted(parts))
        out.append((x0, label))
    return out, max(w["bottom"] for w in band)


def column_of(x0, anchors):
    """Nearest anchor at or to the left of x0 (3pt tolerance for drift)."""
    best = None
    for ax0, label in anchors:
        if x0 >= ax0 - 3.0:
            best = label
        else:
            break
    return best


def records_from_page(page, anchors, header_bottom):
    words = [w for w in page.extract_words()
             if w["top"] > header_bottom + 1 and not FOOTER_RE.match(w["text"])]
    if not words:
        return []

    idcol = anchors[0][1]
    starts = sorted(
        (w["top"] for w in words
         if column_of(w["x0"], anchors) == idcol and UUID_HEAD.match(w["text"])))
    if not starts:
        return []

    bands = []
    for i, top in enumerate(starts):
        lo = top - 2.0
        hi = starts[i + 1] - 2.0 if i + 1 < len(starts) else float("inf")
        bands.append((lo, hi))

    out = []
    for lo, hi in bands:
        cells = {}
        for w in words:
            if not (lo <= w["top"] < hi):
                continue
            col = column_of(w["x0"], anchors)
            if col is None:
                continue
            cells.setdefault(col, []).append(w)
        rec = {}
        for col, ws in cells.items():
            ws.sort(key=lambda w: (round(w["top"], 1), w["x0"]))
            # the Call ID is one token split mid-string by wrapping, so it
            # rejoins with no separator; every other column is word-separated
            sep = "" if col == idcol else " "
            rec[col] = sep.join(w["text"] for w in ws).strip()
        out.append(rec)
    return out


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: import-calls.py <report.pdf>")
    path = sys.argv[1]

    emitted = skipped = 0
    seen = set()
    extras = {"Extension": 0, "Custom Tag": 0, "Answered Date/Time": 0}

    with pdfplumber.open(path) as pdf:
        warn(f"[import-calls] {os.path.basename(path)}: {len(pdf.pages)} page(s), "
             f"timezone {LOCAL_TZ}")
        anchors = header_bottom = None
        for pno, page in enumerate(pdf.pages, 1):
            words = page.extract_words()
            found = header_anchors(words)
            if found:
                anchors, header_bottom = found
                labels = [l for _, l in anchors]
                missing = [r for r in REQUIRED if r not in labels]
                if missing:
                    sys.exit(f"FATAL: page {pno} header is missing required "
                             f"column(s): {missing}\nfound: {labels}")
            elif anchors is None:
                warn(f"  page {pno}: no header and none carried over, skipping")
                continue

            recs = records_from_page(page, anchors, header_bottom)
            warn(f"  page {pno}: {len(recs)} record(s)")

            for rec in recs:
                cid = (rec.get("Call ID") or "").strip().lower()
                if not UUID_FULL.match(cid):
                    warn(f"  ! skipping row, Call ID not a UUID: {cid!r}")
                    skipped += 1
                    continue
                if cid in seen:
                    warn(f"  ! duplicate Call ID within this file, skipping: {cid}")
                    skipped += 1
                    continue
                started = parse_started_at(rec.get("Date/Time"))
                if started is None:
                    skipped += 1
                    continue

                for k in extras:
                    if (rec.get(k) or "").strip():
                        extras[k] += 1

                agent = (rec.get("Agent Name") or "").strip() or None
                frm = norm_phone(rec.get("From"))
                disp = (rec.get("Disposition") or "").strip() or None

                cols = ("call_id, agent_name, from_number, to_number, direction, "
                        "disposition, talk_time_sec, wait_time_sec, started_at")
                vals = ", ".join([
                    sqlstr(cid),
                    sqlstr(agent),
                    sqlstr(frm),
                    "NULL",            # to_number: no source column in this report
                    sqlstr("inbound"),  # queue reports are inbound by definition
                    sqlstr(disp[:32] if disp else None),
                    sqlint(hhmmss_to_sec(rec.get("Talk Time"))),
                    sqlint(hhmmss_to_sec(rec.get("Wait Time"))),
                    sqlstr(started),
                ])
                # collected_at is set explicitly so a re-upload of unchanged
                # rows still advances it. FEEDS.calls reads MAX(collected_at);
                # without this a no-op re-import would leave the feed looking
                # stale even though you had just refreshed it.
                upd = ("agent_name=VALUES(agent_name), from_number=VALUES(from_number), "
                       "to_number=VALUES(to_number), direction=VALUES(direction), "
                       "disposition=VALUES(disposition), talk_time_sec=VALUES(talk_time_sec), "
                       "wait_time_sec=VALUES(wait_time_sec), started_at=VALUES(started_at), "
                       "collected_at=CURRENT_TIMESTAMP")
                stmt = (f"INSERT INTO sdops_call ({cols}) VALUES ({vals}) "
                        f"ON DUPLICATE KEY UPDATE {upd};")
                assert "\n" not in stmt
                print(stmt)
                seen.add(cid)
                emitted += 1

    warn(f"[import-calls] emitted={emitted} skipped={skipped}")
    for k, n in extras.items():
        if n:
            warn(f"  note: {n} row(s) had a non-empty '{k}' — no column in "
                 f"sdops_call, not imported")
    if emitted == 0:
        warn("[import-calls] no call records found — the route will answer 422")


if __name__ == "__main__":
    main()
