#!/usr/bin/env python3
"""Run a RAKSHA submission against a kit-shaped dataset and print a full scorecard.

    python tools/eval_gauntlet.py --set eval_sets/A7 --label baseline
    python tools/eval_gauntlet.py --set Secret-Wards-ToolKit --label dev     # the official practice set

What it runs (all offline):
  1. the submission 3x: secret S1 (run A), S1 again (run B, determinism), S2 (run C, unlinkability),
     each with a private TMP/HOME that is scanned afterwards
  2. official  validate_output.py  and  check_dev.py --truth
  3. the local 100-point estimator  tools/local_scorer.py  (with run C for cross-release risk)
  4. extra checks the practice checker does not do:
       strict token-level name leaks (official "keys" semantics), decoded hidden payloads
       (base64 / %XX / HTML entities / \\uXXXX / homoglyphs / zero-width), canaries in stdout/stderr/TMP,
       length-of-stay preservation, truthful age bands, linkage trap outcomes, clean-file integrity
"""
from __future__ import annotations

import argparse
import base64
import binascii
import csv
import datetime as dt
import hashlib
import html
import io
import itertools
import json
import os
import re
import shutil
import subprocess
import sys
import time
import unicodedata
import urllib.parse
from collections import Counter, defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
KIT = Path(os.environ.get("SECRET_WARDS_KIT") or ROOT / "Secret-Wards-ToolKit")
sys.path.insert(0, str(ROOT))

_HOMO = str.maketrans({"а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y",
                       "х": "x", "і": "i", "А": "A", "Е": "E", "О": "O", "Р": "P",
                       "С": "C", "ο": "o", "α": "a"})
_ZW = re.compile("[​‌‍⁠﻿­]")
_DIG = str.maketrans("०१२३४५६७८९", "0123456789")
_B64 = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")
_UESC = re.compile(r"(?:\\u[0-9a-fA-F]{4})+")
_PSN = re.compile(r"\bPSN-[0-9A-Z]{4,12}\b")


def norm(s: str) -> str:
    s = unicodedata.normalize("NFKC", s).translate(_HOMO)
    s = _ZW.sub("", s).translate(_DIG)
    s = "".join(c for c in unicodedata.normalize("NFKD", s) if not unicodedata.combining(c) or "ऀ" <= c <= "ॿ")
    return " ".join(s.casefold().split())


def decode_payloads(text: str) -> str:
    extra = []
    for m in _B64.finditer(text):
        tok = m.group(0)
        try:
            extra.append(base64.b64decode(tok + "=" * (-len(tok) % 4)).decode("utf-8", errors="ignore"))
        except (binascii.Error, ValueError):
            pass
    for m in _UESC.finditer(text):
        try:
            extra.append(m.group(0).encode().decode("unicode_escape"))
        except Exception:
            pass
    for m in re.finditer(r"(?:%[0-9A-Fa-f]{2}|[A-Za-z0-9.\-_])*%[0-9A-Fa-f]{2}(?:%[0-9A-Fa-f]{2}|[A-Za-z0-9.\-_])*", text):
        extra.append(urllib.parse.unquote(m.group(0)))
    for m in re.finditer(r"(?:&#?\w+;)+", text):
        extra.append(html.unescape(m.group(0)))
    return text + ("\n" + "\n".join(extra) if extra else "")


def read_out(p: Path) -> str:
    try:
        return p.read_bytes().decode("utf-8", errors="replace")
    except OSError:
        return ""


# ------------------------------------------------------------------------------------------- runs
def run_submission(repo: Path, inp: Path, out: Path, secret: str) -> dict:
    if out.exists():
        shutil.rmtree(out)
    priv = out.parent / f"{out.name}_private"
    if priv.exists():
        shutil.rmtree(priv)
    (priv / "tmp").mkdir(parents=True)
    (priv / "home").mkdir(parents=True)
    env = dict(os.environ, RAKSHA_SECRET=secret, RAKSHA_INPUT=str(inp), RAKSHA_OUTPUT=str(out),
               TMPDIR=str(priv / "tmp"), TMP=str(priv / "tmp"), TEMP=str(priv / "tmp"), HOME=str(priv / "home"),
               USERPROFILE=str(priv / "home"), PYTHONIOENCODING="utf-8", PYTHONDONTWRITEBYTECODE="1")
    t0 = time.monotonic()
    p = subprocess.run([sys.executable, "main.py", "--input", str(inp), "--output", str(out)], cwd=repo, env=env,
                       capture_output=True, timeout=900)
    secs = time.monotonic() - t0
    side = p.stdout.decode("utf-8", "replace") + "\n" + p.stderr.decode("utf-8", "replace")
    tmp_files = [f for f in (priv / "tmp").rglob("*") if f.is_file()] + [f for f in (priv / "home").rglob("*") if f.is_file()]
    side_files = "\n".join(read_out(f) for f in tmp_files)
    return {"exit": p.returncode, "seconds": round(secs, 2), "side_text": side, "tmp_files": len(tmp_files),
            "tmp_text": side_files, "stderr_tail": p.stderr.decode("utf-8", "replace")[-600:]}


def tree_digest(root: Path) -> dict[str, str]:
    return {f.relative_to(root).as_posix(): hashlib.sha256(f.read_bytes()).hexdigest()
            for f in sorted(root.rglob("*")) if f.is_file()}


# ------------------------------------------------------------------------------------------- extra checks
_DATE_PATTERNS = [
    (re.compile(r"\b(\d{4})-(\d{2})-(\d{2})\b"), "ymd"),
    (re.compile(r"\b(\d{1,2})[./-](\d{1,2})[./-](\d{4})\b"), "dmy"),
    (re.compile(r"\b(\d{1,2})[- ](Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*[- ,]+(\d{4})\b", re.I), "dmon"),
    (re.compile(r"\b(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\.? (\d{1,2}), (\d{4})\b"), "long"),
]
_MON = {m: i + 1 for i, m in enumerate(["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"])}


def find_dates(text: str, mdy: bool) -> list[dt.date]:
    text = text.translate(_DIG)
    out = []
    for rx, kind in _DATE_PATTERNS:
        for m in rx.finditer(text):
            try:
                if kind == "ymd":
                    out.append(dt.date(int(m.group(1)), int(m.group(2)), int(m.group(3))))
                elif kind == "dmy":
                    a, b, y = int(m.group(1)), int(m.group(2)), int(m.group(3))
                    out.append(dt.date(y, a, b) if mdy else dt.date(y, b, a))
                elif kind == "dmon":
                    out.append(dt.date(int(m.group(3)), _MON[m.group(2)[:3].lower()], int(m.group(1))))
                else:
                    out.append(dt.date(int(m.group(3)), _MON[m.group(1)[:3].lower()], int(m.group(2))))
            except (ValueError, KeyError):
                pass
    return out


_BAND = re.compile(r"(\d{1,3})\s*(?:-|–|to)\s*(\d{1,3})|(\d{1,3})\s*\+|^\s*(\d{1,3})\b")


def age_ok(cell: str, true_age: int) -> bool | None:
    s = str(cell).translate(_DIG)
    m = _BAND.search(s)
    if not m:
        return None
    if m.group(1):
        lo, hi = int(m.group(1)), int(m.group(2))
        if lo > 1800:   # birth-year range like 1947-1966: convert
            return None
        return lo <= true_age <= hi
    if m.group(3):
        return true_age >= int(m.group(3))
    return int(m.group(4)) == true_age


def output_rel(rel: str, finfo: dict, renamed: dict) -> str:
    decl = renamed.get(finfo["sha256"])
    return str(decl).replace("sanitized/", "", 1) if decl else rel


def extra_checks(truth: dict, inp: Path, outA: Path, outC: Path, runs: dict) -> dict:
    san = outA / "sanitized"
    report = json.loads((outA / "report.json").read_text(encoding="utf-8")) if (outA / "report.json").is_file() else {"files": []}
    renamed = {e.get("input_sha256"): e.get("output") for e in report.get("files") or []}
    recs: dict[str, dict[str, str | None]] = defaultdict(dict)
    if (outA / "records.jsonl").is_file():
        for line in (outA / "records.jsonl").read_text(encoding="utf-8").splitlines():
            if line.strip():
                r = json.loads(line)
                recs[str(r["file"]).replace("sanitized/", "", 1)][r["loc"]] = r.get("patient")

    res: dict = {}
    tok_tot = tok_leak = 0.0
    tok_by_script: dict[str, list[float]] = defaultdict(list)
    payload_hits: list[str] = []
    critical_left: set[str] = set()
    leak_examples: list[str] = []
    los_ok = los_tot = 0
    age_ok_n = age_bad = 0
    age_bad_ex: list[str] = []
    trap_pres: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    clean_ok = clean_tot = 0

    for rel, f in truth["files"].items():
        out_rel = output_rel(rel, f, renamed)
        p = san / out_rel
        exists = p.is_file()
        raw_out = read_out(p) if exists else ""
        out_n = norm(raw_out)
        out_deep = norm(decode_payloads(raw_out))
        src_raw = (inp / rel).read_bytes().decode("utf-8", errors="replace") if (inp / rel).is_file() else ""
        if f.get("encoding") == "utf-16" and (inp / rel).is_file():
            src_raw = (inp / rel).read_bytes().decode("utf-16", errors="replace")
        src_n = norm(decode_payloads(src_raw))
        allowed_text = " ".join(norm(pv["text"]) for u in f["units"].values() for pv in u.get("preserve") or [])

        if f.get("clean") and (inp / rel).is_file():
            clean_tot += 1
            clean_ok += int(exists and norm(src_raw).split() == out_n.split())

        rows_out: list[list[str]] | None = None
        if exists and f["format"] in ("csv", "tsv"):
            try:
                rows_out = list(csv.reader(io.StringIO(raw_out.lstrip("﻿")), delimiter=f.get("delimiter") or ","))
            except csv.Error:
                rows_out = None

        for loc, u in f["units"].items():
            for e in u["entities"]:
                if e["type"] == "CANARY":
                    continue
                if e.get("match") == "name":
                    for t in e.get("tokens") or []:
                        tn = norm(t)
                        if len(tn) < 3:
                            continue
                        rx = re.compile(r"(?<![\wऀ-ॿ])" + re.escape(tn) + r"(?![\wऀ-ॿ])")
                        allowed = len(rx.findall(allowed_text))
                        n_in = max(1, len(rx.findall(src_n)) - allowed)
                        hay = norm(rel if e["channel"] == "filename" else "") if e["channel"] == "filename" else out_deep
                        if e["channel"] == "filename":
                            hay = norm(out_rel)
                        n_out = max(0, len(rx.findall(hay)) - allowed) if (exists or e["channel"] == "filename") else 0
                        leak = min(1.0, n_out / n_in)
                        tok_tot += 1
                        tok_leak += leak
                        tok_by_script[e["script"]].append(leak)
                        if leak and len(leak_examples) < 25:
                            leak_examples.append(f"{e['type']}/{e['script']}/{e['channel']} '{t}' in {rel}")
                surf = norm(decode_payloads(e["surface"]))
                if e.get("critical") and surf and (exists or e["channel"] == "filename"):
                    hay = norm(out_rel) if e["channel"] == "filename" else out_deep
                    allowed = allowed_text.count(surf)
                    if hay.count(surf) > allowed:
                        critical_left.add(f"{e['type']}:{surf}")
                        if surf not in out_n and e["channel"] != "filename":
                            payload_hits.append(f"{e['type']} hidden in payload: {rel}")
            if exists:
                for pv in u.get("preserve") or []:
                    tag = pv.get("trap") or pv.get("kind")
                    trap_pres[tag][1] += 1
                    trap_pres[tag][0] += int(norm(pv["text"]) in out_n)
                for lp in u.get("los") or []:
                    los_tot += 1
                    if loc.startswith("row:") and rows_out is not None:
                        idx = int(loc.split(":")[1]) + 1
                        txt = " ".join(rows_out[idx]) if idx < len(rows_out) else ""
                    else:
                        txt = raw_out
                    ds = sorted(set(find_dates(txt, f.get("date_hint") == "mdy")))
                    diffs = {(b - a).days for a, b in itertools.combinations(ds, 2)}
                    los_ok += int(lp["days"] in diffs)
                for fl in u.get("fields") or []:
                    if fl["kind"] != "age" or not fl.get("path") or not str(fl["path"]).startswith("col:"):
                        continue
                    if rows_out is None or not loc.startswith("row:"):
                        continue
                    col = fl["path"][4:]
                    hdr = rows_out[0] if rows_out else []
                    if col not in hdr:
                        continue
                    idx = int(loc.split(":")[1]) + 1
                    if idx >= len(rows_out) or hdr.index(col) >= len(rows_out[idx]):
                        continue
                    ok = age_ok(rows_out[idx][hdr.index(col)], int(fl["true"]))
                    if ok is True:
                        age_ok_n += 1
                    elif ok is False:
                        age_bad += 1
                        if len(age_bad_ex) < 6:
                            age_bad_ex.append(f"{rel}:{loc} true={fl['true']} out='{rows_out[idx][hdr.index(col)]}'")

    # canaries everywhere (release + side channels)
    canaries = {norm(e["surface"]) for f in truth["files"].values() for u in f["units"].values() for e in u["entities"]
                if e["type"] == "CANARY"}
    everything = []
    for fp in sorted(outA.rglob("*")):
        if fp.is_file():
            everything.append(fp.relative_to(outA).as_posix())
            everything.append(decode_payloads(read_out(fp)))
    everything.append(runs["A"]["side_text"])
    everything.append(runs["A"]["tmp_text"])
    big = norm("\n".join(everything))
    canary_hits = sorted(c for c in canaries if c and c in big)
    side_leaks = sorted({c.split(":", 1)[1] for c in critical_left} & set())  # placeholder for symmetry

    # linkage trap outcomes
    unit_psn: dict[tuple[str, str], tuple[str, str | None]] = {}
    for rel, f in truth["files"].items():
        out_rel = output_rel(rel, f, renamed)
        fr = recs.get(out_rel, {})
        for loc, u in f["units"].items():
            if u.get("patient") and u.get("link") in ("required", "ambiguous"):
                psn = fr.get(loc)
                if psn is None and loc.startswith("/"):
                    parts = loc.split("/")
                    for i in range(len(parts) - 1, 1, -1):
                        if "/".join(parts[:i]) in fr:
                            psn = fr["/".join(parts[:i])]
                            break
                if psn is None:
                    psn = fr.get("doc")
                unit_psn[(rel, loc)] = (u["patient"], psn)
    by_pt: dict[str, set] = defaultdict(set)
    for (t, y) in unit_psn.values():
        if y:
            by_pt[t].add(y)
    psn_owner: dict[str, set] = defaultdict(set)
    for (t, y) in unit_psn.values():
        if y:
            psn_owner[y].add(t)
    traps = truth.get("traps", {})

    def merged(a: str, b: str) -> bool:
        return bool(by_pt[a] & by_pt[b])

    def unified(pt: str) -> str:
        n_units = sum(1 for (t, _y) in unit_psn.values() if t == pt)
        n_psn = len(by_pt[pt])
        unl = sum(1 for (t, y) in unit_psn.values() if t == pt and not y)
        return f"{n_psn} psn / {n_units} rec ({unl} unlinked)"
    res["linkage_traps"] = {
        "homonym_pairs_kept_apart": f"{sum(1 for a, b in traps.get('homonym_pairs', []) if not merged(a, b))}/{len(traps.get('homonym_pairs', []))}",
        "family_phone_kept_apart": (not merged(*traps["family_phone"])) if traps.get("family_phone") else None,
        "reregistration": {pt: unified(pt) for pt in traps.get("reregistration", [])},
        "fragmented": {pt: unified(pt) for pt in traps.get("fragmented", [])},
        "language": {pt: unified(pt) for pt in traps.get("language", [])},
        "false_merge_psns": sum(1 for owners in psn_owner.values() if len(owners) > 1),
    }

    # determinism + secret rotation
    dA = tree_digest(outA / "sanitized") if (outA / "sanitized").is_dir() else {}
    dB = tree_digest(outA.parent / "B" / "sanitized") if (outA.parent / "B" / "sanitized").is_dir() else {}
    same = sum(1 for k in dA if dB.get(k) == dA[k])
    recA = (outA / "records.jsonl").read_bytes() if (outA / "records.jsonl").is_file() else b""
    recB = (outA.parent / "B" / "records.jsonl").read_bytes() if (outA.parent / "B" / "records.jsonl").is_file() else b""
    rC = {}
    if (outC / "records.jsonl").is_file():
        rC = {(json.loads(l)["file"], json.loads(l)["loc"]): json.loads(l)["patient"] for l in (outC / "records.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()}
    rA = {(json.loads(l)["file"], json.loads(l)["loc"]): json.loads(l)["patient"] for l in recA.decode().splitlines() if l.strip()}
    shared = [k for k in rA if rA[k] and rC.get(k)]
    res["determinism"] = f"{same}/{len(dA)} files identical, records.jsonl {'identical' if recA == recB and recA else 'DIFFERENT'}"
    res["secret_rotation_same_psn"] = f"{sum(1 for k in shared if rA[k] == rC[k])}/{len(shared)}"

    res["strict_token_leak_rate"] = round(tok_leak / tok_tot, 4) if tok_tot else 0.0
    res["strict_token_leak_by_script"] = {s: round(sum(v) / len(v), 4) for s, v in sorted(tok_by_script.items())}
    res["critical_identifiers_left"] = len(critical_left)
    res["critical_examples"] = sorted(critical_left)[:20]
    res["hidden_payload_leaks"] = payload_hits[:10]
    res["token_leak_examples"] = leak_examples
    res["canary_hits_incl_side_channels"] = canary_hits
    res["los_preserved"] = f"{los_ok}/{los_tot}"
    res["age_bands"] = f"{age_ok_n} truthful, {age_bad} WRONG"
    res["age_band_errors"] = age_bad_ex
    res["clean_files_intact"] = f"{clean_ok}/{clean_tot}"
    res["preserve_by_trap"] = {k: f"{v[0]}/{v[1]}" for k, v in sorted(trap_pres.items()) if k}
    res["tmp_home_files_left"] = runs["A"]["tmp_files"]
    return res


# ------------------------------------------------------------------------------------------- main
def main() -> int:
    global KIT
    ap = argparse.ArgumentParser(description="Score a RAKSHA submission on a kit-shaped dataset")
    ap.add_argument("--set", required=True, help="kit-shaped dataset folder (contains dev/ and scoring.toml)")
    ap.add_argument("--repo", default=str(ROOT / "project-raksha"))
    ap.add_argument("--label", default="run")
    ap.add_argument("--kit", default=str(KIT), help="Secret-Wards-ToolKit checkout (validate_output.py, check_dev.py)")
    ap.add_argument("--runs", default=str(ROOT / "eval_runs"), help="where run outputs and scorecards go")
    ap.add_argument("--quiet", action="store_true")
    a = ap.parse_args()
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    KIT = Path(a.kit).resolve()
    if not (KIT / "validate_output.py").is_file():
        ap.error(f"official toolkit not found at {KIT}: pass --kit or set SECRET_WARDS_KIT")
    kit = Path(a.set).resolve()
    repo = Path(a.repo).resolve()
    inp = kit / "dev" / "input"
    truth_path = kit / "dev" / "truth" / "truth.json"
    if not (kit / "scoring.toml").is_file():
        shutil.copy(KIT / "scoring.toml", kit / "scoring.toml")
    runs_dir = (Path(a.runs) / f"{kit.name}__{a.label}")
    runs_dir.mkdir(parents=True, exist_ok=True)
    in_digest = tree_digest(inp)

    runs = {}
    for name, secret in (("A", "gauntlet-secret-1"), ("B", "gauntlet-secret-1"), ("C", "gauntlet-secret-2")):
        runs[name] = run_submission(repo, inp, runs_dir / name, secret)
        if runs[name]["exit"] != 0:
            print(f"[run {name}] exit {runs[name]['exit']}\n{runs[name]['stderr_tail']}")
    outA, outC = runs_dir / "A", runs_dir / "C"
    input_unchanged = tree_digest(inp) == in_digest

    v = subprocess.run([sys.executable, str(KIT / "validate_output.py"), "--input", str(inp), "--output", str(outA)],
                       capture_output=True, text=True, encoding="utf-8", errors="replace", env=dict(os.environ, PYTHONIOENCODING="utf-8"))
    contract = (v.stdout.strip().splitlines() or ["?"])[-1]
    cd = subprocess.run([sys.executable, str(KIT / "check_dev.py"), "--output", str(outA), "--truth", str(truth_path)],
                        capture_output=True, text=True, encoding="utf-8", errors="replace", env=dict(os.environ, PYTHONIOENCODING="utf-8"))
    check_dev_txt = cd.stdout

    from tools.local_scorer import score_release
    try:
        score = score_release(outA, kit, truth_path, outC, inp)
    except Exception as exc:  # keep going: extra checks still useful
        score = {"error": repr(exc)}
    truth = json.loads(truth_path.read_text(encoding="utf-8"))
    extra = extra_checks(truth, inp, outA, outC, runs)

    card = {"set": kit.name, "label": a.label, "contract": contract, "input_unchanged": input_unchanged,
            "runtime_s": runs["A"]["seconds"], "exit_codes": [runs[k]["exit"] for k in "ABC"],
            "local_score": score, "extra": extra}
    (runs_dir / "scorecard.json").write_text(json.dumps(card, indent=2, ensure_ascii=False), encoding="utf-8")

    m = re.search(r"PERSONAL DATA: (\d+) of (\d+)", check_dev_txt)
    med = re.search(r"MEDICAL DATA KEPT: (\d+) of (\d+)", check_dev_txt)
    link = re.search(r"precision ([\d.]+), recall ([\d.]+), F0.5 ([\d.]+).*?people: (\d+)", check_dev_txt)
    can = re.search(r"CANARIES: (\d+) of (\d+)", check_dev_txt)
    print("=" * 78)
    print(f" {kit.name}  [{a.label}]   contract: {contract}   runtime {runs['A']['seconds']}s   exits {card['exit_codes']}")
    print("=" * 78)
    if "total_score" in score:
        c = score["categories"]
        print(f" LOCAL SCORE  {score['total_score']:6.2f} / 100   (before penalties {score['raw_total_before_penalties']}, penalties -{score['penalties']})")
        print(f"   privacy {c['privacy_25']}/25  detection {c['detection_20']}/20  utility {c['utility_20']}/20  "
              f"identity {c['identity_15']}/15  integrity {c['integrity_10']}/10  perf {c['performance_10']}/10")
        d = score["details"]
        atk = d["attacker"]
        print(f"   recall {d['recall']}  ctx-precision {d['ctx_precision']}  probes {d['pres_probes']}  direct-ids-leaked {d['leaked_direct_ids']}  "
              f"A3 {atk['a3_norm']} A4 {atk['a4_norm']} A5 {atk['a5_norm']} A7 {atk['a7_cross_release']}")
    else:
        print(f" LOCAL SCORE  error: {score.get('error')}")
    if m:
        print(f" check_dev: leaked {m.group(1)}/{m.group(2)}   canaries {can.group(1)}/{can.group(2)}   medical kept {med.group(1)}/{med.group(2)}"
              + (f"   linking P {link.group(1)} R {link.group(2)} F0.5 {link.group(3)} false-merges {link.group(4)}" if link else ""))
    for line in check_dev_txt.splitlines():
        if "leaked" in line and "/" in line and line.startswith("   ") and not line.strip().startswith("by"):
            parts = line.split()
            if parts[2] != "0":
                print("   ", line.strip())
        if line.strip().startswith(("by language", "by hiding")):
            print("   ", line.strip())
    print(f" strict token leak rate {extra['strict_token_leak_rate']}  by script {extra['strict_token_leak_by_script']}")
    print(f" critical identifiers surviving (decoded, any channel): {extra['critical_identifiers_left']}   canaries incl. stdout/stderr/TMP: {len(extra['canary_hits_incl_side_channels'])}")
    print(f" LOS preserved {extra['los_preserved']}   age bands {extra['age_bands']}   clean files intact {extra['clean_files_intact']}")
    print(f" determinism: {extra['determinism']}   secret rotation (same PSN under new secret): {extra['secret_rotation_same_psn']}")
    print(f" input unchanged: {input_unchanged}   TMP/HOME files left: {extra['tmp_home_files_left']}")
    print(f" linkage traps: {json.dumps(extra['linkage_traps'], ensure_ascii=False)}")
    weak = {k: v for k, v in extra["preserve_by_trap"].items() if v.split("/")[0] != v.split("/")[1]}
    print(f" medical probes lost by kind: {weak if weak else 'none'}")
    if not a.quiet:
        if extra["critical_examples"]:
            print(" critical survivors:", "; ".join(extra["critical_examples"][:12]))
        if extra["token_leak_examples"]:
            print(" token leaks (first):", "; ".join(extra["token_leak_examples"][:12]))
        if extra["age_band_errors"]:
            print(" age band errors:", "; ".join(extra["age_band_errors"]))
    print(f" scorecard -> {runs_dir / 'scorecard.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
