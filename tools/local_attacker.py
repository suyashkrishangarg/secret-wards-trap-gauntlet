#!/usr/bin/env python3
"""Local adversarial attack simulator implementing docs/ATTACKS.md (A1-A7)."""
from __future__ import annotations

import argparse
import base64
import csv
import datetime as dt
import hashlib
import json
import re
import unicodedata
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from indic_transliteration import sanscript
from indic_transliteration.sanscript import transliterate

_DEVA = re.compile(r"[\u0900-\u097f]")
_VIRAMA = "\u094d"
_MATRAS = set(chr(c) for c in range(0x093E, 0x094D)) | {"\u0962", "\u0963"}
_DIGIT_MAP = str.maketrans("०१२३४५६७८९", "0123456789")
_PSN_RE = re.compile(r"\bPSN-[0-9A-HJ-NP-TV-Z]{6,10}\b")
_PHONE_RE = re.compile(r"(?<!\d)(?:\+?91[\s-]?)?([6-9]\d{4}[\s-]?\d{5})(?!\d)")
_MASKED_PHONE_RE = re.compile(r"\b([6-9]\d)[X*]{4,6}(\d{2,4})\b", re.I)
_MASKED_AADHAAR_RE = re.compile(r"(?i)\b[X*]{4}[\s-]?[X*]{4}[\s-]?(\d{4})\b")
_EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.]+")
_PIN6_RE = re.compile(r"\b([1-8]\d{5})\b")
_PIN3_RE = re.compile(r"\b([1-8]\d{2})[*X]{3}\b", re.I)
_AGE_BAND_RE = re.compile(r"(?i)(?:age[:\s]*|आयु[:\s]*)?(\d{1,3})\s*-\s*(\d{1,3})\s*(?:yrs?|years?|वर्ष|/|\b)")
_AGE_TOP_RE = re.compile(r"(?i)(?:age[:\s]*|आयु[:\s]*)?(\d{2,3})\+\s*(?:yrs?|years?|वर्ष|/|\b)")
_AGE_EXACT_RE = re.compile(r"(?i)(?:age[:\s]*|आयु[:\s]*)(\d{1,3})\b|\b(\d{1,3})\s*(?:yrs?|years?|वर्ष)\b|\b(\d{1,3})\s*/\s*[MF]\b")
_DATE_ISO_RE = re.compile(r"\b((?:19|20)\d{2})-(\d{2})-(\d{2})\b")
_DATE_DMY_RE = re.compile(r"\b(\d{2})[/-](\d{2})[/-]((?:19|20)\d{2})\b")
_DR_SKIP_RE = re.compile(r"(?i)\b(?:dr\.?|doctor|डॉ\.?)\s+[A-Z\u0900-\u097f][a-zA-Z\u0900-\u097f.]+(?:\s+[A-Z\u0900-\u097f][a-zA-Z\u0900-\u097f.]+){0,2}")


def _norm(s: str) -> str:
    s = unicodedata.normalize("NFKC", s).translate(_DIGIT_MAP)
    return " ".join(s.casefold().split())


def _roman_token(tok: str) -> str:
    if _DEVA.search(tok):
        bare = tok[-1] not in _MATRAS and tok[-1] != _VIRAMA and "\u0915" <= tok[-1] <= "\u0939"
        s = transliterate(tok, sanscript.DEVANAGARI, sanscript.ITRANS)
        for m in ("M", "~N", ".N", "~n", ".n"):
            s = s.replace(m, "n")
        s = s.lower()
        if bare and s.endswith("a"):
            s = s[:-1]
        tok = s
    tok = re.sub(r"[^a-z0-9]", "", tok.lower())
    aliases = {"md": "mohammad", "mohd": "mohammad", "mohammed": "mohammad", "muhammad": "mohammad"}
    return aliases.get(tok, tok)


def _name_set(s: str) -> set[str]:
    return {_roman_token(t) for t in re.split(r"[\s_,./-]+", s) if len(_roman_token(t)) >= 2}


def _parse_dates(text: str, dmy: bool = True) -> list[dt.date]:
    out: list[dt.date] = []
    for y, m, d in _DATE_ISO_RE.findall(text):
        try:
            out.append(dt.date(int(y), int(m), int(d)))
        except ValueError:
            pass
    for a, b, y in _DATE_DMY_RE.findall(text):
        day, mon = (int(a), int(b)) if dmy else (int(b), int(a))
        try:
            out.append(dt.date(int(y), mon, day))
        except ValueError:
            pass
    return out


def _extract_record_evidence(text: str, rel_file: str, ref_year: int = 2026) -> dict[str, Any]:
    normed = _norm(text)
    cleaned_no_dr = _DR_SKIP_RE.sub(" ", text)
    ev: dict[str, Any] = {
        "phones": set(),
        "emails": set(_EMAIL_RE.findall(normed)),
        "aadhaar_last4": set(_MASKED_AADHAAR_RE.findall(text)),
        "masked_phones": set(_MASKED_PHONE_RE.findall(text)),
        "pins": set(_PIN6_RE.findall(normed)),
        "pin3s": set(_PIN3_RE.findall(text)),
        "ages": [],
        "age_bands": [],
        "birth_years": set(),
        "genders": set(),
        "tokens": _name_set(cleaned_no_dr),
        "dates": _parse_dates(normed, dmy="arogya" not in rel_file.lower()),
        "psns": set(_PSN_RE.findall(text)),
        "hospitals": set(),
        "raw_text": normed,
    }
    for m in _PHONE_RE.findall(normed):
        digits = re.sub(r"\D", "", m)[-10:]
        if len(digits) == 10:
            ev["phones"].add(digits)
    for lo, hi in _AGE_BAND_RE.findall(normed):
        a, b = int(lo), int(hi)
        if 0 <= a <= b <= 120:
            ev["age_bands"].append((a, b))
    for top in _AGE_TOP_RE.findall(normed):
        t = int(top)
        if 60 <= t <= 110:
            ev["age_bands"].append((t, 120))
    for g1, g2, g3 in _AGE_EXACT_RE.findall(normed):
        g = g1 or g2 or g3
        if g and 0 <= int(g) <= 115:
            val = int(g)
            # Exclude if part of an age band already matched
            if not any(lo <= val <= hi for lo, hi in ev["age_bands"]):
                ev["ages"].append(val)
    if re.search(r"(?i)\b(?:female|महिला)\b|/\s*f\b|\bw/o\b|\bd/o\b|\bdidi\b|\bbehenji\b", normed):
        ev["genders"].add("F")
    if re.search(r"(?i)\b(?:male|पुरुष)\b|/\s*m\b|\bs/o\b|\bsahab\b|\bbhaiya\b", normed):
        ev["genders"].add("M")
    for hosp in ("sanjeevani", "jeevan jyoti", "arogya", "hardoi"):
        if hosp in normed or hosp.replace(" ", "") in rel_file.lower():
            ev["hospitals"].add(hosp)
    for d in ev["dates"]:
        if 1915 <= d.year <= 2025:
            ev["birth_years"].add(d.year)
    return ev


def _load_registry(path: Path) -> list[dict[str, Any]]:
    rows = []
    with open(path, encoding="utf-8") as fh:
        for r in csv.DictReader(fh):
            rows.append(
                {
                    "rid": r["rid"],
                    "name": r["name"],
                    "name_toks": _name_set(r["name"]),
                    "given": _roman_token(r["name"].split()[0]) if r["name"].split() else "",
                    "surname": _roman_token(r["name"].split()[-1]) if len(r["name"].split()) > 1 else "",
                    "rel_toks": _name_set(r.get("relative_name", "")),
                    "gender": r["gender"].strip().upper(),
                    "age": int(r["age"]) if r["age"].isdigit() else None,
                    "house": r.get("house_no", "").strip(),
                    "village": _roman_token(r.get("village", "")),
                    "tehsil": _roman_token(r.get("tehsil", "")),
                    "district": _roman_token(r.get("district", "")),
                    "pin": r.get("pin", "").strip(),
                    "pin3": r.get("pin", "").strip()[:3],
                    "phone": re.sub(r"\D", "", r.get("phone", ""))[-10:],
                    "email": r.get("email", "").strip().lower(),
                    "aadhaar_last4": r.get("aadhaar_last4", "").strip(),
                }
            )
    return rows


def _score_candidates(ev: dict[str, Any], registry: list[dict[str, Any]], reg_districts: set[str], reg_tehsils: set[str], reg_villages: set[str]) -> dict[str, float]:
    cands = list(registry)

    def _flt(pred):
        nonlocal cands
        nxt = [c for c in cands if pred(c)]
        if nxt:
            cands = nxt

    if ev["phones"]:
        _flt(lambda c: c["phone"] in ev["phones"])
    if ev["emails"]:
        _flt(lambda c: c["email"] in ev["emails"])
    if ev["aadhaar_last4"]:
        _flt(lambda c: c["aadhaar_last4"] in ev["aadhaar_last4"])
    if ev["masked_phones"]:
        _flt(lambda c: any(c["phone"].startswith(p0) and c["phone"].endswith(p1) for p0, p1 in ev["masked_phones"]))

    hits_dist = ev["tokens"] & reg_districts
    if hits_dist:
        _flt(lambda c: c["district"] in hits_dist)
    if len(ev["genders"]) == 1:
        g = next(iter(ev["genders"]))
        _flt(lambda c: c["gender"] == g)
    if ev["age_bands"]:
        lo = min(a for a, _ in ev["age_bands"])
        hi = max(b for _, b in ev["age_bands"])
        _flt(lambda c: c["age"] is not None and (lo - 2) <= c["age"] <= (hi + 2))
    elif ev["ages"]:
        lo, hi = min(ev["ages"]), max(ev["ages"])
        _flt(lambda c: c["age"] is not None and (lo - 2) <= c["age"] <= (hi + 2))

    hits_teh = ev["tokens"] & reg_tehsils
    if hits_teh:
        _flt(lambda c: c["tehsil"] in hits_teh)
    hits_vil = ev["tokens"] & reg_villages
    if hits_vil:
        _flt(lambda c: c["village"] in hits_vil)
    if ev["pins"]:
        _flt(lambda c: c["pin"] in ev["pins"])
    elif ev["pin3s"]:
        _flt(lambda c: c["pin3"] in ev["pin3s"])

    weights: dict[str, float] = {}
    for c in cands:
        w = 1.0
        if c["name_toks"] and c["name_toks"].issubset(ev["tokens"]):
            w += 60.0
        elif c["given"] and c["given"] in ev["tokens"]:
            w += 8.0
        if c["surname"] and c["surname"] in ev["tokens"]:
            w += 3.0
        if c["rel_toks"] and (c["rel_toks"] & ev["tokens"]):
            w += 8.0
        if c["house"] and re.search(rf"\b{re.escape(c['house'])}\b", ev["raw_text"]):
            w += 2.0
        weights[c["rid"]] = w
    tot = sum(weights.values()) or 1.0
    return {rid: w / tot for rid, w in weights.items()}


def run_attack(
    output_dir: Path,
    truth_path: Path,
    registry_path: Path,
    known_facts_path: Path,
    raw_attack_path: Path,
    other_output_dir: Path | None = None,
) -> dict[str, Any]:
    truth = json.loads(truth_path.read_text(encoding="utf-8"))
    raw_ref = json.loads(raw_attack_path.read_text(encoding="utf-8")).get("result", {})
    registry = _load_registry(registry_path)
    reg_districts = {r["district"] for r in registry if r["district"]}
    reg_tehsils = {r["tehsil"] for r in registry if r["tehsil"]}
    reg_villages = {r["village"] for r in registry if r["village"]}
    pid_to_rid = {pt_key: p["rid"] for pt_key, p in truth["patients"].items()}

    facts = [json.loads(line) for line in known_facts_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    san_dir = output_dir / "sanitized"
    inp_dir = truth_path.resolve().parents[1] / "input"
    report = json.loads((output_dir / "report.json").read_text(encoding="utf-8")) if (output_dir / "report.json").is_file() else {"files": []}
    renamed = {str(e.get("input_sha256", "")).lower(): str(e.get("output") or "").replace("sanitized/", "", 1) for e in report.get("files", [])}

    # Build per-record evidence from sanitized output
    unit_records: list[tuple[str, str, dict[str, Any]]] = []
    profile_pools: dict[str, list[dict[str, Any]]] = defaultdict(list)
    _REF_RE = re.compile(r"\b(?:SNJ/\d+/\d+|JJH-\d+|UHID-\d+|DHH\d+-\d+|ADM\d+|IPD-\d+-\d+|IP/\d+/\d+)\b")

    for rel, finfo in truth["files"].items():
        if finfo.get("clean"):
            continue
        src_p = inp_dir / rel
        disk_sha = hashlib.sha256(src_p.read_bytes()).hexdigest().lower() if src_p.is_file() else finfo["sha256"].lower()
        out_rel = renamed.get(disk_sha) or renamed.get(finfo["sha256"].lower()) or rel
        p = san_dir / out_rel
        if not p.is_file():
            continue
        txt = p.read_text(encoding="utf-8", errors="ignore")
        if finfo["format"] in ("csv", "tsv"):
            delim = finfo.get("delimiter") or ("," if finfo["format"] == "csv" else "\t")
            rows = list(csv.reader(txt.splitlines(), delimiter=delim))
            header = rows[0] if rows else []
            for idx, r in enumerate(rows[1:]):
                loc = f"row:{idx}"
                u = finfo["units"].get(loc)
                if not u or not u.get("patient"):
                    continue
                row_text = " ".join(f"{h}: {v}" for h, v in zip(header, r))
                ev = _extract_record_evidence(row_text, out_rel)
                unit_records.append((u["patient"], loc, ev))
                keys = ev["psns"] or set(_REF_RE.findall(row_text)) or {f"REC:{out_rel}:{loc}"}
                for pk in keys:
                    profile_pools[pk].append(ev)
        elif finfo["format"] == "json" and any(k.startswith("/") for k in finfo["units"]):
            try:
                data = json.loads(txt)
            except ValueError:
                data = {}
            for loc, u in finfo["units"].items():
                if not loc.startswith("/") or not u.get("patient"):
                    continue
                node = data
                for part in [x for x in loc.split("/") if x]:
                    if isinstance(node, list) and part.isdigit() and int(part) < len(node):
                        node = node[int(part)]
                    elif isinstance(node, dict) and part in node:
                        node = node[part]
                dump = json.dumps(node, ensure_ascii=False)
                ev = _extract_record_evidence(dump, out_rel)
                unit_records.append((u["patient"], loc, ev))
                keys = ev["psns"] or set(_REF_RE.findall(dump)) or {f"REC:{out_rel}:{loc}"}
                for pk in keys:
                    profile_pools[pk].append(ev)
        else:
            u = finfo["units"].get("doc")
            if not u or not u.get("patient"):
                continue
            ev = _extract_record_evidence(txt, out_rel)
            unit_records.append((u["patient"], "doc", ev))
            keys = ev["psns"] or set(_REF_RE.findall(txt)) or {f"REC:{out_rel}:doc"}
            for pk in keys:
                profile_pools[pk].append(ev)

    # A2/A3 record-level risk
    rec_probs = []
    patient_max_conf: dict[str, float] = defaultdict(float)
    for pid, _loc, ev in unit_records:
        true_rid = pid_to_rid.get(pid)
        probs = _score_candidates(ev, registry, reg_districts, reg_tehsils, reg_villages)
        p_true = probs.get(true_rid, 0.0) if true_rid else 0.0
        rec_probs.append(p_true)
        patient_max_conf[pid] = max(patient_max_conf[pid], p_true)

    # A4 profile-level aggregation
    pooled_evs: dict[str, dict[str, Any]] = {}
    for psn, evs in profile_pools.items():
        merged = {
            "phones": set().union(*(e["phones"] for e in evs)),
            "emails": set().union(*(e["emails"] for e in evs)),
            "aadhaar_last4": set().union(*(e["aadhaar_last4"] for e in evs)),
            "masked_phones": set().union(*(e["masked_phones"] for e in evs)),
            "pins": set().union(*(e["pins"] for e in evs)),
            "pin3s": set().union(*(e["pin3s"] for e in evs)),
            "ages": [a for e in evs for a in e["ages"]],
            "age_bands": [b for e in evs for b in e["age_bands"]],
            "birth_years": set().union(*(e["birth_years"] for e in evs)),
            "genders": set().union(*(e["genders"] for e in evs)),
            "tokens": set().union(*(e["tokens"] for e in evs)),
            "dates": sorted(set().union(*(e["dates"] for e in evs))),
            "psns": {psn},
            "hospitals": set().union(*(e["hospitals"] for e in evs)),
            "raw_text": " ".join(e["raw_text"] for e in evs),
        }
        pooled_evs[psn] = merged

    psn_probs = {psn: _score_candidates(ev, registry, reg_districts, reg_tehsils, reg_villages) for psn, ev in pooled_evs.items()}
    for pid, _loc, ev in unit_records:
        true_rid = pid_to_rid.get(pid)
        for psn in ev["psns"]:
            patient_max_conf[pid] = max(patient_max_conf[pid], psn_probs.get(psn, {}).get(true_rid, 0.0))

    n_patients = len(truth["patients"])
    a3_raw = sum(rec_probs) / len(rec_probs) if rec_probs else 0.0
    a4_raw = sum(1 for p in truth["patients"] if patient_max_conf.get(p, 0.0) >= 0.5) / max(1, n_patients)

    # A5 targeted known-facts attack (with global shift check)
    fact_by_rid = {f["rid"]: f for f in facts}
    shift_votes = Counter()
    for psn, probs in psn_probs.items():
        if not probs:
            continue
        top_rid, top_p = max(probs.items(), key=lambda kv: kv[1])
        if top_p >= 0.9 and top_rid in fact_by_rid and pooled_evs[psn]["dates"]:
            for kd_str in fact_by_rid[top_rid].get("visit_dates", []):
                kd = dt.date.fromisoformat(kd_str)
                for pd in pooled_evs[psn]["dates"]:
                    shift_votes[(pd - kd).days] += 1
    global_shift = 0
    if shift_votes:
        best_shift, cnt = shift_votes.most_common(1)[0]
        if cnt >= 2:
            global_shift = best_shift

    # Rare conditions across profiles
    cond_counts = Counter()
    for f in facts:
        ch = (f.get("condition_hint") or "").casefold()
        if ch:
            for psn, ev in pooled_evs.items():
                if ch[:12] in ev["raw_text"]:
                    cond_counts[ch] += 1

    targeted_scores = []
    for f in facts:
        rid = f["rid"]
        if rid not in set(pid_to_rid.values()):
            continue  # decoy
        k_dates = [dt.date.fromisoformat(d) for d in f.get("visit_dates", [])]
        k_stay = f.get("stay_days")
        k_cond = (f.get("condition_hint") or "").casefold()
        k_hosp = (f.get("hospital") or "").casefold()
        prof_scores: dict[str, float] = {}
        for psn, ev in pooled_evs.items():
            base = psn_probs[psn].get(rid, 0.0)
            if base == 0.0:
                continue
            sig = 0.0
            for kd in k_dates:
                shifted_kd = kd + dt.timedelta(days=global_shift)
                if shifted_kd in ev["dates"]:
                    sig += 4.0
            if k_cond and k_cond[:12] in ev["raw_text"]:
                sig += 8.0 if cond_counts[k_cond] <= 3 else 2.0
            if k_stay is not None and len(ev["dates"]) >= 2:
                if any((d2 - d1).days == k_stay for d1 in ev["dates"] for d2 in ev["dates"] if d2 > d1):
                    sig += 4.0
            if sig > 0:
                if any(h in k_hosp for h in ev["hospitals"]):
                    sig *= 2.0
                prof_scores[psn] = base * (1.0 + sig)
        if prof_scores:
            best_psn = max(prof_scores, key=lambda k: prof_scores[k])
            best_prob = psn_probs[best_psn].get(rid, 0.0)
            targeted_scores.append(min(1.0, best_prob * 1.5))
        else:
            targeted_scores.append(0.0)

    a5_raw = sum(targeted_scores) / len(targeted_scores) if targeted_scores else 0.0

    # Normalize by raw baseline per docs/SCORING.md
    raw_a3 = float(raw_ref.get("record_linkage_risk") or 0.9218)
    raw_a4 = float(raw_ref.get("patients_reidentified") or 0.9792)
    raw_a5 = float(raw_ref.get("targeted_success") or 1.0)

    # A7 cross-release check if second output provided
    a7 = 0.0
    if other_output_dir and (other_output_dir / "records.jsonl").is_file() and (output_dir / "records.jsonl").is_file():
        r1 = {(r["file"], r["loc"]): r["patient"] for r in (json.loads(l) for l in (output_dir / "records.jsonl").read_text(encoding="utf-8").splitlines() if l.strip())}
        r2 = {(r["file"], r["loc"]): r["patient"] for r in (json.loads(l) for l in (other_output_dir / "records.jsonl").read_text(encoding="utf-8").splitlines() if l.strip())}
        shared = [k for k in r1 if k in r2 and r1[k] and r2[k]]
        if shared:
            a7 = sum(1 for k in shared if r1[k] == r2[k]) / len(shared)

    return {
        "a3_abs": round(a3_raw, 4),
        "a4_abs": round(a4_raw, 4),
        "a5_abs": round(a5_raw, 4),
        "a3_norm": round(min(1.0, a3_raw / raw_a3), 4),
        "a4_norm": round(min(1.0, a4_raw / raw_a4), 4),
        "a5_norm": round(min(1.0, a5_raw / raw_a5), 4),
        "a7_cross_release": round(a7, 4),
        "global_shift_recovered": global_shift,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Local Secret Wards attacker simulator")
    ap.add_argument("--output", required=True)
    ap.add_argument("--kit", default="Secret-Wards-ToolKit")
    ap.add_argument("--other-output", default="")
    args = ap.parse_args()
    kit = Path(args.kit)
    res = run_attack(
        Path(args.output),
        kit / "dev" / "truth" / "truth.json",
        kit / "dev" / "attacker" / "registry.csv",
        kit / "dev" / "attacker" / "known_facts.jsonl",
        kit / "dev" / "truth" / "raw_attack.json",
        Path(args.other_output) if args.other_output else None,
    )
    print(json.dumps(res, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
