#!/usr/bin/env python3
"""Local scorer implementing docs/SCORING.md & scoring.toml against truth.json."""
from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import itertools
import json
import math
import os
import re
import tomllib
import unicodedata
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from tools.local_attacker import run_attack

_DIGIT_MAP = str.maketrans("०१२३४५६७८९", "0123456789")
_B64_RE = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")
_PSN_RE = re.compile(r"\bPSN-[0-9A-HJ-NP-TV-Z]{6,10}\b")


def _norm(s: str) -> str:
    s = unicodedata.normalize("NFKC", s).translate(_DIGIT_MAP)
    s = "".join(c for c in unicodedata.normalize("NFKD", s) if not unicodedata.combining(c))
    return " ".join(s.casefold().split())


def _decode_b64_runs(text: str) -> str:
    extra = []
    for m in _B64_RE.finditer(text):
        tok = m.group(0)
        try:
            extra.append(base64.b64decode(tok + "=" * (-len(tok) % 4)).decode("utf-8", errors="ignore"))
        except Exception:
            pass
    return text + "\n" + "\n".join(extra) if extra else text


def _read_norm_tree(root: Path) -> dict[str, str]:
    files_txt: dict[str, str] = {}
    if not root.is_dir():
        return files_txt
    for p in sorted(root.rglob("*")):
        if p.is_file():
            rel = p.relative_to(root).as_posix()
            raw = p.read_bytes().decode("utf-8", errors="replace")
            files_txt[rel] = _norm(_decode_b64_runs(raw))
    return files_txt


def _record_for(loc: str, recs: dict[str, Any]) -> Any:
    if loc in recs:
        return recs[loc]
    if loc.startswith("/"):
        parts = loc.split("/")
        for i in range(len(parts) - 1, 1, -1):
            anc = "/".join(parts[:i])
            if anc in recs:
                return recs[anc]
    return recs.get("doc")


def score_release(
    output_dir: Path,
    kit_dir: Path,
    truth_path: Path | None = None,
    other_output_dir: Path | None = None,
    input_dir: Path | None = None,
) -> dict[str, Any]:
    cfg = tomllib.loads((kit_dir / "scoring.toml").read_text(encoding="utf-8"))
    t_path = truth_path or (kit_dir / "dev" / "truth" / "truth.json")
    truth = json.loads(t_path.read_text(encoding="utf-8"))
    inp_dir = input_dir or t_path.resolve().parents[1] / "input"
    san_dir = output_dir / "sanitized"

    report = json.loads((output_dir / "report.json").read_text(encoding="utf-8")) if (output_dir / "report.json").is_file() else {"files": [], "counts": {}}
    renamed = {str(e.get("input_sha256", "")).lower(): e.get("output") for e in report.get("files", [])}
    status_by_sha = {str(e.get("input_sha256", "")).lower(): e.get("status") for e in report.get("files", [])}

    recs_by_file: dict[str, dict[str, Any]] = defaultdict(dict)
    recs_raw: list[dict[str, Any]] = []
    if (output_dir / "records.jsonl").is_file():
        for line in (output_dir / "records.jsonl").read_text(encoding="utf-8").splitlines():
            if line.strip():
                r = json.loads(line)
                recs_raw.append(r)
                recs_by_file[str(r["file"]).replace("sanitized/", "", 1)][r["loc"]] = r.get("patient")

    san_texts = _read_norm_tree(san_dir)
    all_output_text = "\n".join(list(san_texts.keys()) + list(san_texts.values()))
    if (output_dir / "report.json").is_file():
        all_output_text += "\n" + _norm((output_dir / "report.json").read_text(encoding="utf-8"))
    if (output_dir / "records.jsonl").is_file():
        all_output_text += "\n" + _norm((output_dir / "records.jsonl").read_text(encoding="utf-8"))

    # 1. Detection & contextual intelligence
    type_weights = cfg["detection"]["type_weights"]
    type_hits, type_tot = Counter(), Counter()
    script_hits, script_tot = Counter(), Counter()
    trap_ok, trap_tot = Counter(), Counter()
    pres_ok = pres_all = 0
    raw_copies = 0
    leaked_direct_ids: set[str] = set()
    canary_surfaces: set[str] = set()
    unit_patient: dict[tuple[str, str], tuple[str, Any]] = {}
    patient_direct_leak: set[str] = set()
    clean_tok_ok = clean_tok_tot = 0

    for rel, finfo in truth["files"].items():
        src = inp_dir / rel
        disk_sha = hashlib.sha256(src.read_bytes()).hexdigest().lower() if src.is_file() else ""
        sha = finfo["sha256"].lower()
        decl = renamed.get(disk_sha) or renamed.get(sha)
        out_rel = str(decl).replace("sanitized/", "", 1) if decl else rel
        p = san_dir / out_rel
        exists = p.is_file()
        out_norm = san_texts.get(out_rel, "")
        fname_norm = _norm(out_rel)

        has_pii = any(u["entities"] for u in finfo["units"].values())
        if has_pii and exists and finfo.get("expect") == "either" and src.is_file() and p.read_bytes() == src.read_bytes():
            raw_copies += 1

        if finfo.get("clean") and src.is_file():
            src_toks = Counter(_norm(src.read_text(encoding="utf-8", errors="ignore")).split())
            out_toks = Counter(out_norm.split())
            for tok, cnt in src_toks.items():
                clean_tok_tot += cnt
                clean_tok_ok += min(cnt, out_toks.get(tok, 0))

        for loc, u in finfo["units"].items():
            if u.get("link") == "required" and u.get("patient"):
                unit_patient[(rel, loc)] = (u["patient"], _record_for(loc, recs_by_file.get(out_rel, {})))
            for pv in u.get("preserve") or []:
                pres_all += 1
                hit = _norm(pv["text"]) in out_norm
                pres_ok += int(hit)
                k = pv.get("kind", "other")
                if k in ("doctor", "eponym", "context", "ward", "frequency", "dose", "complaint", "history"):
                    trap_tot[k] += 1
                    trap_ok[k] += int(hit)
            for e in u["entities"]:
                etype = e["type"]
                surf = _norm(e["surface"])
                if etype == "CANARY":
                    canary_surfaces.add(surf)
                    continue
                hay = fname_norm if e["channel"] == "filename" else out_norm
                allowed = sum(1 for pv in (u.get("preserve") or []) if surf and surf in _norm(pv["text"]))
                leaked = bool(surf) and (hay.count(surf) > allowed) if (exists or e["channel"] == "filename") else False
                type_tot[etype] += 1
                script_tot[e["script"]] += 1
                if not leaked:
                    type_hits[etype] += 1
                    script_hits[e["script"]] += 1
                elif etype in ("AADHAAR", "ABHA_NUMBER", "ABHA_ADDRESS", "PHONE", "EMAIL", "MRN", "PAN", "PATIENT_NAME"):
                    leaked_direct_ids.add(f"{etype}:{surf}")
                    if u.get("patient"):
                        patient_direct_leak.add(u["patient"])

    weighted_type_num = sum(type_weights.get(t, 0.5) * (type_hits[t] / type_tot[t]) for t in type_tot)
    weighted_type_den = sum(type_weights.get(t, 0.5) for t in type_tot) or 1.0
    macro_type_recall = weighted_type_num / weighted_type_den
    macro_script_recall = sum((script_hits[s] / script_tot[s]) for s in script_tot) / max(1, len(script_tot))
    recall = 0.5 * macro_type_recall + 0.5 * macro_script_recall

    trap_precs = [(trap_ok[k] / trap_tot[k]) for k in trap_tot]
    if clean_tok_tot:
        trap_precs.append(clean_tok_ok / clean_tok_tot)
    ctx_prec = sum(trap_precs) / len(trap_precs) if trap_precs else 1.0
    beta = cfg["detection"]["beta"]
    det_score = ((1 + beta**2) * ctx_prec * recall / (beta**2 * ctx_prec + recall)) if (ctx_prec + recall) else 0.0

    # 2. Identity resolution
    units = list(unit_patient.values())
    tp = fp = 0
    by_true, yours = defaultdict(list), defaultdict(list)
    for i, (t, y) in enumerate(units):
        by_true[t].append(i)
        if y:
            yours[y].append(i)
    true_pairs = sum(len(v) * (len(v) - 1) // 2 for v in by_true.values())
    for members in yours.values():
        for i, j in itertools.combinations(members, 2):
            if units[i][0] == units[j][0]:
                tp += 1
            else:
                fp += 1
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / true_pairs if true_pairs else 0.0
    f05 = (1.25 * prec * rec / (0.25 * prec + rec)) if (prec + rec) else 0.0

    # B-cubed F1
    b3_p_list, b3_r_list = [], []
    for i, (t, y) in enumerate(units):
        if y:
            same_y = yours[y]
            b3_p_list.append(sum(1 for j in same_y if units[j][0] == t) / len(same_y))
            b3_r_list.append(sum(1 for j in same_y if units[j][0] == t) / len(by_true[t]))
        else:
            b3_p_list.append(1.0)
            b3_r_list.append(1.0 / len(by_true[t]))
    b3_p = sum(b3_p_list) / len(b3_p_list) if b3_p_list else 0.0
    b3_r = sum(b3_r_list) / len(b3_r_list) if b3_r_list else 0.0
    b3_f1 = (2 * b3_p * b3_r / (b3_p + b3_r)) if (b3_p + b3_r) else 0.0

    def _trap_pair_recall(pids: list[str]) -> float:
        ok_p = tot_p = 0
        for p in pids:
            idxs = by_true.get(p, [])
            for i, j in itertools.combinations(idxs, 2):
                tot_p += 1
                if units[i][1] and units[i][1] == units[j][1]:
                    ok_p += 1
        return ok_p / tot_p if tot_p else 1.0

    traps = truth.get("traps", {})
    lang_trap = _trap_pair_recall(traps.get("language", []))
    frag_trap = _trap_pair_recall(traps.get("fragmented", []))
    hom_pairs = traps.get("homonym_pairs", [])
    hom_sep = 0.0
    if hom_pairs:
        sep = 0
        for p1, p2 in hom_pairs:
            psns1 = {units[i][1] for i in by_true.get(p1, []) if units[i][1]}
            psns2 = {units[i][1] for i in by_true.get(p2, []) if units[i][1]}
            if not (psns1 & psns2):
                sep += 1
        hom_sep = sep / len(hom_pairs)
    id_score = (0.4 * f05 + 0.3 * b3_f1 + 0.1 * lang_trap + 0.1 * frag_trap + 0.1 * hom_sep) if yours else 0.0

    # 3. Utility (clinical probes + retention proxy)
    probe_score = (pres_ok / pres_all) if pres_all else 1.0
    tok_ret = (clean_tok_ok / clean_tok_tot) if clean_tok_tot else 1.0
    rec_ret = sum(1 for rel, finfo in truth["files"].items() if finfo.get("expect") == "sanitize" and (san_dir / (str(renamed.get(finfo["sha256"].lower()) or rel).replace("sanitized/", "", 1))).is_file()) / max(1, sum(1 for f in truth["files"].values() if f.get("expect") == "sanitize"))
    utility_score = 0.55 * probe_score + 0.20 * rec_ret + 0.25 * tok_ret

    # 4. Integrity
    expected_sanitize = [f for f in truth["files"].values() if f.get("expect") == "sanitize"]
    honest_total = report.get("counts", {}).get("files_total") == len(truth["files"])
    valid_fmt = 0
    for rel, finfo in truth["files"].items():
        src = inp_dir / rel
        disk_sha = hashlib.sha256(src.read_bytes()).hexdigest().lower() if src.is_file() else ""
        decl = renamed.get(disk_sha) or renamed.get(finfo["sha256"].lower())
        out_rel = str(decl).replace("sanitized/", "", 1) if decl else rel
        p = san_dir / out_rel
        if not p.is_file():
            if finfo.get("expect") == "either":
                valid_fmt += 1
            continue
        try:
            raw_txt = p.read_text(encoding="utf-8")
            if finfo["format"] in ("json", "fhir"):
                json.loads(raw_txt)
            valid_fmt += 1
        except Exception:
            pass
    fmt_ratio = valid_fmt / max(1, len(truth["files"]))
    psn_consistent = 0
    psn_claims = [r for r in recs_raw if r.get("patient")]
    for r in psn_claims:
        rel_f = str(r["file"]).replace("sanitized/", "", 1)
        if r["patient"].casefold() in san_texts.get(rel_f, ""):
            psn_consistent += 1
    psn_ratio = (psn_consistent / len(psn_claims)) if psn_claims else 0.0
    integrity_score = 0.35 * fmt_ratio + 0.25 * (1.0 if honest_total else 0.5) + 0.20 * psn_ratio + 0.20 * (1.0 if raw_copies == 0 else 0.0)

    # 5. Privacy via local_attacker
    atk = run_attack(
        output_dir,
        t_path,
        kit_dir / "dev" / "attacker" / "registry.csv",
        kit_dir / "dev" / "attacker" / "known_facts.jsonl",
        kit_dir / "dev" / "truth" / "raw_attack.json",
        other_output_dir,
    )
    a1 = len(patient_direct_leak) / max(1, len(truth["patients"]))
    pw = cfg["privacy"]["weights"]
    risk = (
        pw["direct_exposure"] * a1
        + pw["record_linkage"] * atk["a3_norm"]
        + pw["profile_reidentification"] * atk["a4_norm"]
        + pw["targeted_attack"] * atk["a5_norm"]
        + pw["cross_release"] * atk["a7_cross_release"]
    ) / (pw["direct_exposure"] + pw["record_linkage"] + pw["profile_reidentification"] + pw["targeted_attack"] + pw["cross_release"])
    privacy_score = (1.0 - risk) * min(1.0, utility_score / cfg["privacy"]["utility_coupling_threshold"])

    # 6. Performance
    secs = float((report.get("timing") or {}).get("seconds") or 0.0)
    rss = float((report.get("resources") or {}).get("peak_rss_mb") or 0.0)
    perf_score = 0.5 + 0.25 * (1.0 if secs <= 15 else max(0.0, 1.0 - (secs - 15) / 285)) + 0.25 * (1.0 if rss <= 512 else max(0.0, 1.0 - (rss - 512) / 3584))

    canary_hits = sum(1 for c in canary_surfaces if c and c in all_output_text)
    pen = cfg["penalties"]
    total_pen = (
        min(pen["leaked_identifier_cap"], len(leaked_direct_ids) * pen["per_leaked_identifier"])
        + min(pen["canary_cap"], canary_hits * pen["per_canary_leak"])
        + min(pen["unprocessed_cap"], raw_copies * pen["per_unprocessed_export"])
    )

    w = cfg["weights"]
    raw_total = 100.0 * (
        w["detection"] * det_score
        + w["identity_resolution"] * id_score
        + w["privacy"] * privacy_score
        + w["utility"] * utility_score
        + w["integrity"] * integrity_score
        + w["performance"] * perf_score
    )
    return {
        "total_score": round(raw_total - total_pen, 2),
        "raw_total_before_penalties": round(raw_total, 2),
        "penalties": round(total_pen, 2),
        "categories": {
            "privacy_25": round(25 * privacy_score, 2),
            "detection_20": round(20 * det_score, 2),
            "utility_20": round(20 * utility_score, 2),
            "identity_15": round(15 * id_score, 2),
            "integrity_10": round(10 * integrity_score, 2),
            "performance_10": round(10 * perf_score, 2),
        },
        "details": {
            "recall": round(recall, 4),
            "ctx_precision": round(ctx_prec, 4),
            "pres_probes": f"{pres_ok}/{pres_all}",
            "leaked_direct_ids": len(leaked_direct_ids),
            "canary_hits": canary_hits,
            "raw_copies": raw_copies,
            "linking_f05": round(f05, 4),
            "linking_b3": round(b3_f1, 4),
            "homonym_sep": round(hom_sep, 4),
            "attacker": atk,
        },
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Local Secret Wards scorer")
    ap.add_argument("--output", required=True)
    ap.add_argument("--kit", default="Secret-Wards-ToolKit")
    ap.add_argument("--truth", default="")
    ap.add_argument("--input", default="")
    ap.add_argument("--other-output", default="")
    args = ap.parse_args()
    res = score_release(
        Path(args.output),
        Path(args.kit),
        Path(args.truth) if args.truth else None,
        Path(args.other_output) if args.other_output else None,
        Path(args.input) if args.input else None,
    )
    print(json.dumps(res, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
