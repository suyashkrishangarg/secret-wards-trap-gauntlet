# Trap Gauntlet: an adversarial test set and scorer for Secret Wards (Track 3)

A seeded generator of messy multi-hospital Indian health-record dumps that plants every trap named in the
Secret Wards problem statement, `docs/DATASET.md` and `docs/ATTACKS.md`, using formats the official practice
data never shows. Every set comes with an answer key in the official `raksha-truth/1` schema, so the
toolkit's own `check_dev.py` can grade it, plus a 100-point estimator and a voter-roll attacker.

All data is synthetic: names come from generic pools, and phone, Aadhaar, ABHA and hospital numbers are random.

## What is in the repo

```text
tools/gauntlet_gen.py    generator (stdlib only)
tools/eval_gauntlet.py   runs a submission 3x and writes a scorecard
tools/local_scorer.py    100-point estimate of docs/SCORING.md
tools/local_attacker.py  A1-A7 attacker from docs/ATTACKS.md (record linkage, pooled profile, targeted, ...)
sets/A7                  level 1, name/header pool A
sets/B11                 level 1, held-out pool B (different names and header labels)
sets/H7                  level 2 ("hard"): A7 plus about 30 hostile files and 15 hard-trap patients
sets/H11                 level 2 ("hard"): B11 plus the same hard traps in pool B
```

Level 1 contains the traps the problem statement names. Level 2 adds what a hostile export and a hostile
reviewer would add (see [Level 2 traps](#level-2-hard-traps)). `--level 1` reproduces A7 and B11 byte-for-byte.

Each set is laid out like the official kit: `dev/input/`, `dev/truth/truth.json`,
`dev/truth/raw_attack.json` (the attacker on the raw input, to normalise attack scores),
`dev/attacker/registry.csv` (a population register about 4x the patients, 60% with leaked contacts) and
`dev/attacker/known_facts.jsonl` (what the attacker knows about about 30% of patients plus every
re-identification trap patient, plus decoys).

## Quick start

Python 3.11+. Clone the official toolkit next to this repo (or pass `--kit`).

```bash
pip install -r requirements.txt
git clone https://github.com/Reinforce-SST/Secret-Wards-ToolKit ../Secret-Wards-ToolKit

# score your submission on a pre-generated set (runs it 3x: same secret twice + a different secret)
python tools/eval_gauntlet.py --set sets/B11 --repo /path/to/your-team-repo \
       --kit ../Secret-Wards-ToolKit --label try1

# make a fresh set (pool A = one vocabulary, pool B = a disjoint one; keep one pool unseen while tuning)
python tools/gauntlet_gen.py --out sets/B99 --seed 99 --pool B                 # level 2 (default)
python tools/gauntlet_gen.py --out sets/B99-l1 --seed 99 --pool B --level 1    # original traps only
python tools/gauntlet_gen.py --out sets/A21 --seed 21 --pool A --patients 60 --bulk 6000   # bigger
```

`--repo` must contain a `raksha.toml` (or `main.py` taking `--input/--output` and `RAKSHA_SECRET`).
Results go to `eval_runs/<set>__<label>/` (`scorecard.json` plus the three run outputs).

**Windows:** this repo's `.gitattributes` disables line-ending conversion, because `truth.json` pins the
SHA-256 of every input file. If you copy the sets elsewhere, keep the bytes exact (`git -c core.autocrlf=false`).

## What the scorecard checks

| Line | Source | Meaning |
|---|---|---|
| `contract` | official `validate_output.py` | must be `CONTRACT OK` |
| `check_dev` | official `check_dev.py --truth` | surface leaks per type / script / channel, canaries, medical values, pairwise linking |
| `LOCAL SCORE` | `local_scorer.py` | 100-point estimate of `docs/SCORING.md` (privacy uses `local_attacker.py`) |
| `strict token leak rate` | `eval_gauntlet.py` | every name *token* counts (official "keys" semantics), minus occurrences inside preserve probes |
| `critical identifiers surviving` | `eval_gauntlet.py` | direct IDs and full names after decoding base64 / %XX / HTML entities / `\uXXXX` / homoglyphs / zero-width |
| `canaries incl. stdout/stderr/TMP` | `eval_gauntlet.py` | the whole output tree plus side channels plus a private TMP/HOME |
| `LOS preserved` | `eval_gauntlet.py` | each admission's true length of stay is still an interval between two output dates |
| `age bands` | `eval_gauntlet.py` | structured age cells must be bands that contain the true age |
| `determinism` / `secret rotation` | `eval_gauntlet.py` | A == B byte-identical; C (new secret) shares no pseudonym |
| `linkage traps` | `eval_gauntlet.py` | homonyms kept apart, family phone kept apart, re-registration / fragmented / language patients unified; level 2 adds twins and father/son kept apart, maiden name / transliteration / corrupted duplicate / newborn unified |
| `release hygiene` | `eval_gauntlet.py` | CSV/TSV cells a spreadsheet would run as formulas, JSON outputs that are not strict JSON (`NaN`), output file names with shell metacharacters or `..` |

`check_dev.py` cannot tell a doctor from a relative with the same first name: "Dr. Anirban Saha" kept while
"brother Anirban" is removed still shows as one leak there. The strict token check subtracts preserve-probe
occurrences, as the official scorer does.

## Trap catalogue

| Trap | Planted as |
|---|---|
| **Unseen hospitals and ID shapes** | `SSH-R-25-055336`, `BCT22376516`, `KR-6361141`, `VZC.25.004417`, IPD `KRM/IP/2025/7743`, `ADM-25-3397`, `VZC-IP-10462`, scheme `ABPMJAY/SSH/25/123456` |
| **Unseen headers** | A: `Beneficiary, Kin, Abode, Cell, Natl ID, Born, Rogi, Sambandhi, Dooraabhash, PtFirst, Ph#, MRNo...`; B: `Insured Person, Next of Kin, Residence, GivenName, FamilyName, Hamlet, SubDiv, D.O.B., रोगी, संबंधी, निवास स्थान...`; JSON keys `beneficiary/kin/residence/aadhr_num/vzc_id` (A) or `members/person/guardian/uid_number/card_no` (B) |
| **Name pools** | pan-India (Tamil, North-East, Punjabi, Bengali, Marathi, Muslim, Christian); pools A and B are disjoint |
| **Name forms** | `SURNAME, Given`, `UPPER CASE`, `Mohammad / Mohd. / Md.` variants, `Given S.` initials, split first/last columns, Devanagari, Hinglish with honorifics (`ji, sahab, didi, amma, garu, anna, akka, ben`) |
| **Relatives** | `S/o, D/o, W/o`, `पुत्र/पुत्री/पत्नी`, `पिता:/पति:`, "brought by son X", "unke pati X ne bataya", "Attendant X", WhatsApp sender "X bhaiya" |
| **Phones** | 12 groupings: plain, `+91 xxxxx xxxxx`, `0xxxxx-xxxxx`, `xxxx-xxxxxx`, `xxx xxx xxxx`, `+91-xxx-xxx-xxxx`, `0091 ...`, Devanagari digits, `(xxx) xxx-xxxx`, `+91xxxxxxxxxx`, `xx xxxx xxxx`, `xxxxx.xxxxx` |
| **Aadhaar / ABHA / PAN / email** | spaced, dashed, dotted, contiguous, Devanagari digits, JSON number, masked `XXXX XXXX 1234`; ABHA number and ABHA address `x.y@abdm`; PAN in claims; email in JSON |
| **Dates** | `dd.mm.yyyy`, `dd-mm-yyyy`, ISO, `mm/dd/yyyy` (one hospital), `dd-Mon-yyyy`, `Month d, yyyy`, Devanagari digits, `[dd/mm/yy, hh:mm pm]`, year-less "5 September" |
| **Meaning traps** | relative shares the treating doctor's first name; `C/O fever` vs `C/O <relative>`; `K/C/O`, `H/O`; `Ward 7 (Surgery)` vs residential `Ward 14`; `ASHA worker`; eponyms (Parkinson's, Bell's palsy, Down syndrome, Wilson's, Hansen's, Koch's); doses `1-0-1`, `Dolo 650 BD x 5 days`; phone-shaped batch numbers; PIN-shaped platelet counts; claim amounts; `Medicine Unit 2` |
| **Hinglish false-positive bait** | capitalised verbs at line start ("Bataya gaya ki raat ko..."), "ne bataya ki dawai nahi li" |
| **Fragmented identity** | discharge note with only "Given, W/o RelGiven" and a year-less date |
| **Homonyms** | two pairs with the exact same full name, different village, age and relative |
| **Family phone** | husband and wife both patients, sharing one phone |
| **Re-registration** | same patient, two UHIDs at the same hospital, linked only through Aadhaar |
| **Re-identification** | 97-year-old with Wilson's disease in a one-off village; Takayasu arteritis plus a Whipple procedure; known-facts file with true admission dates |
| **Hidden leakage** | PII in JSON keys, a pivoted CSV header, file names (`consent_<Given>_<Sur>_<phone>.txt`), export metadata paths, FHIR `text.div` narrative, base64 attachment, `\uXXXX`-escaped Devanagari JSON, `%20`-encoded URL, HTML numeric entities, Cyrillic homoglyphs, zero-width space |
| **Canaries** (5, in no list) | gate-pass log, helpdesk JSON summary, base64 consent scan, ambulance CSV narrative, Hinglish "X ji ka phone aaya tha" |
| **Clean documents** | protocol, formulary, duty roster, bed census in `clean/`, plus one clean SOP outside `clean/` |
| **Robustness** | UTF-8 BOM `;`-CSV, UTF-16 TSV, cp1252 CSV with ragged unquoted commas and multi-line quoted cells, CRLF notes, exact duplicate export, 3,000 to 6,000-row bulk JSON, truncated JSON, CDA XML, PDF, JPEG, XLSX, empty CSV, invalid UTF-8, JSON behind `.csv`, 1,500-deep JSON |

## Level 2 (hard) traps

| Trap | Planted as |
|---|---|
| **Hostile export cells** | spreadsheet formulas in a remarks column (`=CMD\|' /C calc'!A0`, `+SUM(...)`, `-2+3+cmd...`, `@HYPERLINK(...)`, tab + `=1+1`); a NUL byte between a referrer's name and phone; Excel-mangled phones (`9.62731E+09`) and float phones in JSON (`9876543210.0`); zero-width spaces inside names and phone digits; SQL, XSS, JNDI, template and path-traversal strings in free text |
| **Corrupted duplicates** | the same registration row twice, the copy's age replaced by `-1`, `0x7fffffff`, `9223372036854775807` or `NaN`: must link as one patient, and no raw garbage age should pass through |
| **Meaning inside structure** | "C/O fever and weakness; Bell's palsy; HbA1c 6.5%" in a *structured* column (value-based profiling must not read it as "care of <relative>"); two columns both headed `Name` (patient and relative); `S/o Late X`; `C/O X (PAN: ...)` |
| **People** | `B/O <mother>` newborns with ages in days or months; a doctor sharing the patient's surname; a mixed-script name (Devanagari given name + Latin surname); apostrophe surnames (`D'Souza`); a 29 Feb DOB and an impossible `31/02/2025` |
| **Identity** | twins (same DOB, parents, address and phone, different given names) kept apart; father and son with the same name, address and phone kept apart, plus a WhatsApp line that could be either (ambiguous on purpose); a married woman linked to her maiden-name record through Aadhaar + phone; Devanagari-only FHIR names whose surnames romanise badly (नायर / Nair, अय्यर / Iyer) linked through a shared UHID; lower-case hospital IDs (`kvh/op/25-000123`) |
| **Privacy** | FHIR narrative `"<village> 247451"`: a PIN with no "PIN" cue right after the village; a phone stored reversed inside a bidi override (`U+202E ... U+202C`) |
| **Hostile files** | unsafe names (`$(whoami)_kvh_opd.json`, `visit;rm -rf ~;.txt`, `.._.._etc_passwd_<Given>.txt`, backtick `id` backtick `_lab.csv`); JSON with `NaN` / `Infinity`; a 1.2 MB single-line OCR dump and an 80 KB regex bomb, each hiding a canary; a 150 KB JSON field hiding a canary; DOCX, SQLite, NUL-only and broken-surrogate UTF-16 files |

All level-2 hostile files are `expect: "either"`, as in the official rules: quarantine them, or export them
cleaned and under a safe name. Never copy them raw.

Note on file names: the official `check_dev.py` reads a quarantined file's *original* path as its file name,
so PII in the name of a quarantined file counts as a file-name leak. Exporting the cleaned file under a
keyed name avoids that.

Linkability in the truth file is computed from evidence, not hand-labelled: units of a patient are linked
through keys unique to that patient (shared ID, name + DOB, name + relative, name + village + age). The
largest connected component is `required`; any other unit is `ambiguous`.
