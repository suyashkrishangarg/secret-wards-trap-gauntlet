#!/usr/bin/env python3
"""Trap Gauntlet: a seeded, adversarial Secret-Wards-style dataset with an official-schema answer key.

Writes a *kit-shaped* folder so both the official practice checker and the local scorer can grade it:

    <out>/scoring.toml                       (copied from the official kit)
    <out>/dev/input/...                      what the pipeline receives
    <out>/dev/truth/truth.json               answer key (raksha-truth/1 schema, + "los" probes)
    <out>/dev/truth/raw_attack.json          attacker baseline on the raw input (for normalised risk)
    <out>/dev/attacker/registry.csv          voter-roll-style population register
    <out>/dev/attacker/known_facts.jsonl     partial knowledge + decoys

Every trap from the problem statement, docs/DATASET.md and docs/ATTACKS.md is planted, with formats the
practice data never shows (new hospitals, ID shapes, header labels, date formats, name pools, scripts).

    --pool A   tuning vocabulary (names + header labels)
    --pool B   held-out vocabulary: never tune against it, use it as the final generalisation check
"""
from __future__ import annotations

import argparse
import base64
import csv
import datetime as dt
import hashlib
import html
import io
import json
import os
import random
import shutil
import sys
import tempfile
import urllib.parse
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
# official toolkit checkout (only scoring.toml is copied from it); override with SECRET_WARDS_KIT
KIT = Path(os.environ.get("SECRET_WARDS_KIT") or ROOT / "Secret-Wards-ToolKit")
REF_DATE = dt.date(2025, 12, 15)
DEVA_DIGITS = str.maketrans("0123456789", "०१२३४५६७८९")
GENERIC = {"devi", "kumar", "kumari", "md", "mohd", "mohammad", "ji", "bai", "begum", "singh", "kaur", "देवी", "कुमार", "मोहम्मद",
           "sahab", "bhaiya", "babu", "anna", "garu", "bhai", "didi", "behenji", "amma", "akka", "ben", "जी"}

# ----------------------------------------------------------------------------------------------- pools
# (latin, devanagari). Pool A = even index, pool B = odd index. None of these are practice-data names.
MALE = [
    ("Thiruvenkadam", "तिरुवेंकडम"), ("Arivazhagan", "अरिवलगन"), ("Ngawang", "नवांग"), ("Kezhokhoto", "केझोखोतो"),
    ("Zothanmawia", "ज़ोथनमाविया"), ("Harpreet", "हरप्रीत"), ("Gurbaksh", "गुरबख्श"), ("Sukhdev", "सुखदेव"),
    ("Anirban", "अनिर्बान"), ("Subhendu", "शुभेंदु"), ("Debashish", "देबाशीष"), ("Ritwik", "ऋत्विक"),
    ("Jayesh", "जयेश"), ("Hitesh", "हितेश"), ("Bhavik", "भाविक"), ("Omkar", "ओंकार"),
    ("Pandurang", "पांडुरंग"), ("Shrikant", "श्रीकांत"), ("Venkatesh", "वेंकटेश"), ("Nagarjuna", "नागार्जुन"),
    ("Raghavendra", "राघवेंद्र"), ("Muthuswamy", "मुथुस्वामी"), ("Selvaraj", "सेल्वराज"), ("Ilango", "इलांगो"),
    ("Jitendra", "जितेंद्र"), ("Bhupendra", "भूपेंद्र"), ("Lakhan", "लखन"), ("Chhotelal", "छोटेलाल"),
    ("Ramdular", "रामदुलार"), ("Bajrangi", "बजरंगी"), ("Imtiaz", "इम्तियाज़"), ("Faizan", "फ़ैज़ान"),
    ("Shoaib", "शोएब"), ("Tanveer", "तनवीर"), ("Yusuf", "यूसुफ़"), ("Joseph", "जोसेफ"),
    ("Ignatius", "इग्नेशियस"), ("Anthony", "एंथनी"), ("Dorjee", "दोरजी"), ("Pemba", "पेम्बा"),
    ("Bhaskar", "भास्कर"), ("Gopinath", "गोपीनाथ"), ("Hemant", "हेमंत"), ("Prabhakar", "प्रभाकर"),
    ("Dhananjay", "धनंजय"), ("Kulwant", "कुलवंत"), ("Tejinder", "तेजिंदर"), ("Biswajit", "बिस्वजीत"),
    ("Somnath", "सोमनाथ"), ("Rajan", "राजन"),
]
FEMALE = [
    ("Lalrinpuii", "ललरिनपुई"), ("Kaveri", "कावेरी"), ("Ilavarasi", "इलवरसी"), ("Meenakshi", "मीनाक्षी"),
    ("Thenmozhi", "तेनमोझी"), ("Sangeetha", "संगीता"), ("Harleen", "हरलीन"), ("Jasvinder", "जसविंदर"),
    ("Paramjit", "परमजीत"), ("Moumita", "मौमिता"), ("Sharmistha", "शर्मिष्ठा"), ("Debjani", "देबजानी"),
    ("Ishani", "ईशानी"), ("Hetal", "हेतल"), ("Falguni", "फाल्गुनी"), ("Bhargavi", "भार्गवी"),
    ("Revathi", "रेवती"), ("Shobha", "शोभा"), ("Ujwala", "उज्ज्वला"), ("Madhavi", "माधवी"),
    ("Ashwini", "अश्विनी"), ("Rukmini", "रुक्मिणी"), ("Phoolmati", "फूलमती"), ("Ramrati", "रामरती"),
    ("Bhagwati", "भगवती"), ("Chandrakala", "चंद्रकला"), ("Nazia", "नाज़िया"), ("Rukhsana", "रुख़साना"),
    ("Shabnam", "शबनम"), ("Tabassum", "तबस्सुम"), ("Philomena", "फ़िलोमिना"), ("Grace", "ग्रेस"),
    ("Pema", "पेमा"), ("Dolkar", "दोलकर"), ("Vimala", "विमला"), ("Hemlata", "हेमलता"),
    ("Jyotsna", "ज्योत्स्ना"), ("Anupama", "अनुपमा"), ("Lalitha", "ललिता"), ("Gowri", "गौरी"),
    ("Zubeda", "ज़ुबैदा"), ("Afreen", "आफ़रीन"), ("Kiranjeet", "किरणजीत"), ("Bidisha", "बिदिशा"),
    ("Meera", "मीरा"), ("Tulsi", "तुलसी"), ("Yamuna", "यमुना"), ("Saroj", "सरोज"),
]
SURNAMES = [
    ("Subramaniam", "सुब्रमण्यम"), ("Hmar", "ह्मार"), ("Bhutia", "भूटिया"), ("Sema", "सेमा"),
    ("Lepcha", "लेप्चा"), ("Gill", "गिल"), ("Sandhu", "संधू"), ("Grewal", "ग्रेवाल"),
    ("Bhattacharya", "भट्टाचार्य"), ("Chakraborty", "चक्रवर्ती"), ("Mukherjee", "मुखर्जी"), ("Ganguly", "गांगुली"),
    ("Desai", "देसाई"), ("Parmar", "परमार"), ("Solanki", "सोलंकी"), ("Kulkarni", "कुलकर्णी"),
    ("Deshpande", "देशपांडे"), ("Gaikwad", "गायकवाड़"), ("Pillai", "पिल्लई"), ("Nambiar", "नांबियार"),
    ("Menon", "मेनन"), ("Naidu", "नायडू"), ("Gowda", "गौड़ा"), ("Hegde", "हेगड़े"),
    ("Rathore", "राठौर"), ("Shekhawat", "शेखावत"), ("Bairwa", "बैरवा"), ("Kushwaha", "कुशवाहा"),
    ("Prajapati", "प्रजापति"), ("Ansari", "अंसारी"), ("Qureshi", "क़ुरैशी"), ("Siddiqui", "सिद्दीक़ी"),
    ("Shaikh", "शेख़"), ("Fernandes", "फ़र्नांडिस"), ("Mathew", "मैथ्यू"), ("Tamang", "तमांग"),
    ("Gurung", "गुरुंग"), ("Mahato", "महतो"), ("Murmu", "मुर्मू"), ("Soren", "सोरेन"),
    ("Oraon", "उरांव"), ("Baghel", "बघेल"), ("Lodhi", "लोधी"), ("Rajbhar", "राजभर"),
    ("Kharbanda", "खरबंदा"), ("Wadhwa", "वाधवा"), ("Kalita", "कलिता"), ("Bora", "बोरा"),
]
# Canaries: exist nowhere else in the data and in no name list; only context reveals them.
CANARIES = [
    ("Vaikunthanathan Ezhumalai", "Vaikunthanathan", "Ezhumalai"),
    ("Thangjam Ibemhal", "Thangjam", "Ibemhal"),
    ("Pirzada Ruhullah", "Pirzada", "Ruhullah"),
    ("Neelkanth Gudadhe", "Neelkanth", "Gudadhe"),
    ("Zeenatunnisa Kalwani", "Zeenatunnisa", "Kalwani"),
]
DOCTORS = [  # several share a first name with patients/relatives (doctor-vs-relative trap)
    ("Ramesh Iyer", "रमेश अय्यर"), ("Sukhdev Bhalla", "सुखदेव भल्ला"), ("Kaveri Rao", "कावेरी राव"),
    ("Anirban Saha", "अनिर्बान साहा"), ("Meenakshi Sundaram", "मीनाक्षी सुंदरम"), ("Imtiaz Hussain", "इम्तियाज़ हुसैन"),
    ("Pandurang Joshi", "पांडुरंग जोशी"), ("Grace Varghese", "ग्रेस वर्गीज़"),
]
GEO = [  # real districts / tehsils (public admin areas), synthetic villages
    ("Ratnagiri", "रत्नागिरी", [("Chiplun", "चिपलून"), ("Dapoli", "दापोली")], "415"),
    ("Satara", "सातारा", [("Karad", "कराड"), ("Wai", "वाई")], "415"),
    ("Kamrup", "कामरूप", [("Rangiya", "रंगिया"), ("Boko", "बोको")], "781"),
    ("Jorhat", "जोरहाट", [("Titabor", "टीटाबोर"), ("Mariani", "मरियानी")], "785"),
    ("Rewa", "रीवा", [("Mauganj", "मऊगंज"), ("Sirmour", "सिरमौर")], "486"),
    ("Alappuzha", "अलप्पुझा", [("Kuttanad", "कुट्टनाड"), ("Cherthala", "चेरथला")], "688"),
    ("Barmer", "बाड़मेर", [("Balotra", "बालोतरा"), ("Sheo", "शिव")], "344"),
    ("Jhunjhunu", "झुंझुनू", [("Chirawa", "चिड़ावा"), ("Nawalgarh", "नवलगढ़")], "333"),
]
V_PRE = [("Kanhai", "कन्हई"), ("Bel", "बेल"), ("Dhan", "धन"), ("Moti", "मोती"), ("Kesar", "केसर"), ("Ratan", "रतन"),
         ("Hira", "हीरा"), ("Bakhri", "बखरी"), ("Nimba", "निम्बा"), ("Jamun", "जामुन"), ("Mahua", "महुआ"), ("Kadam", "कदम")]
V_SUF = [("pur", "पुर"), ("gaon", "गांव"), ("wadi", "वाड़ी"), ("palli", "पल्ली"), ("khera", "खेड़ा"), ("tola", "टोला"),
         ("dih", "डीह"), ("halli", "हल्ली")]
LOCALITIES = [("Mohalla Kazi Tola", "मोहल्ला काज़ी टोला"), ("Shivaji Peth", "शिवाजी पेठ"), ("Nehru Colony", "नेहरू कॉलोनी"),
              ("Ward 14", "वार्ड 14"), ("Gandhi Chowk", "गांधी चौक"), ("Burma Camp Lane 3", "बर्मा कैंप लेन 3")]
LANDMARKS = [("near Hanuman Mandir", "हनुमान मंदिर के पास"), ("opp. Gram Panchayat Bhavan", "ग्राम पंचायत भवन के सामने"),
             ("behind Govt. Primary School", "सरकारी स्कूल के पीछे"), ("near Pani Tanki", "पानी टंकी के पास")]
HOSPITALS = {
    "ssh": ("Sahyadri Sevashram Hospital", "सह्याद्री सेवाश्रम अस्पताल"),
    "bct": ("Brahmaputra Care Trust Hospital", "ब्रह्मपुत्र केयर ट्रस्ट अस्पताल"),
    "krm": ("Konkan Rural Mission Hospital", "कोंकण ग्रामीण मिशन अस्पताल"),
    "vzc": ("Vindhya Zila Chikitsalaya", "विंध्य ज़िला चिकित्सालय"),
}
DX_COMMON = [("I10", "Essential (primary) hypertension"), ("E11.9", "Type 2 diabetes mellitus without complications"),
             ("A90", "Dengue fever"), ("A01.0", "Typhoid fever"), ("J18.9", "Pneumonia, unspecified organism"),
             ("N39.0", "Urinary tract infection, site not specified"), ("A15.0", "Tuberculosis of lung"),
             ("B54", "Unspecified malaria"), ("K35.80", "Acute appendicitis"), ("E03.9", "Hypothyroidism, unspecified"),
             ("D50.9", "Iron deficiency anaemia, unspecified"), ("J45.909", "Asthma, uncomplicated")]
DX_RARE = [("E83.01", "Wilson's disease"), ("M31.4", "Takayasu arteritis"), ("G12.21", "Amyotrophic lateral sclerosis"),
           ("E75.22", "Gaucher disease"), ("A30.9", "Hansen's disease"), ("Q87.4", "Marfan syndrome")]
PROC_COMMON = ["Laparoscopic appendectomy", "Inguinal hernia repair", "Lower segment caesarean section", "Cholecystectomy"]
PROC_RARE = ["Pancreaticoduodenectomy (Whipple procedure)", "Thymectomy"]
DRUGS = [("Amlodipine", "5 mg"), ("Metformin", "500 mg"), ("Telmisartan", "40 mg"), ("Atorvastatin", "10 mg"),
         ("Pantoprazole", "40 mg"), ("Levothyroxine", "50 mcg"), ("Azithromycin", "500 mg"), ("Cefixime", "200 mg"),
         ("Ondansetron", "4 mg"), ("Glimepiride", "1 mg"), ("Rifampicin", "450 mg"), ("Ecosprin", "75 mg"),
         ("Furosemide", "40 mg"), ("Penicillamine", "250 mg"), ("Prednisolone", "10 mg"), ("Ramipril", "5 mg")]
FREQS = ["1-0-1", "1-0-0", "0-0-1", "1-1-1", "BD", "OD", "TDS", "HS"]
COMPLAINTS = ["fever x 3 days", "pain abdomen x 2 days", "cough with expectoration x 2 weeks", "breathlessness on exertion",
              "giddiness x 1 week", "burning micturition x 4 days", "vomiting x 1 day", "joint pains x 1 month"]
LABS = [("Haemoglobin", (7.5, 15.5), "g/dL", 1), ("Random Blood Sugar", (80, 320), "mg/dL", 0),
        ("Serum Creatinine", (0.6, 3.2), "mg/dL", 1), ("Platelet count", (45000, 420000), "/cumm", 0),
        ("TSH", (0.5, 9.0), "mIU/L", 2), ("Total Leucocyte Count", (4000, 15000), "/cumm", 0), ("HbA1c", (5.0, 12.0), "%", 1)]
HON_M = ["ji", "sahab", "bhaiya", "babu", "anna", "garu", "bhai"]
HON_F = ["ji", "didi", "behenji", "amma", "akka", "ben"]
MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
MONTHS_FULL = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October",
               "November", "December"]

# Header vocabularies: pool A for tuning, pool B held out. Neither appears in the practice data.
HDR = {
    "ssh": {
        "A": ["Reg Code", "Beneficiary", "Kin", "Sex", "Yrs", "Born", "Abode", "Gaon/Wadi", "Taluka", "Zilla",
              "Postcode", "Cell", "Natl ID", "ABHA", "Registered"],
        "B": ["SSH No", "Insured Person", "Next of Kin", "Gender", "Age(Y)", "D.O.B.", "Residence", "Locality",
              "Block", "District", "PIN", "Contact", "UIDAI No", "Health ID", "Regd On"],
    },
    "bct": {
        "A": ["Panjikaran Kramank", "Rogi", "Sambandhi", "Ling", "Aayu", "Janm Din", "Nivas Sthan", "Gaon", "Tehsil",
              "Zila", "Pin", "Dooraabhash", "Aadhaar Sankhya", "Tithi"],
        "B": ["क्रमांक", "रोगी", "संबंधी", "लिंग", "आयु", "जन्म", "निवास स्थान", "गांव", "तहसील", "ज़िला", "पिनकोड",
              "संपर्क", "आधार", "दिनांक"],
    },
    "krm": {
        "A": ["PtFirst", "PtLast", "RelNm", "G", "AgeYr", "DtOfBirth", "Addr1", "Vill", "Tal", "Dist", "PC", "Ph#",
              "UID", "MRNo", "DtReg", "Remarks"],
        "B": ["GivenName", "FamilyName", "Guardian", "Sx", "Age", "BirthDt", "Street", "Hamlet", "SubDiv", "Dist",
              "Pin", "Phone", "Aadhar", "UHID", "Date", "Notes"],
    },
    "lab": {
        "A": ["sample", "pt", "ref", "age_sex", "test", "result", "unit", "collected", "reported", "ref_by"],
        "B": ["accession", "patient", "hosp_no", "agesex", "investigation", "value", "uom", "drawn", "signed", "referring"],
    },
    "bill": {
        "A": ["claim_no", "insured", "scheme_id", "payer_pan", "hosp_no", "procedure", "package", "amount_inr",
              "admitted", "discharged"],
        "B": ["claim", "member", "card", "pan_no", "uhid", "surgery", "pkg_code", "amount", "doa", "dod"],
    },
}
JKEYS = {  # JSON key vocabularies
    "A": {"reg_list": "beneficiaries", "person": "beneficiary", "given": "given", "family": "family", "kin": "kin",
          "sex": "sex", "age": "age", "dob": "born", "res": "residence", "phone": "contact_no", "aadhaar": "aadhr_num",
          "id": "vzc_id", "reg": "registered", "pt": "pt", "nm": "nm", "ref": "ref", "cb": "callback_no"},
    "B": {"reg_list": "members", "person": "person", "given": "first", "family": "last", "kin": "guardian",
          "sex": "gender", "age": "age_years", "dob": "date_of_birth", "res": "address", "phone": "mobile_no",
          "aadhaar": "uid_number", "id": "card_no", "reg": "enrolled_on", "pt": "patient_info", "nm": "full_name",
          "ref": "hosp_no", "cb": "contact"},
}


# ----------------------------------------------------------------------------------------------- model
@dataclass
class Person:
    pid: str
    rid: str
    given: str
    given_d: str
    sur: str
    sur_d: str
    gender: str
    dob: dt.date
    prefix: str = ""          # "Mohammad" style generic prefix with variants
    middle: str = ""          # generic middle (Devi / Kumar)
    rel_type: str = ""        # S/o D/o W/o
    rel: "Person | None" = None
    house: str = ""
    locality: tuple[str, str] = ("", "")
    landmark: tuple[str, str] = ("", "")
    village: tuple[str, str] = ("", "")
    tehsil: tuple[str, str] = ("", "")
    district: tuple[str, str] = ("", "")
    pin: str = ""
    phone: str = ""
    email: str = ""
    aadhaar: str = ""
    abha: str = ""
    pan: str = ""
    leaked: bool = False

    @property
    def age(self) -> int:
        d = REF_DATE
        return d.year - self.dob.year - ((d.month, d.day) < (self.dob.month, self.dob.day))

    @property
    def canon(self) -> str:
        return f"{self.given} {self.sur}".lower()


@dataclass
class Admission:
    hosp: str
    ipd: str
    adm: dt.date
    dis: dt.date
    dx: tuple[str, str]
    proc: str
    ward: str
    doctor: tuple[str, str]
    ins: str


@dataclass
class Patient:
    key: str
    p: Person
    hosps: list[str]
    uhids: dict[str, list[str]]
    traps: list[str] = field(default_factory=list)
    visits: list[tuple[dt.date, str, str, tuple[str, str]]] = field(default_factory=list)
    adm: Admission | None = None


class Unit:
    def __init__(self, loc: str, patient: str | None = None, link: str = "required") -> None:
        self.loc, self.patient, self.link = loc, patient, link
        self.tags: list[str] = []
        self.entities: list[dict[str, Any]] = []
        self.preserve: list[dict[str, Any]] = []
        self.dates: list[dict[str, Any]] = []
        self.fields: list[dict[str, Any]] = []
        self.los: list[dict[str, Any]] = []
        self.keys: set[tuple] = set()
        self.flags: dict[str, Any] = {}

    def to_json(self) -> dict[str, Any]:
        return {"loc": self.loc, "patient": self.patient, "cid": f"{self.patient}#0" if self.patient else None,
                "link": self.link if self.patient else "none", "tags": self.tags, "entities": self.entities,
                "preserve": self.preserve, "dates": self.dates, "fields": self.fields, "exclude": [], "los": self.los}


@dataclass
class FileRec:
    path: str
    data: bytes
    fmt: str
    encoding: str = "utf-8"
    delimiter: str | None = None
    expect: str = "sanitize"
    category: str = ""
    clean: bool = False
    date_hint: str = "dmy"
    generalizable: list[str] = field(default_factory=list)
    units: dict[str, Unit] = field(default_factory=dict)


# ----------------------------------------------------------------------------------------------- formatting
def deva(s: str) -> str:
    return s.translate(DEVA_DIGITS)


def fmt_phone(d: str, style: int) -> str:
    return [
        d, f"+91 {d[:5]} {d[5:]}", f"0{d[:5]}-{d[5:]}", f"{d[:4]}-{d[4:]}", f"{d[:3]} {d[3:6]} {d[6:]}",
        f"+91-{d[:3]}-{d[3:6]}-{d[6:]}", f"0091 {d}", deva(f"{d[:5]} {d[5:]}"), f"({d[:3]}) {d[3:6]}-{d[6:]}",
        f"+91{d}", f"{d[:2]} {d[2:6]} {d[6:]}", f"{d[:5]}.{d[5:]}",
    ][style % 12]


def fmt_aadhaar(a: str, style: int) -> str:
    return [f"{a[:4]} {a[4:8]} {a[8:]}", f"{a[:4]}-{a[4:8]}-{a[8:]}", a, deva(f"{a[:4]} {a[4:8]} {a[8:]}"),
            f"{a[:4]}.{a[4:8]}.{a[8:]}"][style % 5]


def fmt_abha(a: str, style: int) -> str:
    return [f"{a[:2]}-{a[2:6]}-{a[6:10]}-{a[10:]}", a, f"{a[:2]} {a[2:6]} {a[6:10]} {a[10:]}"][style % 3]


def fmt_date(d: dt.date, style: str) -> str:
    return {
        "dmy_slash": f"{d.day:02d}/{d.month:02d}/{d.year}", "dmy_dot": f"{d.day:02d}.{d.month:02d}.{d.year}",
        "dmy_dash": f"{d.day:02d}-{d.month:02d}-{d.year}", "iso": d.isoformat(),
        "mdy": f"{d.month:02d}/{d.day:02d}/{d.year}", "dmon": f"{d.day:02d}-{MONTHS[d.month - 1]}-{d.year}",
        "long": f"{MONTHS_FULL[d.month - 1]} {d.day}, {d.year}", "dmon_sp": f"{d.day} {MONTHS[d.month - 1]} {d.year}",
        "deva": deva(f"{d.day:02d}/{d.month:02d}/{d.year}"), "compact": d.strftime("%Y%m%d"),
        "noyear": f"{d.day} {MONTHS_FULL[d.month - 1]}",
    }[style]


def render_name(p: Person, form: str, script: str = "latin", variant: int = 0) -> str:
    pre_l = ["Mohammad ", "Mohd. ", "Md. ", "Mohd "][variant % 4] if p.prefix else ""
    pre_d = "मोहम्मद " if p.prefix else ""
    mid_l = f" {p.middle}" if p.middle else ""
    mid_d = {"Devi": " देवी", "Kumar": " कुमार"}.get(p.middle, "")
    if script == "deva":
        return {"full": f"{pre_d}{p.given_d}{mid_d} {p.sur_d}", "given": f"{pre_d}{p.given_d}"}.get(form, f"{p.given_d} {p.sur_d}")
    return {
        "full": f"{pre_l}{p.given}{mid_l} {p.sur}",
        "plain": f"{p.given} {p.sur}",
        "given": f"{p.given}",
        "sur_first": f"{p.sur.upper()}, {p.given}",
        "initial": f"{p.given[0]}. {p.sur}",
        "given_init": f"{pre_l}{p.given} {p.sur[0]}.",
        "upper": f"{pre_l}{p.given}{mid_l} {p.sur}".upper(),
    }[form]


def name_tokens(surface: str) -> list[str]:
    plain = urllib.parse.unquote(html.unescape(surface)).replace("​", "")
    plain = plain.translate(str.maketrans({"а": "a", "о": "o", "е": "e"}))
    toks = []
    for t in plain.replace(",", " ").replace(".", " ").replace("_", " ").split():
        tl = t.lower()
        if len(t) <= 1 or tl in GENERIC:
            continue
        toks.append(tl)
    return toks


# ----------------------------------------------------------------------------------------------- entity helpers
class Ctx:
    """Registers every planted surface against a unit while composing text."""

    def __init__(self, u: Unit) -> None:
        self.u = u

    def _ent(self, typ: str, surface: str, person: Person | str, role: str, script: str, channel: str,
             match: str, critical: bool, **extra: Any) -> None:
        pid = person.pid if isinstance(person, Person) else person
        e = {"type": typ, "surface": surface, "person": pid, "role": role, "script": script, "channel": channel,
             "match": match, "critical": critical}
        e.update(extra)
        self.u.entities.append(e)

    def name(self, p: Person, form: str = "full", script: str = "latin", role: str = "patient",
             channel: str = "content", variant: int = 0, hinglish: bool = False, surface: str | None = None) -> str:
        s = surface or render_name(p, form, script, variant)
        toks = name_tokens(s)
        typ = "PATIENT_NAME" if role == "patient" else "RELATIVE_NAME"
        full = len(toks) >= 2
        sc = "deva" if script == "deva" else ("hinglish" if hinglish else "latin")
        self._ent(typ, s, p, role, sc, channel, "name", typ == "PATIENT_NAME" and full, tokens=toks, full=full)
        if role == "patient":
            self.u.flags["name_full" if full else "name_given"] = True
        else:
            self.u.flags["rel"] = True
        return s

    def hon(self, p: Person, hon: str, role: str = "patient") -> str:
        s = f"{p.given} {hon}"
        self.name(p, role=role, hinglish=True, surface=s)
        return s

    def digits(self, typ: str, surface: str, person: Person | str, channel: str = "content", role: str = "patient",
               key_digits: str | None = None) -> str:
        k = key_digits or "".join(ch for ch in surface.translate(str.maketrans("०१२३४५६७८९", "0123456789")) if ch.isdigit())
        self._ent(typ, surface, person, role, "deva" if any("\u0900" <= c <= "\u097f" for c in surface) else "latin",
                  channel, "digits", True, key=k)
        if role == "patient" and typ in ("PHONE", "AADHAAR", "ABHA_NUMBER", "MRN", "INSURANCE_ID"):
            self.u.keys.add(("id", typ, k))
        return surface

    def phone(self, p: Person, style: int, role: str = "patient", channel: str = "content") -> str:
        s = fmt_phone(p.phone, style)
        self.digits("PHONE", s, p, channel, role, key_digits=p.phone)
        if role != "patient":   # attendant phone still links by data evidence -> family-phone trap
            self.u.keys.add(("id", "PHONE", p.phone))
        return s

    def text(self, typ: str, surface: str, person: Person | str, channel: str = "content", critical: bool = False,
             role: str = "patient") -> str:
        self._ent(typ, surface, person, role, "deva" if any("\u0900" <= c <= "\u097f" for c in surface) else "latin",
                  channel, "text", critical, key=surface.lower())
        if typ in ("PAN", "EMAIL", "ABHA_ADDRESS", "INSURANCE_ID") and role == "patient":
            self.u.keys.add(("id", typ, surface.upper()))
        if typ == "VILLAGE":
            self.u.flags["village"] = True
        return surface

    def dob(self, p: Person, style: str, path: str | None = None) -> str:
        s = fmt_date(p.dob, style)
        self._ent("DOB", s, p, "patient", "deva" if style == "deva" else "latin", "content", "dob", False,
                  key=p.dob.isoformat())
        self.u.fields.append({"kind": "dob", "true": p.dob.isoformat(), "path": path, "patient": self.u.patient})
        self.u.flags["dob"] = True
        return s

    def age(self, p: Person, s: str, path: str | None = None) -> str:
        self.u.fields.append({"kind": "age", "true": p.age, "path": path, "patient": self.u.patient})
        self.u.flags["age"] = True
        return s

    def date(self, d: dt.date, style: str, event: str, anchor: str | None = None, path: str | None = None) -> str:
        s = fmt_date(d, style)
        self.u.dates.append({"true": d.isoformat(), "event": event, "patient": self.u.patient,
                             "hint": "mdy" if style == "mdy" else "dmy", "anchor": anchor, "path": path})
        return s

    def keep(self, text: str, kind: str, weight: float = 1.0, trap: str | None = None, path: str | None = None) -> str:
        pv: dict[str, Any] = {"text": text, "kind": kind, "weight": weight}
        if trap:
            pv["trap"] = trap
        if path:
            pv["path"] = path
        self.u.preserve.append(pv)
        return text

    def addr(self, p: Person, script: str = "latin") -> str:
        """Full address line: house, locality, landmark, village, tehsil, district, pin."""
        i = 1 if script == "deva" else 0
        house = self.text("HOUSE", (f"H.No. {p.house}" if i == 0 else f"मकान नं. {p.house}"), p)
        loc = self.text("LOCALITY", p.locality[i], p)
        lm = self.text("LANDMARK", p.landmark[i], p)
        vil = self.text("VILLAGE", p.village[i], p)
        dist = self.keep(p.district[i], "district", 0.3)
        pin = self.pin(p)
        if i == 0:
            return f"{house}, {loc}, {lm}, Vill. {vil}, Tal. {p.tehsil[0]}, Dist. {dist} - {pin}"
        return f"{house}, {loc}, {lm}, ग्राम {vil}, तहसील {p.tehsil[1]}, ज़िला {dist} - {pin}"

    def pin(self, p: Person) -> str:
        self._ent("PIN", p.pin, p, "patient", "latin", "content", "digits_exact", False, key=p.pin)
        return p.pin


# ----------------------------------------------------------------------------------------------- generator
class Gauntlet:
    def __init__(self, seed: int, pool: str, n_patients: int, n_bulk: int) -> None:
        self.r = random.Random(f"gauntlet:{seed}:{pool}")
        self.seed, self.pool = seed, pool
        self.n_patients, self.n_bulk = n_patients, n_bulk
        sel = 0 if pool == "A" else 1
        self.male = MALE[sel::2]
        self.female = FEMALE[sel::2]
        self.surnames = SURNAMES[sel::2]
        self.persons: list[Person] = []
        self.patients: list[Patient] = []
        self.files: dict[str, FileRec] = {}
        self.canary_ids: list[str] = []
        self._ids: set[str] = set()
        self.k = JKEYS[pool]

    # ---------------------------------------------------------------- identifiers
    def _uniq(self, fn) -> str:
        while True:
            v = fn()
            if v not in self._ids:
                self._ids.add(v)
                return v

    def rdig(self, n: int, first: str = "123456789") -> str:
        return self.r.choice(first) + "".join(self.r.choice("0123456789") for _ in range(n - 1))

    def new_uhid(self, h: str) -> str:
        r = self.r
        return self._uniq(lambda: {
            "ssh": f"SSH-R-25-{r.randint(1000, 99999):06d}",
            "bct": f"BCT{r.randint(10_000_000, 99_999_999)}",
            "krm": f"KR-{r.randint(100000, 9999999):07d}",
            "vzc": f"VZC.25.{r.randint(1000, 999999):06d}",
        }[h])

    def new_ipd(self, h: str) -> str:
        r = self.r
        return self._uniq(lambda: {
            "ssh": f"IPD/25/{r.randint(100, 99999):05d}", "bct": f"ADM-25-{r.randint(100, 9999):04d}",
            "krm": f"KRM/IP/2025/{r.randint(100, 9999):04d}", "vzc": f"VZC-IP-{r.randint(10000, 99999)}",
        }[h])

    def new_person(self, gender: str, sur: tuple[str, str] | None = None, age_range=(18, 80)) -> Person:
        r = self.r
        g = r.choice(self.male if gender == "M" else self.female)
        s = sur or r.choice(self.surnames)
        age = r.randint(*age_range)
        dob = REF_DATE - dt.timedelta(days=age * 365 + r.randint(10, 350))
        dist = r.choice(GEO)
        teh = r.choice(dist[2])
        vil = r.choice(V_PRE), r.choice(V_SUF)
        village = (vil[0][0] + vil[1][0], vil[0][1] + vil[1][1])
        if r.random() < 0.25:
            village = (village[0] + " Khurd", village[1] + " खुर्द")
        idx = len(self.persons)
        p = Person(
            pid=f"G{idx:05d}", rid=self._uniq(lambda: f"RG{self.rdig(8)}"), given=g[0], given_d=g[1], sur=s[0], sur_d=s[1],
            gender=gender, dob=dob, house=str(r.randint(1, 480)) + r.choice(["", "", "/A", "-B"]),
            locality=r.choice(LOCALITIES), landmark=r.choice(LANDMARKS), village=village, tehsil=teh,
            district=(dist[0], dist[1]), pin=dist[3] + f"{r.randint(1, 999):03d}",
            phone=self._uniq(lambda: self.rdig(10, "6789")), aadhaar=self._uniq(lambda: self.rdig(12, "23456789")),
            abha=self._uniq(lambda: "91" + self.rdig(12, "0123456789")),
            pan=self._uniq(lambda: "".join(r.choice("ABCDEFGHJKLMNPQRSTUVWXYZ") for _ in range(3)) + "P"
                           + s[0][0].upper() + self.rdig(4) + r.choice("ABCDEFGHJKLMNPQRSTUVWXYZ")),
            leaked=r.random() < 0.6,
        )
        p.email = f"{p.given.lower()}.{p.sur.lower()[:4]}{r.randint(10, 99)}@{r.choice(['mailbox.in', 'rediffmail.com', 'gmail.com'])}"
        self.persons.append(p)
        return p

    def attach_relative(self, p: Person, rel_type: str | None = None) -> Person:
        rt = rel_type or ("W/o" if p.gender == "F" and self.r.random() < 0.6 else self.r.choice(["S/o", "D/o"] if p.gender == "M" else ["D/o"]))
        if p.gender == "M":
            rt = "S/o"
        lo, hi = (max(18, p.age - 8), p.age + 8) if rt == "W/o" else (p.age + 20, p.age + 35)
        rel = self.new_person("M", sur=(p.sur, p.sur_d), age_range=(lo, max(lo + 1, hi)))
        for attr in ("house", "locality", "landmark", "village", "tehsil", "district", "pin"):
            setattr(rel, attr, getattr(p, attr))
        p.rel_type, p.rel = rt, rel
        return rel

    # ---------------------------------------------------------------- population
    def build_population(self) -> None:
        r = self.r
        hs = list(HOSPITALS)
        for i in range(self.n_patients):
            gender = "F" if i % 2 else "M"
            p = self.new_person(gender, age_range=(19, 84))
            self.attach_relative(p)
            if gender == "F" and r.random() < 0.2:
                p.middle = "Devi"
            elif gender == "M" and r.random() < 0.15:
                p.middle = "Kumar"
            hosps = sorted(r.sample(hs, 2 if r.random() < 0.35 else 1))
            pt = Patient(key=f"PT{i:05d}", p=p, hosps=hosps, uhids={h: [self.new_uhid(h)] for h in hosps})
            self.patients.append(pt)
        P = self.patients
        # --- trap assignments (indices stable across seeds) ---
        # homonym pairs: exact same full name, different village/age/relative
        for a, b in ((0, 2), (4, 6)):
            pb = P[b].p
            pa = P[a].p
            pb.given, pb.given_d, pb.sur, pb.sur_d, pb.middle, pb.gender = pa.given, pa.given_d, pa.sur, pa.sur_d, "", pa.gender
            pa.middle = ""
            pb.rel.sur, pb.rel.sur_d = pa.sur, pa.sur_d
            if pb.rel.given == pa.rel.given:
                pb.rel.given, pb.rel.given_d = ("Lakhan", "लखन") if pa.rel.given != "Lakhan" else ("Somnath", "सोमनाथ")
            if pa.village == pb.village:
                pb.village = (pb.village[0] + " Kalan", pb.village[1] + " कलां")
            P[a].traps.append("homonym")
            P[b].traps.append("homonym")
        # 97-year-old with rare disease in a tiny village (re-identification)
        old = P[8].p
        old.dob = REF_DATE - dt.timedelta(days=97 * 365 + 40)
        old.village = ("Hirakhera Chhota", "हीराखेड़ा छोटा")
        old.rel_type = "S/o" if old.gender == "M" else "D/o"
        P[8].traps.append("reid_old_rare")
        P[9].traps.append("reid_rare_proc")
        # married couple, both patients: wife's records carry the husband's phone (family-phone trap)
        wife, husband = P[11], P[10]
        husband.p.gender = "M"
        wife.p.gender = "F"
        wife.p.rel_type, wife.p.rel = "W/o", husband.p
        wife.p.sur, wife.p.sur_d = husband.p.sur, husband.p.sur_d
        for attr in ("house", "locality", "landmark", "village", "tehsil", "district", "pin"):
            setattr(wife.p, attr, getattr(husband.p, attr))
        wife.p.phone = husband.p.phone   # one family phone for both spouses
        wife.traps.append("family_phone")
        husband.traps.append("family_phone")
        # re-registration: same hospital, two UHIDs, same Aadhaar
        rr = P[12]
        rr.uhids[rr.hosps[0]].append(self.new_uhid(rr.hosps[0]))
        rr.traps.append("reregistration")
        for i in (13, 15):
            P[i].traps.append("fragmented")
            P[i].p.gender = "F"
            if P[i].p.rel_type != "W/o":
                P[i].p.rel_type = "W/o"
        for i in (14, 16):
            P[i].traps.append("language")
        for i, (dg, dd) in ((17, ("Ramesh", "रमेश")), (18, ("Sukhdev", "सुखदेव"))):
            P[i].traps.append("meaning")   # relative shares the treating doctor's first name
            P[i].p.rel.given, P[i].p.rel.given_d = dg, dd
        P[20].p.prefix = "Mohammad"
        P[20].traps.append("name_variants")
        # non-patient population (registry only): 4x patients
        for _ in range(self.n_patients * 3):
            q = self.new_person(self.r.choice("MF"), age_range=(18, 92))
            self.attach_relative(q)
        # a registry decoy that shares the 97-year-old's village name but is young (k-anonymity pressure)
        # encounters
        for pt in self.patients:
            n_vis = r.randint(1, 3)
            for _ in range(n_vis):
                d = REF_DATE - dt.timedelta(days=r.randint(20, 330))
                pt.visits.append((d, r.choice(pt.hosps), r.choice(COMPLAINTS), r.choice(DX_COMMON)))
            pt.visits.sort()
            if r.random() < 0.55 or any(t.startswith("reid") or t in ("fragmented", "language", "meaning", "family_phone") for t in pt.traps):
                h = pt.hosps[0]
                adm = REF_DATE - dt.timedelta(days=r.randint(15, 300))
                los = r.randint(2, 12)
                dx = r.choice(DX_COMMON)
                proc = r.choice(PROC_COMMON) if r.random() < 0.3 else ""
                if "reid_old_rare" in pt.traps:
                    dx, los = DX_RARE[0], 23
                if "reid_rare_proc" in pt.traps:
                    dx, proc, los = DX_RARE[1], PROC_RARE[0], 17
                pt.adm = Admission(h, self.new_ipd(h), adm, adm + dt.timedelta(days=los), dx, proc,
                                   r.choice(["Ward 7 (Surgery)", "Ward 3 (Medicine)", "Ward 2 (Obstetrics & Gynaecology)", "Ward 5 (Medicine)"]),
                                   r.choice(DOCTORS), f"ABPMJAY/{h.upper()}/25/{r.randint(100000, 999999)}")
        for i, pt in enumerate(self.patients):  # stable person ids for patients
            pt.p.pid = f"P{i:05d}"

    # ---------------------------------------------------------------- file helpers
    def add(self, fr: FileRec) -> FileRec:
        self.files[fr.path] = fr
        return fr

    def unit(self, fr: FileRec, loc: str, pt: Patient | None) -> Ctx:
        u = Unit(loc, pt.key if pt else None)
        fr.units[loc] = u
        return Ctx(u)

    def doctor(self, avoid: Person | None = None) -> tuple[str, str]:
        choices = [d for d in DOCTORS if not avoid or d[0].split()[0] not in (avoid.given, avoid.rel.given if avoid.rel else "")]
        return self.r.choice(choices or DOCTORS)

    # ---------------------------------------------------------------- registration
    def gen_registration(self) -> None:
        r = self.r
        by_h: dict[str, list[tuple[Patient, str]]] = {h: [] for h in HOSPITALS}
        for pt in self.patients:
            for h in pt.hosps:
                for uh in pt.uhids[h]:
                    by_h[h].append((pt, uh))
        for h in by_h:
            r.shuffle(by_h[h])

        # SSH: semicolon CSV, UTF-8 BOM, dotted DMY dates, novel headers
        hdr = HDR["ssh"][self.pool]
        fr = FileRec("registration/sahyadri_beneficiaries.csv", b"", "csv", "utf-8-sig", ";", category="registration",
                     generalizable=[f"col:{hdr[4]}", f"col:{hdr[5]}", f"col:{hdr[10]}", f"col:{hdr[7]}"])
        rows = [hdr]
        for i, (pt, uh) in enumerate(by_h["ssh"]):
            p = pt.p
            c = self.unit(fr, f"row:{i}", pt)
            form = "sur_first" if i % 4 == 1 else ("initial" if "initials" in pt.traps else "full")
            if form == "initial":  # initial + surname alone is weak evidence; keep full name in kin column context
                form = "full"
            rows.append([
                c.digits("MRN", uh, p), c.name(p, form), f"{p.rel_type} {c.name(p.rel, 'full', role='relative')}",
                p.gender, c.age(p, str(p.age), f"col:{hdr[4]}"), c.dob(p, "dmy_dot", f"col:{hdr[5]}"),
                f"{c.text('HOUSE', 'H.No. ' + p.house, p)}, {c.text('LOCALITY', p.locality[0], p)}, {c.text('LANDMARK', p.landmark[0], p)}",
                c.text("VILLAGE", p.village[0], p), p.tehsil[0], c.keep(p.district[0], "district", 0.3, path=f"col:{hdr[9]}"),
                c.pin(p), c.phone(p, i), c.digits("AADHAAR", fmt_aadhaar(p.aadhaar, i), p),
                c.digits("ABHA_NUMBER", fmt_abha(p.abha, i), p) if i % 3 else c.text("ABHA_ADDRESS", f"{p.given.lower()}.{p.sur.lower()}@abdm", p, critical=True),
                c.date(REF_DATE - dt.timedelta(days=r.randint(200, 900)), "dmy_dot", "registration:ssh", path=f"col:{hdr[14]}"),
            ])
            if "family_phone" in pt.traps and p.gender == "F":
                c.u.tags.append("family_phone")
        fr.data = self._csv(rows, ";").encode("utf-8-sig")
        self.add(fr)
        # exact duplicate export under another name (dedup trap)
        dup = FileRec("registration/sahyadri_beneficiaries (copy).csv", fr.data, "csv", "utf-8-sig", ";",
                      category="registration", generalizable=fr.generalizable)
        for loc, u in fr.units.items():
            nu = Unit(loc, u.patient)
            nu.__dict__.update({k: (list(v) if isinstance(v, list) else (set(v) if isinstance(v, set) else (dict(v) if isinstance(v, dict) else v))) for k, v in u.__dict__.items()})
            dup.units[loc] = nu
        self.add(dup)

        # BCT: UTF-16 TSV, bilingual headers, Devanagari rows, Devanagari digits
        hdr = HDR["bct"][self.pool]
        fr = FileRec("registration/brahmaputra_panjikaran.tsv", b"", "tsv", "utf-16", "\t", category="registration",
                     generalizable=[f"col:{hdr[4]}", f"col:{hdr[5]}", f"col:{hdr[10]}", f"col:{hdr[7]}"])
        rows = [hdr]
        for i, (pt, uh) in enumerate(by_h["bct"]):
            p = pt.p
            c = self.unit(fr, f"row:{i}", pt)
            dv = i % 3 != 2
            rel_word = {"S/o": "पुत्र", "D/o": "पुत्री", "W/o": "पत्नी"}[p.rel_type] if dv else p.rel_type
            rows.append([
                c.digits("MRN", uh, p), c.name(p, "full", "deva" if dv else "latin"),
                f"{rel_word} {c.name(p.rel, 'full', 'deva' if dv else 'latin', role='relative')}",
                ("पुरुष" if p.gender == "M" else "महिला") if dv else p.gender,
                c.age(p, f"{deva(str(p.age)) if i % 2 else p.age} वर्ष", f"col:{hdr[4]}"),
                c.dob(p, "deva" if i % 2 else "dmy_dash", f"col:{hdr[5]}"),
                (f"{c.text('HOUSE', 'मकान नं. ' + p.house, p)}, {c.text('LOCALITY', p.locality[1], p)}, {c.text('LANDMARK', p.landmark[1], p)}"
                 if dv else f"{c.text('HOUSE', 'House ' + p.house, p)}, {c.text('LOCALITY', p.locality[0], p)}"),
                c.text("VILLAGE", p.village[1] if dv else p.village[0], p), p.tehsil[1] if dv else p.tehsil[0],
                c.keep(p.district[1] if dv else p.district[0], "district", 0.3, path=f"col:{hdr[9]}"), c.pin(p),
                c.phone(p, 7 if i % 2 else i), c.digits("AADHAAR", fmt_aadhaar(p.aadhaar, 3 if dv else i), p),
                c.date(REF_DATE - dt.timedelta(days=r.randint(200, 900)), "dmy_dash", "registration:bct", path=f"col:{hdr[13]}"),
            ])
        fr.data = self._csv(rows, "\t").encode("utf-16")
        self.add(fr)

        # KRM: cp1252 legacy CSV, MONTH-first dates, split names, ragged rows, multi-line quoted remarks
        hdr = HDR["krm"][self.pool]
        fr = FileRec("registration/konkan_legacy_export.csv", b"", "csv", "cp1252", ",", category="registration",
                     date_hint="mdy", generalizable=[f"col:{hdr[4]}", f"col:{hdr[5]}", f"col:{hdr[10]}", f"col:{hdr[7]}"])
        lines = [",".join(hdr)]
        for i, (pt, uh) in enumerate(by_h["krm"]):
            p = pt.p
            c = self.unit(fr, f"row:{i}", pt)
            given = c.name(p, surface=(("Md. " if p.prefix else "") + p.given))
            sur = c.name(p, surface=p.sur)
            c.u.flags["name_full"] = True
            rel = c.name(p.rel, "full", role="relative")
            house = c.text("HOUSE", f"H.No. {p.house}", p)
            loc = c.text("LOCALITY", p.locality[0], p)
            addr = f"{house}, {loc}" if i % 3 == 0 else f'"{house}, {loc}"'  # unquoted comma -> ragged row
            remarks = (f'"Old pt. K/C/O DM.\nC/O {c.name(p.rel, "full", role="relative")}, {c.text("LANDMARK", p.landmark[0], p)}"'
                       if i % 4 == 0 else "Follow up")
            if i % 4 == 0:
                c.keep("K/C/O DM", "history", trap="k/c/o")
            lines.append(",".join([
                given, sur, f"{p.rel_type} {rel}", p.gender, c.age(p, str(p.age), f"col:{hdr[4]}"),
                c.dob(p, "mdy", f"col:{hdr[5]}"), addr, c.text("VILLAGE", p.village[0], p), p.tehsil[0],
                c.keep(p.district[0], "district", 0.3), c.pin(p), c.phone(p, [0, 1, 2, 3, 4, 5, 6, 8, 9, 10, 11][i % 11]),
                c.digits("AADHAAR", fmt_aadhaar(p.aadhaar, [0, 1, 2, 4][i % 4]), p), c.digits("MRN", uh, p),
                c.date(REF_DATE - dt.timedelta(days=r.randint(200, 900)), "mdy", "registration:krm"), remarks,
            ]))
        fr.data = ("\r\n".join(lines) + "\r\n").encode("cp1252", errors="replace")
        self.add(fr)

        # VZC: nested JSON, Aadhaar stored as a NUMBER, novel keys, export metadata with PII in a path
        k = self.k
        items = []
        fr = FileRec("registration/vindhya_members.json", b"", "json", category="registration",
                     generalizable=[f"/{k['reg_list']}/[]/{k['age']}", f"/{k['reg_list']}/[]/{k['dob']}",
                                    f"/{k['reg_list']}/[]/{k['res']}/pin", f"/{k['reg_list']}/[]/{k['res']}/village"])
        for i, (pt, uh) in enumerate(by_h["vzc"]):
            p = pt.p
            c = self.unit(fr, f"/{k['reg_list']}/{i}", pt)
            c.u.tags.append("numeric_aadhaar")
            g = c.name(p, surface=p.given)
            fam = c.name(p, surface=p.sur)
            c.u.flags["name_full"] = True
            items.append({
                k["id"]: c.digits("MRN", uh, p),
                k["person"]: {k["given"]: g, k["family"]: fam},
                k["kin"]: {"relation": p.rel_type, "name": c.name(p.rel, "full", role="relative")},
                k["sex"]: p.gender, k["age"]: int(c.age(p, str(p.age), f"/{k['age']}")),
                k["dob"]: c.dob(p, "iso", f"/{k['dob']}"),
                k["res"]: {"house": c.text("HOUSE", f"H.No. {p.house}", p), "locality": c.text("LOCALITY", p.locality[0], p),
                           "village": c.text("VILLAGE", p.village[0], p), "tehsil": p.tehsil[0],
                           "district": c.keep(p.district[0], "district", 0.3), "pin": c.pin(p)},
                k["phone"]: c.phone(p, 0),
                "email": c.text("EMAIL", p.email, p, critical=True) if i % 3 == 0 else None,
                k["aadhaar"]: int(c.digits("AADHAAR", p.aadhaar, p)),
                k["reg"]: c.date(REF_DATE - dt.timedelta(days=r.randint(200, 900)), "iso", "registration:vzc"),
            })
        first = by_h["vzc"][0][0].p if by_h["vzc"] else self.patients[0].p
        meta = self.unit(fr, "@file", None)
        src = f"E:/hmis/export/{first.given}_{first.sur}_{by_h['vzc'][0][1] if by_h['vzc'] else 'x'}.xlsx"
        meta.name(first, surface=f"{first.given}_{first.sur}", channel="metadata")
        if by_h["vzc"]:
            meta.digits("MRN", by_h["vzc"][0][1], first, channel="metadata")
        doc = {"facility": {"name": HOSPITALS["vzc"][0], "state_code": "MP"},
               "export_meta": {"tool": "HMIS 4.1", "source_file": src, "record_count": len(items)},
               k["reg_list"]: items}
        fr.data = json.dumps(doc, ensure_ascii=False, indent=2).encode("utf-8")
        self.add(fr)

    @staticmethod
    def _csv(rows: list[list[str]], delim: str) -> str:
        buf = io.StringIO()
        csv.writer(buf, delimiter=delim, lineterminator="\n").writerows(rows)
        return buf.getvalue()

    # ---------------------------------------------------------------- OPD
    def gen_opd(self) -> None:
        k = self.k
        groups: dict[tuple[str, int], list[tuple[Patient, tuple]]] = {}
        for pt in self.patients:
            for v in pt.visits:
                groups.setdefault((v[1], v[0].month), []).append((pt, v))
        for (h, mon), items in sorted(groups.items()):
            fr = FileRec(f"opd/{h}_opd_2025_{mon:02d}.json", b"", "json", category="opd")
            visits = []
            for i, (pt, (d, _h, comp, dx)) in enumerate(sorted(items, key=lambda x: x[1][0])):
                p = pt.p
                c = self.unit(fr, f"/visits/{i}", pt)
                drug, dose = self.r.choice(DRUGS)
                freq = self.r.choice(FREQS)
                doc = self.doctor(p)
                v = {
                    "slip": i + 1,
                    k["pt"]: {k["nm"]: c.name(p, "full" if i % 3 else "given_init", variant=i), k["ref"]: c.digits("MRN", pt.uhids[h][0], p),
                              "age_sex": c.age(p, f"{p.age}/{p.gender}")},
                    "date": c.date(d, "iso", "opd_visit"),
                    "complaint": c.keep(f"C/O {comp}", "complaint", trap="c/o-complaint"),
                    "vitals": {"bp": c.keep(f"{self.r.randint(110, 170)}/{self.r.randint(70, 100)}", "vital", 0.5), "pulse": self.r.randint(64, 110)},
                    "dx": {"code": c.keep(dx[0], "diagnosis_code"), "display": c.keep(dx[1], "diagnosis")},
                    "advice": c.keep(f"Tab. {drug} {dose} {freq} x {self.r.choice([5, 7, 30])} days", "medication", trap="dose"),
                    "doctor": c.keep(f"Dr. {doc[0]}", "doctor", 0.3, trap="doctor"),
                }
                if i % 2 == 0:
                    v[k["cb"]] = c.phone(p, i + 2)
                visits.append(v)
            first, fv = items[0][0].p, items[0][0]
            meta = self.unit(fr, "@file", None)
            src = f"D:\\HMIS\\dump\\{first.given}_{first.sur}_{fv.uhids[h][0].replace('/', '-')}.xlsx"
            meta.name(first, surface=f"{first.given}_{first.sur}", channel="metadata")
            meta.digits("MRN", fv.uhids[h][0].replace("/", "-"), first, channel="metadata")
            out = {"export_info": {"system": "HMIS v3.2", "source_file": src, "rows": len(visits)},
                   "facility": {"name": HOSPITALS[h][0]}, "visits": visits}
            fr.data = json.dumps(out, ensure_ascii=False, indent=2).encode("utf-8")
            self.add(fr)

    # ---------------------------------------------------------------- admissions: discharge, FHIR, nursing, billing
    def gen_admissions(self) -> None:
        r = self.r
        bill_rows: dict[str, list] = {}
        n = 0
        for pt in self.patients:
            if not pt.adm:
                continue
            n += 1
            a, p = pt.adm, pt.p
            style = ("fragment" if "fragmented" in pt.traps else "labelled" if "meaning" in pt.traps else "hindi" if ("language" in pt.traps or n % 5 == 0)
                     else "narrative" if n % 3 == 0 else "labelled")
            self._discharge(pt, n, style)
            self._fhir(pt, n)
            self._nursing(pt, n)
            bill_rows.setdefault(a.hosp, []).append(pt)
        hdr = HDR["bill"][self.pool]
        for h, pts in sorted(bill_rows.items()):
            fr = FileRec(f"billing/{h}_claims.csv", b"", "csv", category="billing")
            rows = [hdr]
            for i, pt in enumerate(pts):
                a, p = pt.adm, pt.p
                c = self.unit(fr, f"row:{i}", pt)
                rows.append([
                    f"CLM{r.randint(100000, 999999)}", c.name(p, "upper" if i % 2 else "full", variant=i),
                    c.text("INSURANCE_ID", a.ins, p, critical=True), c.text("PAN", p.pan, p, critical=True) if i % 2 == 0 else "",
                    c.digits("MRN", pt.uhids[h][0], p), c.keep(a.proc or "Medical management", "procedure"),
                    c.keep(f"PKG-{r.randint(100, 999)}", "package", 0.5), c.keep(str(r.randint(9000, 180000)), "amount", 0.5),
                    c.date(a.adm, "dmy_slash", "admission"), c.date(a.dis, "dmy_slash", "discharge"),
                ])
                c.u.los.append({"days": (a.dis - a.adm).days})
            fr.data = self._csv(rows, ",").encode("utf-8")
            self.add(fr)

    def _discharge(self, pt: Patient, n: int, style: str) -> None:
        a, p = pt.adm, pt.p
        r = self.r
        fr = FileRec(f"discharge/ds_{n:04d}.txt", b"", "text", category="discharge")
        c = self.unit(fr, "doc", pt)
        drug, dose = r.choice(DRUGS)
        if a.dx == DX_RARE[0]:
            drug, dose = "Penicillamine", "250 mg"
        freq = r.choice(FREQS[:4])
        los = (a.dis - a.adm).days
        if style != "fragment":
            c.u.los.append({"days": los})
        doc = a.doctor
        if style == "fragment":
            c.u.tags.append("frag_trap")
            txt = (f"Discharge note\n\n{c.name(p, 'given')}, {p.rel_type} {c.name(p.rel, 'given', role='relative')}, discharged in stable condition.\n"
                   f"Visit: {c.date(a.dis, 'noyear', 'discharge', anchor='Visit:')}\n"
                   f"Treated for {c.keep(a.dx[1], 'diagnosis')}. {c.keep('BP 150/90', 'vital')}. Continue {c.keep(f'{drug} {dose}', 'medication')} {c.keep(freq, 'frequency', trap='1-0-1') if '-' in freq else freq}.\n")
        elif style == "hindi":
            gen = "पुरुष" if p.gender == "M" else "महिला"
            relw = {"S/o": "पिता", "D/o": "पिता", "W/o": "पति"}[p.rel_type]
            txt = (f"डिस्चार्ज सारांश — {c.keep(HOSPITALS[a.hosp][1], 'hospital', 0.3)}\n"
                   f"रोगी का नाम: {c.name(p, 'full', 'deva')}   आयु: {c.age(p, deva(str(p.age)) + ' वर्ष')} / {gen}\n"
                   f"{relw}: {c.name(p.rel, 'full', 'deva', role='relative')} | फ़ोन: {c.phone(p, 7)}\n"
                   f"आईपीडी सं.: {c.digits('MRN', a.ipd, p)}\n"
                   f"पता: {c.addr(p, 'deva')}\n"
                   f"भर्ती: {c.date(a.adm, 'deva', 'admission')}   छुट्टी: {c.date(a.dis, 'deva', 'discharge')}\n"
                   f"निदान: {c.keep(a.dx[1], 'diagnosis')} ({c.keep(a.dx[0], 'diagnosis_code')})\n"
                   f"दवा: {c.keep(f'{drug} {dose}', 'medication')} {freq} x 30 days\n"
                   f"{c.keep('डॉ. ' + doc[1], 'doctor', 0.5, trap='doctor')}\n")
        elif style == "narrative":
            title = "Mr." if p.gender == "M" else "Mrs."
            man = "man" if p.gender == "M" else "woman"
            relw = {"S/o": "son", "D/o": "daughter", "W/o": "husband"}
            attendant = "son" if p.age > 55 else "brother"
            txt = (f"DISCHARGE SUMMARY - {c.keep(HOSPITALS[a.hosp][0], 'hospital', 0.3)}\n\n"
                   f"{title} {c.name(p, 'full', variant=n)}, a {c.age(p, str(p.age))}-year-old {man} from {c.text('VILLAGE', p.village[0], p)}, "
                   f"was admitted on {c.date(a.adm, 'long', 'admission')} under {c.keep('Dr. ' + doc[0], 'doctor', 0.5, trap='doctor')} "
                   f"and discharged on {c.date(a.dis, 'long', 'discharge')}.\n"
                   f"Brought by {attendant} {c.name(p.rel, 'given', role='relative')} (mob {c.phone(p.rel, n + 4, role='relative')}).\n"
                   f"C/O {c.keep(r.choice(COMPLAINTS), 'complaint', trap='c/o-complaint')}. "
                   f"{c.keep('H/O pulmonary TB, completed ATT', 'history', trap='h/o')}.\n"
                   f"Final diagnosis: {c.keep(a.dx[1], 'diagnosis')} [{c.keep(a.dx[0], 'diagnosis_code')}].\n"
                   f"Discharge Rx: Tab {c.keep(f'{drug} {dose}', 'medication', trap='dose')} {c.keep(freq, 'frequency', trap='1-0-1') if '-' in freq else freq} x 30 days; "
                   f"{c.keep('Dolo 650 BD x 5 days', 'medication', trap='dose')}.\n"
                   f"Review in {c.keep('Medicine Unit 2', 'department')} OPD after 1 week. {c.keep('ASHA worker', 'context', trap='asha')} to monitor at home.\n")
        else:
            kin_rel = p.rel
            meaning = "meaning" in pt.traps
            if meaning:  # relative shares the doctor's first name: Dr. stays, relative goes
                doc = next(x for x in DOCTORS if x[0].split()[0] == kin_rel.given)
            hb = round(r.uniform(7.5, 14.5), 1)
            plt = r.randint(45000, 420000)
            txt = (f"DISCHARGE SUMMARY\n{c.keep(HOSPITALS[a.hosp][0], 'hospital', 0.3)}\n\n"
                   f"Patient: {c.name(p, 'sur_first' if n % 2 else 'full', variant=n)}    Age/Sex: {c.age(p, f'{p.age}Y/{p.gender}')}\n"
                   + (f"DOB: {c.dob(p, 'dmon_sp')}\n" if n % 2 == 0 else "")
                   + f"Kin: {p.rel_type} {c.name(kin_rel, 'full', role='relative')}    Ph: {c.phone(p, n)}\n"
                   f"IPD No: {c.digits('MRN', a.ipd, p)}   UHID: {c.digits('MRN', pt.uhids[a.hosp][0], p)}\n"
                   f"Address: {c.addr(p)}\n"
                   f"Admitted: {c.date(a.adm, 'dmon', 'admission', anchor='Admitted:')}   Discharged: {c.date(a.dis, 'dmon', 'discharge', anchor='Discharged:')}\n"
                   f"Ward/Bed: {c.keep(a.ward, 'ward', trap='hospital-ward')} / Bed {r.randint(1, 30)}\n"
                   f"Diagnosis: {c.keep(a.dx[1], 'diagnosis')} ({c.keep(a.dx[0], 'diagnosis_code')})\n"
                   + (f"Procedure: {c.keep(a.proc, 'procedure')}\n" if a.proc else "")
                   + f"{c.keep('K/C/O DM, HTN', 'history', trap='k/c/o')}. {c.keep('C/O fever x 3 days', 'complaint', trap='c/o-complaint')}.\n"
                   f"Labs: {c.keep(f'Hb {hb} g/dL', 'lab')}, {c.keep(f'Platelet count {plt} /cumm', 'lab')}.\n"
                   f"{c.keep('Inj. Insulin 10 units', 'medication', trap='dose')} SC HS; Tab {c.keep(f'{drug} {dose}', 'medication', trap='dose')} {c.keep(freq, 'frequency', trap='1-0-1') if '-' in freq else freq}.\n"
                   f"Seen by {c.keep('Dr. ' + doc[0], 'doctor', 0.5, trap='doctor-vs-relative' if meaning else 'doctor')}. "
                   f"Attendant {c.name(kin_rel, 'full', role='relative')} counselled re: {c.keep(r.choice(['Parkinson' + chr(39) + 's disease', 'Bell' + chr(39) + 's palsy', 'Down syndrome']), 'eponym', trap='eponym')} risk in family.\n"
                   f"Vaccine {c.keep('Batch No. 8812045671', 'context', 0.5)} given.\n")
        fr.data = txt.encode("utf-8")
        self.add(fr)

    def _fhir(self, pt: Patient, n: int) -> None:
        a, p = pt.adm, pt.p
        r = self.r
        fr = FileRec(f"fhir/bundle_{hashlib.sha1(f'{self.seed}{pt.key}'.encode()).hexdigest()[:8]}.json", b"", "fhir",
                     category="fhir", generalizable=["/entry/[]/resource/birthDate", "/entry/[]/resource/address/[]/postalCode"])
        c = self.unit(fr, "doc", pt)
        c.u.los.append({"days": (a.dis - a.adm).days})

        def uid(tag: str) -> str:
            h = hashlib.sha1(f"{self.seed}{pt.key}{tag}".encode()).hexdigest()
            return f"{h[:8]}-{h[8:12]}-4{h[13:16]}-a{h[17:20]}-{h[20:32]}"
        ids = {t: uid(t) for t in ("pat", "prac", "org", "enc", "cond", "obs", "med", "doc")}
        full = c.name(p, "plain")
        for tok in (p.given, p.sur):
            if tok not in a.doctor[0].split():
                c.name(p, surface=tok)
        narrative_name = c.name(p, "full", variant=n)
        att = f"Discharge summary\nPatient: {c.name(p, 'plain', channel='base64')}\nPhone: {c.phone(p, 1, channel='base64')}\nDx: {a.dx[1]}\n"
        doc_name = a.doctor
        hb = round(r.uniform(7.5, 14.5), 1)
        res = [
            {"resourceType": "Patient", "id": ids["pat"],
             "text": {"status": "generated", "div": f"<div xmlns=\"http://www.w3.org/1999/xhtml\">{narrative_name}, {p.rel_type} {c.name(p.rel, 'full', role='relative')}</div>"},
             "identifier": [{"system": f"urn:hospital:{a.hosp}", "value": c.digits("MRN", pt.uhids[a.hosp][0], p)},
                            {"system": "https://healthid.abdm.gov.in", "value": c.digits("ABHA_NUMBER", fmt_abha(p.abha, 0), p)}],
             "name": [{"text": full, "family": p.sur, "given": [p.given]}],
             "telecom": [{"system": "phone", "value": c.phone(p, 1)}],
             "gender": "male" if p.gender == "M" else "female",
             "birthDate": c.dob(p, "iso", "/entry/0/resource/birthDate"),
             "address": [{"line": [c.text("HOUSE", f"H.No. {p.house}", p), c.text("LOCALITY", p.locality[0], p)],
                          "city": c.text("VILLAGE", p.village[0], p), "district": c.keep(p.district[0], "district", 0.3),
                          "postalCode": c.pin(p), "country": "IN"}]},
            {"resourceType": "Practitioner", "id": ids["prac"], "name": [{"text": c.keep("Dr. " + doc_name[0], "doctor", 0.5, trap="doctor")}]},
            {"resourceType": "Organization", "id": ids["org"], "name": c.keep(HOSPITALS[a.hosp][0], "hospital", 0.3)},
            {"resourceType": "Encounter", "id": ids["enc"], "status": "finished",
             "class": {"system": "http://terminology.hl7.org/CodeSystem/v3-ActCode", "code": "IMP"},
             "subject": {"reference": f"urn:uuid:{ids['pat']}"},
             "period": {"start": c.date(a.adm, "iso", "admission"), "end": c.date(a.dis, "iso", "discharge")},
             "serviceProvider": {"reference": f"urn:uuid:{ids['org']}"}},
            {"resourceType": "Condition", "id": ids["cond"], "subject": {"reference": f"urn:uuid:{ids['pat']}"},
             "code": {"coding": [{"system": "http://hl7.org/fhir/sid/icd-10", "code": c.keep(a.dx[0], "diagnosis_code"),
                                  "display": c.keep(a.dx[1], "diagnosis")}]}},
            {"resourceType": "Observation", "id": ids["obs"], "status": "final", "subject": {"reference": f"urn:uuid:{ids['pat']}"},
             "code": {"text": "Haemoglobin"}, "valueQuantity": {"value": float(c.keep(str(hb), "lab", 0.5)), "unit": "g/dL"}},
            {"resourceType": "DocumentReference", "id": ids["doc"], "status": "current",
             "subject": {"reference": f"urn:uuid:{ids['pat']}"},
             "content": [{"attachment": {"contentType": "text/plain", "data": base64.b64encode(att.encode()).decode()}}]},
        ]
        bundle = {"resourceType": "Bundle", "id": uid("bundle"), "type": "document",
                  "meta": {"source": f"#{pt.uhids[a.hosp][0]}"},
                  "entry": [{"fullUrl": f"urn:uuid:{x['id']}", "resource": x} for x in res]}
        fr.data = json.dumps(bundle, ensure_ascii=False, indent=2).encode("utf-8")
        self.add(fr)

    def _nursing(self, pt: Patient, n: int) -> None:
        a, p = pt.adm, pt.p
        r = self.r
        slug = a.ipd.lower().replace("/", "-")
        fr = FileRec(f"notes/nursing_{slug}.txt", b"", "text", category="nursing")
        fu = self.unit(fr, "@filename", None)
        fu.digits("MRN", slug, p, channel="filename")
        c = self.unit(fr, "doc", pt)
        hon = r.choice(HON_M if p.gender == "M" else HON_F)
        rel_hon = r.choice(HON_M)
        d1 = a.adm + dt.timedelta(days=1)
        lines = [
            f"NURSING NOTES - {c.keep(a.ward, 'ward', trap='hospital-ward')}, Bed {r.randint(1, 30)}",
            "",
            f"{c.date(d1, 'dmy_slash', 'nursing')} 22:00 - {c.hon(p, hon)} ka {c.keep('BP 140/90', 'vital')}, sugar 210. "
            f"{'Unke pati' if p.rel_type == 'W/o' else 'Unke pita'} {c.name(p.rel, 'given', role='relative', hinglish=True)} ne bataya ki subah dawai nahi li.",
            f"Bataya gaya ki raat ko {c.keep('Paracetamol 650 mg', 'medication', trap='dose')} diya. {c.keep('ASHA worker', 'context', trap='asha')} ne follow up kiya.",
            f"06:00 - Bed pe {c.name(p, 'full', hinglish=True, variant=n)} ({c.age(p, f'{p.age}/{p.gender}')}) theek hai, resident of {c.text('VILLAGE', p.village[0], p)}.",
            f"14:00 - {c.name(p.rel, 'given', role='relative', hinglish=True, surface=f'{p.rel.given} {rel_hon}')} se baat hui, call back on {c.phone(p.rel, n + 9, role='relative')}.",
        ]
        fr.data = ("\r\n".join(lines) + "\r\n").encode("utf-8")  # CRLF line endings
        self.add(fr)

    # ---------------------------------------------------------------- prescriptions & labs
    def gen_rx_and_labs(self) -> None:
        r = self.r
        for i, pt in enumerate(self.patients):
            p = pt.p
            d, h, comp, dx = pt.visits[-1]
            drug, dose = r.choice(DRUGS)
            fr = FileRec(f"prescriptions/rx_{h}_{i:05d}.txt", b"", "text", category="prescription")
            c = self.unit(fr, "doc", pt)
            doc = self.doctor(p)
            mode = i % 3 if "language" not in pt.traps else 2
            if mode == 0:
                txt = (f"{c.keep(HOSPITALS[h][0], 'hospital', 0.3)} - OPD Prescription\n"
                       f"Name: {c.name(p, 'full', variant=i)}   Age: {c.age(p, str(p.age) + ' yrs')}   Sex: {p.gender}\n"
                       f"UHID: {c.digits('MRN', pt.uhids[h][0], p)}   Mob: {c.phone(p, i)}\n"
                       f"Aadhaar: {c.digits('AADHAAR_MASKED', 'XXXX XXXX ' + p.aadhaar[-4:], p)}\n"
                       f"Date: {c.date(d, 'dmy_slash', 'opd_visit')}\n"
                       f"C/O {c.keep(comp, 'complaint', trap='c/o-complaint')}\n"
                       f"Dx: {c.keep(dx[1], 'diagnosis')} ({c.keep(dx[0], 'diagnosis_code')})\n"
                       f"Rx:\n 1. Tab {c.keep(f'{drug} {dose}', 'medication', trap='dose')}  {c.keep('1-0-1', 'frequency', trap='1-0-1')} x 30 days\n"
                       f" 2. {c.keep('Dolo 650 BD x 5 days', 'medication', trap='dose')}\n"
                       f"{c.keep('Dr. ' + doc[0], 'doctor', 0.5, trap='doctor')} (MBBS, MD)\n")
            elif mode == 1:
                txt = (f"Parchi - {c.keep(HOSPITALS[h][0], 'hospital', 0.3)}\n"
                       f"{c.hon(p, r.choice(HON_M if p.gender == 'M' else HON_F))} ({c.age(p, f'{p.age}Y/{p.gender}')}) ko {c.keep(comp.split(' x ')[0], 'complaint')} hai.\n"
                       f"Ref no {c.digits('MRN', pt.uhids[h][0], p)} | WhatsApp {c.phone(p, i + 5)}\n"
                       f"Dawai: {c.keep(f'{drug} {dose}', 'medication', trap='dose')} {c.keep('1-0-1', 'frequency', trap='1-0-1')} khana khane ke baad.\n"
                       f"Agar bukhar ho to {c.keep('Dolo 650 SOS', 'medication', trap='dose')}.\n"
                       f"- {c.keep('Dr. ' + doc[0], 'doctor', 0.5, trap='doctor')}\n")
            else:
                txt = (f"{c.keep(HOSPITALS[h][1], 'hospital', 0.3)} — पर्चा\n"
                       f"रोगी का नाम: {c.name(p, 'full', 'deva')}\n"
                       f"आयु: {c.age(p, deva(str(p.age)) + ' वर्ष')}   मोबाइल: {c.phone(p, 7)}\n"
                       f"पंजीकरण सं.: {c.digits('MRN', pt.uhids[h][0], p)}\n"
                       f"शिकायत: {c.keep(comp, 'complaint')}\n"
                       f"दवा: {c.keep(f'{drug} {dose}', 'medication', trap='dose')} {c.keep('1-0-1', 'frequency', trap='1-0-1')}\n"
                       f"{c.keep('डॉ. ' + doc[1], 'doctor', 0.5, trap='doctor')}\n")
            fr.data = txt.encode("utf-8")
            self.add(fr)

        # lab CSV per hospital (6-digit platelet counts look like PIN codes)
        hdr = HDR["lab"][self.pool]
        by_h: dict[str, list[Patient]] = {}
        for pt in self.patients:
            by_h.setdefault(pt.hosps[0], []).append(pt)
        for h, pts in sorted(by_h.items()):
            fr = FileRec(f"lab/{h}_results.csv", b"", "csv", category="lab", generalizable=[f"col:{hdr[3]}"])
            rows = [hdr]
            idx = 0
            for pt in pts:
                p = pt.p
                for test, rng, unit, nd in r.sample(LABS, 2):
                    c = self.unit(fr, f"row:{idx}", pt)
                    val = f"{r.uniform(*rng):.{nd}f}" if nd else str(r.randint(int(rng[0]), int(rng[1])))
                    d = pt.visits[-1][0]
                    doc = self.doctor(p)
                    rows.append([f"S{r.randint(100000, 999999)}", c.name(p, "full" if idx % 2 else "plain", variant=idx),
                                 c.digits("MRN", pt.uhids[h][0], p), c.age(p, f"{p.age}{'Y' if idx % 2 else ''}/{p.gender}", f"col:{hdr[3]}"),
                                 c.keep(test, "lab_test"), c.keep(val, "lab"), unit, c.date(d, "dmy_slash", "lab_collected"),
                                 c.date(d, "dmy_slash", "lab_reported"), c.keep("Dr. " + doc[0], "doctor", 0.3)])
                    idx += 1
            fr.data = self._csv(rows, ",").encode("utf-8")
            self.add(fr)

        # single-patient JSON reports + WhatsApp forwards
        for i, pt in enumerate(self.patients[: max(6, len(self.patients) // 3)]):
            p = pt.p
            h = pt.hosps[0]
            fr = FileRec(f"lab/report_{i:05d}.json", b"", "json", category="lab")
            c = self.unit(fr, "doc", pt)
            subj = "patient" if self.pool == "A" else "subject"
            doc = self.doctor(p)
            rep = {"lab": c.keep("Lifecare Diagnostics", "hospital", 0.3),
                   subj: {"name": c.name(p, "full", variant=i), "hosp_id": c.digits("MRN", pt.uhids[h][0], p),
                          "mobile": c.phone(p, i + 1), "age": c.age(p, f"{p.age} Yrs")},
                   "referred_by": c.keep("Dr. " + doc[0], "doctor", 0.3),
                   "collected": c.date(pt.visits[-1][0], "iso", "lab_collected"),
                   "panels": [{"name": "Routine", "results": [
                       {"test": c.keep("Haemoglobin", "lab_test"), "value": c.keep(f"{r.uniform(8, 15):.1f}", "lab"), "unit": "g/dL", "range": c.keep("12-16", "range", 0.5)},
                       {"test": c.keep("Platelet count", "lab_test"), "value": c.keep(str(r.randint(110000, 420000)), "lab"), "unit": "/cumm", "range": "150000-450000"}]}]}
            fr.data = json.dumps(rep, ensure_ascii=False, indent=2).encode("utf-8")
            self.add(fr)
            if i % 2 == 0:
                fr = FileRec(f"lab/wa_forward_{i:05d}.txt", b"", "text", category="lab")
                c = self.unit(fr, "doc", pt)
                d = pt.visits[-1][0]
                sender = c.name(p.rel, "given", role="relative", hinglish=True, surface=f"{p.rel.given} {r.choice(HON_M)}")
                ts = f"[{d.day:02d}/{d.month:02d}/{str(d.year)[2:]}, 9:{r.randint(10, 59)} pm]"
                c.date(d, "dmy_slash", "lab_forwarded", anchor="[")
                txt = (f"{ts} {sender}: <attachment: report.pdf>\nForwarded\n*Lifecare Diagnostics*\n"
                       f"{c.name(p, 'full', hinglish=True, variant=i)}  {c.age(p, f'{p.age} Y / {p.gender}')}\n"
                       f"{c.keep('Haemoglobin 9.8 g/dL', 'lab')} | {c.keep('Random Blood Sugar 245 mg/dL', 'lab')}\n"
                       f"Doctor ne bola {c.keep('Dolo 650 BD x 5 days', 'medication', trap='dose')} lena hai\n"
                       f"Koi problem ho to call karo {c.phone(p.rel, i + 2, role='relative')}\n")
                fr.data = txt.encode("utf-8")
                self.add(fr)

    def gen_bulk(self) -> None:
        r = self.r
        fr = FileRec("lab/bulk_results_dump.json", b"", "json", category="bulk")
        rows = []
        for i in range(self.n_bulk):
            pt = self.patients[i % len(self.patients)]
            p = pt.p
            c = self.unit(fr, f"/rows/{i}", pt)
            test, rng, unit, nd = LABS[i % len(LABS)]
            val = f"{r.uniform(*rng):.{nd}f}" if nd else str(r.randint(int(rng[0]), int(rng[1])))
            rows.append({"n": c.name(p, "plain"), "id": c.digits("MRN", pt.uhids[pt.hosps[0]][0], p), "t": test,
                         "v": c.keep(val, "lab", 0.5), "u": unit, "d": c.date(pt.visits[0][0], "iso", f"bulk:{i}")})
        fr.data = json.dumps({"schema": "bulk-v2", "rows": rows}, ensure_ascii=False).encode("utf-8")
        self.add(fr)

    # ---------------------------------------------------------------- clean documents (must survive intact)
    def gen_clean(self) -> None:
        def clean(path: str, fmt: str, data: str, probes: list[tuple[str, str, str | None]], delim: str | None = None) -> None:
            fr = FileRec(path, data.encode("utf-8"), fmt, delimiter=delim, category="clean", clean=True)
            c = self.unit(fr, "doc", None)
            for t, kind, trap in probes:
                c.keep(t, kind, trap=trap)
            self.add(fr)
        clean("clean/malaria_protocol.txt", "text",
              "MALARIA & DENGUE MANAGEMENT PROTOCOL (District Programme)\n\n"
              "1. C/O fever for 2-7 days with chills: test with RDT before treatment.\n"
              "2. Platelet count below 20000 /uL needs referral to Ward 5 (Medicine).\n"
              "3. Paracetamol 650 mg TDS. Avoid NSAIDs.\n"
              "4. ASHA workers do house-to-house fever surveillance every Monday.\n"
              "5. Rule out Addison's disease and Wilson's disease if electrolytes are deranged.\n"
              "6. Protocol owner: Dr. Ramesh Iyer, Medicine Unit 2. Reviewed by Dr. Grace Varghese.\n"
              "7. Helpline numbers are on the notice board, not in this document.\n",
              [("C/O fever for 2-7 days", "complaint", "c/o-complaint"), ("Platelet count below 20000 /uL", "lab", None),
               ("Ward 5 (Medicine)", "ward", "hospital-ward"), ("Paracetamol 650 mg TDS", "medication", "dose"),
               ("ASHA workers", "context", "asha"), ("Addison's disease", "eponym", "eponym"),
               ("Wilson's disease", "eponym", "eponym"), ("Dr. Ramesh Iyer", "doctor", "doctor"), ("Medicine Unit 2", "department", None)])
        clean("clean/drug_formulary.csv", "csv",
              "drug,strength,frequency,notes\nAmlodipine,5 mg,0-0-1,Hypertension\nMetformin,500 mg,1-0-1,Type 2 diabetes\n"
              "Rifampicin,450 mg,1-0-0,Tuberculosis (ATT)\nPenicillamine,250 mg,1-1-1,Wilson's disease\nDolo,650 mg,SOS,Fever\n",
              [("Amlodipine", "medication", None), ("0-0-1", "frequency", "1-0-1"), ("1-0-1", "frequency", "1-0-1"),
               ("Penicillamine", "medication", None), ("Wilson's disease", "eponym", "eponym")], ",")
        clean("clean/duty_roster.csv", "csv",
              "unit,consultant,ward,days\nMedicine Unit 2,Dr. Ramesh Iyer,Ward 3 (Medicine),Mon/Thu\n"
              "Surgery Unit 1,Dr. Sukhdev Bhalla,Ward 7 (Surgery),Tue/Fri\nObstetrics,Dr. Kaveri Rao,Ward 2 (Obstetrics & Gynaecology),Wed/Sat\n",
              [("Dr. Ramesh Iyer", "doctor", "doctor"), ("Dr. Sukhdev Bhalla", "doctor", "doctor"), ("Dr. Kaveri Rao", "doctor", "doctor"),
               ("Ward 7 (Surgery)", "ward", "hospital-ward"), ("Medicine Unit 2", "department", None)], ",")
        clean("clean/bed_census.json", "json",
              json.dumps({"date": "census", "wards": [{"ward": "Ward 3 (Medicine)", "beds": 30, "occupied": 24},
                                                       {"ward": "Ward 7 (Surgery)", "beds": 24, "occupied": 19}]}, indent=2),
              [("Ward 3 (Medicine)", "ward", "hospital-ward"), ("Ward 7 (Surgery)", "ward", "hospital-ward")])
        # a clean document OUTSIDE clean/: the folder name must not be the only signal
        fr = FileRec("misc/infection_control_sop.txt", b"", "text", category="clean", clean=True)
        c = self.unit(fr, "doc", None)
        txt = ("INFECTION CONTROL SOP\nHand hygiene before and after every patient contact.\n"
               f"Isolate {c.keep('Koch' + chr(39) + 's', 'eponym', trap='eponym')} cases in Ward 9 (Isolation).\n"
               f"{c.keep('Inj. Ceftriaxone 1 g IV BD x 5 days', 'medication', trap='dose')} for proven sepsis only.\n"
               f"Escalate to {c.keep('Dr. Anirban Saha', 'doctor', trap='doctor')} (Microbiology).\n"
               f"{c.keep('ASHA workers', 'context', trap='asha')} must wear masks during home visits.\n")
        fr.data = txt.encode("utf-8")
        self.add(fr)

    # ---------------------------------------------------------------- hidden leakage + canaries
    def gen_hidden(self) -> None:
        r = self.r
        P = self.patients
        # PII in JSON KEYS
        fr = FileRec("misc/bed_lookup.json", b"", "json", category="hidden")
        c = self.unit(fr, "@file", None)
        table = {}
        for pt in P[:6]:
            p = pt.p
            key = f"{c.digits('MRN', pt.uhids[pt.hosps[0]][0], p, channel='key')} {c.name(p, 'plain', channel='key')}"
            table[key] = {"bed": r.randint(1, 40), "diet": r.choice(["diabetic", "soft", "normal"])}
        fr.data = json.dumps({"generated": "nightly", "map": table}, ensure_ascii=False, indent=2).encode("utf-8")
        self.add(fr)
        # PII in CSV HEADER (pivoted bedside chart)
        fr = FileRec("misc/bedside_vitals_chart.csv", b"", "csv", category="hidden")
        c = self.unit(fr, "@header", None)
        cols = ["time"]
        for pt in P[6:9]:
            p = pt.p
            cols.append(f"{c.digits('MRN', pt.uhids[pt.hosps[0]][0], p, channel='header')} ({c.name(p, 'given', channel='header')})")
        rows = [cols] + [[f"{hh:02d}:00"] + [f"{r.randint(100, 160)}/{r.randint(60, 100)}" for _ in P[6:9]] for hh in (6, 12, 18)]
        for i in range(3):
            self.unit(fr, f"row:{i}", None)
        fr.data = self._csv(rows, ",").encode("utf-8")
        self.add(fr)
        # PII in FILE NAME
        p = P[21].p
        fname = f"misc/consent_{p.given}_{p.sur}_{p.phone}.txt"
        fr = FileRec(fname, b"", "text", category="hidden")
        fc = self.unit(fr, "@filename", None)
        fc.name(p, surface=f"{p.given}_{p.sur}", channel="filename")
        fc.digits("PHONE", p.phone, p, channel="filename")
        c = self.unit(fr, "doc", P[21])
        fr.data = (f"Consent for procedure signed by {c.name(p, 'plain')}, {p.rel_type} {c.name(p.rel, 'full', role='relative')}.\n"
                   f"Witness: staff nurse. Procedure: {c.keep('Upper GI endoscopy', 'procedure')}.\n").encode("utf-8")
        self.add(fr)
        # %-encoded URL, HTML entities, homoglyphs, zero-width characters, \\u-escaped Devanagari JSON
        p = P[22].p
        fr = FileRec("misc/portal_audit_log.txt", b"", "text", category="hidden")
        c = self.unit(fr, "doc", P[22])
        c.u.tags.append("encoded_payloads")
        q = urllib.parse.quote(f"{p.given} {p.sur}")
        ent = "".join(f"&#{ord(ch)};" for ch in render_name(p, "full", "deva"))
        homo = p.given.replace("a", "\u0430", 1).replace("o", "\u043e", 1) + " " + p.sur
        zw = p.given[:3] + "\u200b" + p.given[3:] + " " + p.sur
        c.name(p, surface=q, channel="content")
        c.name(p, surface=ent, script="deva", channel="content")
        c.name(p, surface=homo, channel="content")
        c.name(p, surface=zw, channel="content")
        fr.data = (f"GET /portal/search?name={q}&mobile={c.phone(p, 0)} 200\n"
                   f"<td>{ent}</td><td>{c.keep('Hb 10.2 g/dL', 'lab')}</td>\n"
                   f"Display name (OCR): {homo}\n"
                   f"Copied from chat: {zw} — {c.keep('Metformin 500 mg 1-0-1', 'medication', trap='dose')}\n").encode("utf-8")
        self.add(fr)
        p = P[23].p
        fr = FileRec("misc/escaped_export.json", b"", "json", category="hidden")
        c = self.unit(fr, "doc", P[23])
        obj = {"record": {"naam": c.name(p, "full", "deva"), "sampark": c.phone(p, 0), "nidan": c.keep("Typhoid fever", "diagnosis")}}
        fr.data = json.dumps(obj, ensure_ascii=True).encode("utf-8")  # Devanagari as \\uXXXX escapes
        self.add(fr)

        # ---- canaries (names in no list; context only) ----
        cans = CANARIES[:5]

        def can(c: Ctx, idx: int, channel: str = "content", form: str = "full") -> tuple[str, str]:
            full, g, s = cans[idx]
            pid = f"CANARY-{idx}"
            if pid not in self.canary_ids:
                self.canary_ids.append(pid)
            surf = full if form == "full" else g
            c._ent("CANARY", full, pid, "patient", "latin", channel, "name", True, tokens=[g.lower(), s.lower()], full=True, canary=True)
            ph = self.rdig(10, "6789")
            c._ent("PHONE", ph, pid, "patient", "latin", channel, "digits", True, key=ph, canary=True)
            return surf, ph
        # 1. gate pass log (no "Name:" label)
        fr = FileRec("notes/gate_pass_register.txt", b"", "text", category="hidden")
        c = self.unit(fr, "doc", None)
        n0, ph0 = can(c, 0)
        fr.data = (f"GATE PASS REGISTER - Ward 3 (Medicine)\n"
                   f"21:40 pass issued to {n0} (brother of bed 12), {ph0[:5]} {ph0[5:]}, returned 22:15\n").encode("utf-8")
        c.u.entities[-1]["surface"] = f"{ph0[:5]} {ph0[5:]}"
        self.add(fr)
        # 2. helpdesk JSON with an unknown key
        fr = FileRec("misc/helpdesk_queue.json", b"", "json", category="hidden")
        c = self.unit(fr, "doc", None)
        n1, ph1 = can(c, 1)
        fr.data = json.dumps({"queue": [{"ticket": 4471, "summary": f"{n1} wants refund of lab fees, ring back {ph1}",
                                         "status": "open"}]}, indent=2).encode("utf-8")
        self.add(fr)
        # 3. base64 scanned consent
        fr = FileRec("misc/scanned_consent.json", b"", "json", category="hidden")
        c = self.unit(fr, "doc", None)
        n2, ph2 = can(c, 2, channel="base64")
        blob = base64.b64encode(f"I, {n2}, consent to surgery. Contact {ph2}.".encode()).decode()
        fr.data = json.dumps({"form": "consent-v1", "scan": {"mime": "text/plain", "payload": blob}}, indent=2).encode("utf-8")
        self.add(fr)
        # 4. ambulance CSV with narrative cell
        fr = FileRec("misc/ambulance_trips.csv", b"", "csv", category="hidden")
        rows = [["trip", "vehicle", "remarks"]]
        for i in range(3):
            c = self.unit(fr, f"row:{i}", None)
            if i == 1:
                n3, ph3 = can(c, 3)
                rows.append([str(700 + i), "MH-08-AB-1102", f"picked up {n3} from bus stand, attendant ph {ph3[:4]}-{ph3[4:]}"])
                c.u.entities[-1]["surface"] = f"{ph3[:4]}-{ph3[4:]}"
            else:
                rows.append([str(700 + i), "MH-08-AB-1102", "inter-facility transfer"])
        fr.data = self._csv(rows, ",").encode("utf-8")
        self.add(fr)
        # 5. Hinglish canary with honorific only
        fr = FileRec("notes/night_shift_handover.txt", b"", "text", category="hidden")
        c = self.unit(fr, "doc", None)
        n4, ph4 = can(c, 4)
        fr.data = (f"Raat 2 baje {n4} ji ka phone aaya tha ({ph4}), unke bhai ke liye bed poocha.\n"
                   "Koi patient issue nahi.\n").encode("utf-8")
        self.add(fr)

    # ---------------------------------------------------------------- malformed / unsupported
    def gen_malformed(self) -> None:
        P = self.patients

        def bad(path: str, fmt: str, data: bytes, pt: Patient | None, ents: list[tuple[str, str]]) -> None:
            fr = FileRec(path, data, fmt, expect="either", category="malformed")
            if pt is not None:
                c = self.unit(fr, "@file", None)
                for typ, surf in ents:
                    if typ == "NAME":
                        c.name(pt.p, surface=surf)
                    else:
                        c.digits(typ, surf, pt.p)
            self.add(fr)
        p = P[24].p
        bad("misc/truncated_visit.json", "json", f'{{"pt": {{"nm": "{p.given} {p.sur}", "cell": "{p.phone}", "dx": "Typh'.encode(),
            P[24], [("NAME", f"{p.given} {p.sur}"), ("PHONE", p.phone)])
        p = P[25].p
        bad("misc/cda_discharge.xml", "xml",
            (f'<?xml version="1.0"?><ClinicalDocument><recordTarget><patientRole><id extension="{p.aadhaar}" root="2.16.356"/>'
             f"<patient><name>{p.given} {p.sur}</name></patient></patientRole></recordTarget></ClinicalDocument>").encode(),
            P[25], [("NAME", f"{p.given} {p.sur}"), ("AADHAAR", p.aadhaar)])
        p = P[26].p
        bad("misc/scan_0042.pdf", "pdf",
            (f"%PDF-1.4\n1 0 obj<</Type/Catalog>>endobj\nBT /F1 12 Tf ({p.given} {p.sur} Mob {p.phone}) Tj ET\n%%EOF\n").encode(),
            P[26], [("NAME", f"{p.given} {p.sur}"), ("PHONE", p.phone)])
        p = P[27].p
        bad("misc/rx_photo.jpg", "binary", b"\xff\xd8\xff\xe0\x00\x10JFIF\x00" + f"Comment: {p.given} {p.sur}".encode() + bytes(range(256)),
            P[27], [("NAME", f"{p.given} {p.sur}")])
        bad("misc/empty_dump.csv", "csv", b"", None, [])
        p = P[28].p
        bad("misc/garbled_note.txt", "text", f"Patient {p.given} {p.sur} ph {p.phone} ".encode() + b"\xc3\x28\xa0\xa1 bad bytes\xff\n",
            P[28], [("NAME", f"{p.given} {p.sur}"), ("PHONE", p.phone)])
        p = P[29].p
        bad("misc/export_mislabeled.csv", "json", json.dumps({"rows": [{"name": f"{p.given} {p.sur}", "mobile": p.phone}]}).encode(),
            P[29], [("NAME", f"{p.given} {p.sur}"), ("PHONE", p.phone)])
        p = P[30].p
        deep: Any = {"name": f"{p.given} {p.sur}", "mobile": p.phone}
        for _ in range(1500):
            deep = {"n": deep}
        old = sys.getrecursionlimit()
        sys.setrecursionlimit(10000)
        try:
            deep_bytes = json.dumps(deep).encode()
        finally:
            sys.setrecursionlimit(old)
        bad("misc/nested_export.json", "json", deep_bytes, P[30], [("NAME", f"{p.given} {p.sur}"), ("PHONE", p.phone)])
        p = P[31].p
        zb = io.BytesIO()
        with zipfile.ZipFile(zb, "w") as z:
            z.writestr("xl/sharedStrings.xml", f"<sst><si><t>{p.given} {p.sur}</t></si><si><t>{p.phone}</t></si></sst>")
        bad("misc/ward_list.xlsx", "binary", zb.getvalue(), P[31], [("NAME", f"{p.given} {p.sur}"), ("PHONE", p.phone)])

    # ---------------------------------------------------------------- truth + attacker
    def finalize(self, out: Path) -> None:
        inp = out / "dev" / "input"
        if out.exists():
            shutil.rmtree(out)
        inp.mkdir(parents=True)
        (out / "dev" / "truth").mkdir(parents=True)
        (out / "dev" / "attacker").mkdir(parents=True)
        if (KIT / "scoring.toml").is_file():
            shutil.copy(KIT / "scoring.toml", out / "scoring.toml")

        # linkability: units of one patient connect through evidence keys unique to that patient
        all_units = [(rel, u) for rel, fr in self.files.items() for u in fr.units.values() if u.patient]
        pmap = {pt.key: pt for pt in self.patients}
        for _rel, u in all_units:
            p = pmap[u.patient].p
            f = u.flags
            if f.get("name_full") and f.get("dob"):
                u.keys.add(("ndob", p.canon, p.dob.isoformat()))
            if (f.get("name_full") or f.get("name_given")) and f.get("rel"):
                u.keys.add(("nrel", p.given.lower(), p.rel.given.lower()))
            if f.get("name_full") and f.get("village") and f.get("age"):
                u.keys.add(("nva", p.canon, p.village[0].lower(), p.age))
        owners: dict[tuple, set[str]] = {}
        for _rel, u in all_units:
            for k in u.keys:
                owners.setdefault(k, set()).add(u.patient)
        parent: dict[int, int] = {}

        def find(x: int) -> int:
            while parent.setdefault(x, x) != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x
        first_by_key: dict[tuple, int] = {}
        for i, (_rel, u) in enumerate(all_units):
            find(i)
            for k in u.keys:
                if len(owners[k]) != 1:
                    continue
                if k in first_by_key:
                    parent[find(i)] = find(first_by_key[k])
                else:
                    first_by_key[k] = i
        comp_size: dict[int, int] = {}
        for i in range(len(all_units)):
            comp_size[find(i)] = comp_size.get(find(i), 0) + 1
        best_comp: dict[str, int] = {}
        for i, (_rel, u) in enumerate(all_units):
            rt = find(i)
            cur = best_comp.get(u.patient)
            if cur is None or comp_size[rt] > comp_size[cur]:
                best_comp[u.patient] = rt
        n_req = n_amb = 0
        for i, (_rel, u) in enumerate(all_units):
            if find(i) == best_comp[u.patient] and comp_size[find(i)] >= 2:
                u.link = "required"
                n_req += 1
            else:
                u.link = "ambiguous"
                n_amb += 1

        files_json: dict[str, Any] = {}
        for rel in sorted(self.files):
            fr = self.files[rel]
            dest = inp / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(fr.data)
            files_json[rel] = {
                "path": rel, "format": fr.fmt, "encoding": fr.encoding, "delimiter": fr.delimiter, "expect": fr.expect,
                "category": fr.category, "clean": fr.clean, "date_hint": fr.date_hint,
                "sha256": hashlib.sha256(fr.data).hexdigest(), "size": len(fr.data), "generalizable": fr.generalizable,
                "units": {loc: u.to_json() for loc, u in fr.units.items()},
            }
        traps = {
            "language": [pt.key for pt in self.patients if "language" in pt.traps],
            "fragmented": [pt.key for pt in self.patients if "fragmented" in pt.traps],
            "meaning": [pt.key for pt in self.patients if "meaning" in pt.traps],
            "reidentification": [pt.key for pt in self.patients if any(t.startswith("reid") for t in pt.traps)],
            "homonym_pairs": [[self.patients[0].key, self.patients[2].key], [self.patients[4].key, self.patients[6].key]],
            "family_phone": [self.patients[10].key, self.patients[11].key],
            "reregistration": [self.patients[12].key],
        }
        truth = {
            "schema": "raksha-truth/1", "generator_version": "gauntlet-1.0", "seed": f"gauntlet-{self.seed}-{self.pool}",
            "profile": "gauntlet", "chaos": True, "ref_date": REF_DATE.isoformat(), "files": files_json,
            "patients": {pt.key: {"rid": pt.p.rid, "pid": pt.p.pid, "hospitals": pt.hosps, "uhids": pt.uhids, "traps": pt.traps}
                         for pt in self.patients},
            "traps": traps, "linkability": {"required_units": n_req, "ambiguous_units": n_amb},
            "canaries": self.canary_ids,
        }
        (out / "dev" / "truth" / "truth.json").write_text(json.dumps(truth, ensure_ascii=False, indent=1), encoding="utf-8")

        # attacker knowledge
        with open(out / "dev" / "attacker" / "registry.csv", "w", encoding="utf-8", newline="") as fh:
            w = csv.writer(fh)
            w.writerow(["rid", "name", "relation", "relative_name", "gender", "age", "house_no", "mohalla", "village",
                        "tehsil", "district", "pin", "phone", "email", "aadhaar_last4"])
            for q in sorted(self.persons, key=lambda x: x.rid):
                w.writerow([q.rid, f"{q.given} {q.sur}", q.rel_type, f"{q.rel.given} {q.rel.sur}" if q.rel else "",
                            q.gender, q.age, q.house, q.locality[0], q.village[0], q.tehsil[0], q.district[0], q.pin,
                            q.phone if q.leaked else "", q.email if q.leaked else "", q.aadhaar[-4:] if q.leaked else ""])
        facts = []
        for pt in self.patients:
            if any(t.startswith("reid") for t in pt.traps) or self.r.random() < 0.3:
                f = {"rid": pt.p.rid, "visit_dates": [pt.visits[0][0].isoformat()], "hospital": HOSPITALS[pt.visits[0][1]][0]}
                if pt.adm and any(t.startswith("reid") for t in pt.traps):
                    f["condition_hint"] = pt.adm.dx[1]
                    f["visit_dates"] = [pt.adm.adm.isoformat()]
                    f["length_of_stay"] = (pt.adm.dis - pt.adm.adm).days
                facts.append(f)
        non_pat = [q for q in self.persons if not q.pid.startswith("P")]
        for q in self.r.sample(non_pat, min(6, len(non_pat))):
            facts.append({"rid": q.rid, "visit_dates": [(REF_DATE - dt.timedelta(days=self.r.randint(20, 300))).isoformat()],
                          "hospital": HOSPITALS[self.r.choice(list(HOSPITALS))][0]})
        self.r.shuffle(facts)
        (out / "dev" / "attacker" / "known_facts.jsonl").write_text("".join(json.dumps(f) + "\n" for f in facts), encoding="utf-8")
        self._raw_baseline(out)
        manifest = {"files": len(self.files), "patients": len(self.patients), "registry": len(self.persons),
                    "required_units": n_req, "ambiguous_units": n_amb, "canaries": len(self.canary_ids), "pool": self.pool,
                    "seed": self.seed}
        (out / "dev" / "dataset_manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        print(json.dumps(manifest))

    def _raw_baseline(self, out: Path) -> None:
        """Run the local attacker on an unsanitised passthrough release -> normalisation baseline."""
        raw_path = out / "dev" / "truth" / "raw_attack.json"
        raw_path.write_text(json.dumps({"result": {}}), encoding="utf-8")
        try:
            sys.path.insert(0, str(ROOT))
            from tools.local_attacker import run_attack  # noqa: WPS433
        except Exception as exc:  # pragma: no cover
            print(f"[warn] attacker baseline skipped: {exc}")
            return
        with tempfile.TemporaryDirectory() as td:
            rel_out = Path(td)
            shutil.copytree(out / "dev" / "input", rel_out / "sanitized")
            (rel_out / "report.json").write_text(json.dumps({"files": []}), encoding="utf-8")
            try:
                res = run_attack(rel_out, out / "dev" / "truth" / "truth.json", out / "dev" / "attacker" / "registry.csv",
                                 out / "dev" / "attacker" / "known_facts.jsonl", raw_path, None)
            except Exception as exc:  # pragma: no cover
                print(f"[warn] attacker baseline failed: {exc}")
                return
        raw_path.write_text(json.dumps({"version": "gauntlet", "result": {
            "record_linkage_risk": max(res["a3_abs"], 1e-6), "patients_reidentified": max(res["a4_abs"], 1e-6),
            "targeted_success": max(res["a5_abs"], 1e-6)}}, indent=2), encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--out", required=True)
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--pool", choices=["A", "B"], default="A")
    ap.add_argument("--patients", type=int, default=44)
    ap.add_argument("--bulk", type=int, default=3000)
    a = ap.parse_args()
    if a.patients < 32:
        ap.error("--patients must be >= 32 (trap slots)")
    g = Gauntlet(a.seed, a.pool, a.patients, a.bulk)
    g.build_population()
    g.gen_registration()
    g.gen_opd()
    g.gen_admissions()
    g.gen_rx_and_labs()
    g.gen_bulk()
    g.gen_clean()
    g.gen_hidden()
    g.gen_malformed()
    g.finalize(Path(a.out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
