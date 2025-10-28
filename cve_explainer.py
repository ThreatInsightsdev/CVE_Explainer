#!/usr/bin/env python3
"""
CVE → Plain‑English Business Impact Explainer
---------------------------------------------
Given a CVE ID, this script pulls NVD, EPSS, and CISA KEV data and produces a
concise, business‑friendly report:
- What it is (plain English)
- How likely it is to be exploited (EPSS + KEV)
- What it affects (vendor/products from NVD CPEs)
- How it’s exploited (CVSS vector explained in human terms)
- Example attack scenario
- What to patch / mitigate (prioritised actions)
- Triage priority (P1/P2/P3) based on a simple, transparent rubric

Usage:
    python cve_explainer.py CVE-2023-12345 --save report.md
    python cve_explainer.py CVE-2023-12345 --json
    python cve_explainer.py CVE-2023-12345 --nvd-api-key YOUR_KEY

You can also pass multiple CVEs:
    python cve_explainer.py CVE-2023-12345 CVE-2024-11111 --save portfolio.md

No external DB required. HTTP-only. Designed for GitHub-friendly OSS use.
Provided by ThreatInsights - https://threatinsights.net
"""

from __future__ import annotations
import argparse
import datetime as dt
import json
import os
import sys
from typing import Any, Dict, List, Optional, Tuple

import requests

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_URL = "https://api.first.org/data/v1/epss"
# CISA KEV JSON feed (URL stable but can change over time; make overridable via env)
KEV_URL = os.environ.get(
    "KEV_URL",
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
)

# Optional: quick check against Exploit-DB mapping (community CSV). This is
# a best-effort signal only; do not block if fails.
EXPLOITDB_CSV = os.environ.get(
    "EXPLOITDB_CSV",
    "https://raw.githubusercontent.com/offensive-security/exploitdb/master/files_exploits.csv",
)


def fetch_json(url: str, params: Optional[dict] = None, headers: Optional[dict] = None, timeout: int = 20) -> Optional[dict]:
    try:
        r = requests.get(url, params=params, headers=headers, timeout=timeout)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        return None


def get_nvd(cve: str, api_key: Optional[str] = None) -> Optional[dict]:
    headers = {"apiKey": api_key} if api_key else None
    return fetch_json(NVD_URL, params={"cveId": cve}, headers=headers)


def get_epss(cve: str) -> Tuple[Optional[float], Optional[float]]:
    js = fetch_json(EPSS_URL, params={"cve": cve})
    try:
        if js and js.get("data"):
            score = float(js["data"][0]["epss"])
            perc = float(js["data"][0]["percentile"])
            return score, perc
    except Exception:
        pass
    return None, None


def load_kev() -> List[dict]:
    js = fetch_json(KEV_URL)
    if not js:
        return []
    # Support both direct list & CISA JSON object structure
    if isinstance(js, dict):
        vulns = js.get("vulnerabilities") or js.get("known_exploited_vulnerabilities") or []
        if isinstance(vulns, list):
            return vulns
    if isinstance(js, list):
        return js
    return []


def kev_contains(cve: str, kev_list: List[dict]) -> Optional[dict]:
    cve_up = cve.upper()
    for item in kev_list:
        if str(item.get("cveID") or item.get("cve_id") or "").upper() == cve_up:
            return item
    return None


def get_exploitdb_hit(cve: str) -> bool:
    try:
        r = requests.get(EXPLOITDB_CSV, timeout=20)
        r.raise_for_status()
        needle = cve.upper()
        return needle in r.text.upper()
    except Exception:
        return False


def parse_nvd(nvd_json: dict, cve: str) -> dict:
    out = {
        "cve": cve,
        "title": None,
        "description": None,
        "cvss": {},
        "cwe": None,
        "published": None,
        "last_modified": None,
        "vendors_products": [],
        "references": [],
    }
    items = nvd_json.get("vulnerabilities") or nvd_json.get("vuln") or []
    if not items:
        return out

    try:
        entry = items[0]["cve"]
    except Exception:
        return out

    # Title/Descriptions
    out["title"] = entry.get("id")
    descs = entry.get("descriptions") or []
    if descs:
        # Prefer English
        en = [d["value"] for d in descs if d.get("lang") == "en"]
        out["description"] = (en[0] if en else descs[0].get("value", "")).strip()

    # CWE
    weaknesses = entry.get("weaknesses") or []
    if weaknesses:
        for w in weaknesses:
            desc = w.get("description") or []
            en = [d["value"] for d in desc if d.get("lang") == "en"]
            if en:
                out["cwe"] = en[0]
                break

    # References
    refs = entry.get("references") or []
    out["references"] = [r.get("url") for r in refs if r.get("url")]

    # Dates
    metrics = entry.get("metrics") or {}
    published = entry.get("published")
    last_modified = entry.get("lastModified")
    out["published"] = published
    out["last_modified"] = last_modified

    # CVSS (v3 preferred)
    cvss = {}
    for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        vals = metrics.get(key)
        if vals:
            primary = vals[0]
            cv = primary.get("cvssData") or {}
            cvss = {
                "version": cv.get("version"),
                "baseScore": primary.get("cvssData", {}).get("baseScore"),
                "baseSeverity": primary.get("cvssData", {}).get("baseSeverity") or primary.get("baseSeverity"),
                "vectorString": primary.get("cvssData", {}).get("vectorString"),
                "attackVector": cv.get("attackVector"),
                "attackComplexity": cv.get("attackComplexity"),
                "privilegesRequired": cv.get("privilegesRequired"),
                "userInteraction": cv.get("userInteraction"),
                "scope": cv.get("scope"),
                "confidentialityImpact": cv.get("confidentialityImpact"),
                "integrityImpact": cv.get("integrityImpact"),
                "availabilityImpact": cv.get("availabilityImpact"),
            }
            break
    out["cvss"] = cvss

    # CPE - vendors/products
    cpes = []
    configs = entry.get("configurations") or []
    for c in configs:
        nodes = c.get("nodes") or []
        for n in nodes:
            matches = n.get("cpeMatch") or []
            for m in matches:
                uri = m.get("criteria") or m.get("cpe23Uri")
                if not uri:
                    continue
                parts = uri.split(":")
                # cpe:2.3:a:vendor:product:version:...
                if len(parts) >= 5:
                    vendor = parts[3]
                    product = parts[4]
                    version = parts[5] if len(parts) > 5 else "*"
                    cpes.append({"vendor": vendor, "product": product, "version": version, "vulnerable": m.get("vulnerable", True)})
    # Deduplicate
    seen = set()
    vp = []
    for item in cpes:
        key = (item["vendor"], item["product"])
        if key in seen:
            continue
        seen.add(key)
        vp.append({"vendor": item["vendor"], "product": item["product"]})
    out["vendors_products"] = vp

    return out


def cvss_to_plain_english(cvss: dict) -> str:
    if not cvss:
        return "No CVSS vector available. Treat with caution and review vendor advisories."
    parts = []

    severity = cvss.get("baseSeverity") or "UNKNOWN"
    score = cvss.get("baseScore")
    if score is not None:
        parts.append(f"Severity is {severity} (CVSS {score}/10).")
    else:
        parts.append(f"Severity is {severity}.")

    av = cvss.get("attackVector")
    if av == "NETWORK":
        parts.append("Exploitable over the network (no local access required).")
    elif av == "ADJACENT_NETWORK":
        parts.append("Requires same network segment or limited network proximity.")
    elif av == "LOCAL":
        parts.append("Requires local access to the system.")
    elif av == "PHYSICAL":
        parts.append("Requires physical access to the device.")

    ac = cvss.get("attackComplexity")
    if ac == "LOW":
        parts.append("Attack complexity is low (straightforward to exploit).")
    elif ac == "HIGH":
        parts.append("Attack complexity is high (conditions must align).")

    pr = cvss.get("privilegesRequired")
    if pr == "NONE":
        parts.append("No prior privileges needed to exploit.")
    elif pr == "LOW":
        parts.append("Requires basic user-level privileges.")
    elif pr == "HIGH":
        parts.append("Requires high privileges (e.g., admin).")

    ui = cvss.get("userInteraction")
    if ui == "NONE":
        parts.append("No user interaction is needed.")
    elif ui == "REQUIRED":
        parts.append("User interaction is required (e.g., click a link/open file).")

    cia_map = {
        "confidentialityImpact": "confidentiality",
        "integrityImpact": "integrity",
        "availabilityImpact": "availability",
    }
    impacts = []
    for k, label in cia_map.items():
        v = cvss.get(k)
        if v == "HIGH":
            impacts.append(f"high {label} impact")
        elif v == "LOW":
            impacts.append(f"low {label} impact")
    if impacts:
        parts.append("Expected impact: " + ", ".join(impacts) + ".")

    return " ".join(parts)


def build_example_scenario(description: Optional[str], cwe: Optional[str], cvss: dict) -> str:
    # Heuristic narrative builder
    scenario_bits = []

    if description:
        scenario_bits.append("A vulnerable component handles input incorrectly, leading to unexpected behaviour.")
    if cwe:
        if "injection" in cwe.lower():
            scenario_bits.append("An attacker sends crafted input to inject commands or queries.")
        if "xss" in cwe.lower() or "cross-site scripting" in cwe.lower():
            scenario_bits.append("A victim visits a malicious page or link, executing attacker-controlled script in the browser.")
        if "path traversal" in cwe.lower():
            scenario_bits.append("The attacker abuses file path handling to read or write unintended files.")
        if "deserial" in cwe.lower():
            scenario_bits.append("The attacker supplies a malicious object that triggers code execution on deserialisation.")

    av = (cvss or {}).get("attackVector")
    ui = (cvss or {}).get("userInteraction")
    pr = (cvss or {}).get("privilegesRequired")

    if av == "NETWORK" and (ui in (None, "NONE")) and (pr in (None, "NONE")):
        scenario_bits.append("They can do this remotely over the internet without any user action.")
    if ui == "REQUIRED":
        scenario_bits.append("The attack requires a user to click a link or open a file.")
    if pr == "LOW":
        scenario_bits.append("Minimal existing access (e.g., normal user account) is needed to trigger the flaw.")
    if pr == "HIGH":
        scenario_bits.append("The attacker must already have admin-level access to succeed (privilege escalation likely limited).")

    if not scenario_bits:
        scenario_bits.append("An attacker exploits the flaw under certain conditions described in vendor guidance.")

    return " ".join(scenario_bits)


def pick_priority(cvss: dict, epss: Optional[float], kev_hit: bool) -> Tuple[str, str]:
    """
    Simple & transparent rubric:
    - P1 (Urgent): KEV-listed OR (CVSS >= 9.0 and EPSS >= 0.5)
    - P2 (High): CVSS >= 7.0 OR EPSS >= 0.35
    - P3 (Medium): CVSS >= 4.0 OR EPSS >= 0.10
    - P4 (Low): everything else
    """
    score = (cvss or {}).get("baseScore") or 0.0
    try:
        score = float(score)
    except Exception:
        score = 0.0
    e = epss or 0.0

    if kev_hit or (score >= 9.0 and e >= 0.5):
        return "P1 (Urgent)", "Known exploited or highly likely to be exploited. Patch immediately; apply interim controls today."
    if score >= 7.0 or e >= 0.35:
        return "P2 (High)", "Serious risk; schedule patching within 7 days and monitor for exploitation indicators."
    if score >= 4.0 or e >= 0.10:
        return "P3 (Medium)", "Moderate risk; remediate in the next patch cycle and implement monitoring."
    return "P4 (Low)", "Lower risk; address during normal maintenance windows."


def mitigation_guidance(cvss: dict, vendors_products: List[dict]) -> List[str]:
    hints = []
    if vendors_products:
        prods = ", ".join({f"{vp['vendor']}:{vp['product']}" for vp in vendors_products})
        hints.append(f"Identify affected assets running: {prods}.")
    if cvss.get("attackVector") == "NETWORK":
        hints.append("If patching is delayed, reduce exposure: restrict internet-facing access, apply WAF/IPS virtual patches, and tighten firewall rules.")
    if cvss.get("userInteraction") == "REQUIRED":
        hints.append("Warn users and enable email/URL filtering to block malicious links or attachments.")
    if cvss.get("privilegesRequired") in ("NONE", "LOW"):
        hints.append("Increase authentication hardening (MFA, least privilege, device posture) to limit blast radius.")
    hints.append("Apply vendor patches/updates and confirm versions post‑update.")
    hints.append("Add detection rules for known indicators and technique patterns; review logs for suspicious activity since the published date.")
    return hints


def md_report(data: dict) -> str:
    lines = []
    lines.append(f"# {data['cve']} — Plain‑English Explainer")
    if data.get("nvd", {}).get("title"):
        lines.append(f"**Title:** {data['nvd']['title']}")
    if data.get("nvd", {}).get("description"):
        lines.append(f"\n**What is it?** {data['nvd']['description']}")
    if data.get("nvd", {}).get("published"):
        pub = data['nvd']['published']
        lines.append(f"**Published:** {pub}")
    if data.get("nvd", {}).get("last_modified"):
        lines.append(f"**Last Modified:** {data['nvd']['last_modified']}")

    # Risk snapshot
    cvss = data.get("nvd", {}).get("cvss", {})
    epss = data.get("epss", {}).get("score")
    kev = data.get("kev", {}).get("present", False)
    exploitdb = data.get("exploitdb", False)

    lines.append("\n## Risk Snapshot")
    pe = cvss_to_plain_english(cvss)
    lines.append(f"- {pe}")
    if epss is not None:
        lines.append(f"- **EPSS:** {epss:.3f} (probability of exploitation); percentile {data['epss'].get('percentile', 0.0):.3f}")
    if kev:
        lines.append("- **CISA KEV:** Listed (evidence of exploitation in the wild).")
    else:
        lines.append("- **CISA KEV:** Not listed at time of lookup.")
    if exploitdb:
        lines.append("- **Exploit-DB:** Public exploit reference found.")
    else:
        lines.append("- **Exploit-DB:** No direct mapping found (best-effort check).")

    # Affected
    vps = data.get("nvd", {}).get("vendors_products", [])
    if vps:
        lines.append("\n## Affected Vendors / Products")
        for vp in vps[:20]:
            lines.append(f"- {vp['vendor']} : {vp['product']}")
        if len(vps) > 20:
            lines.append(f"- (+{len(vps)-20} more)")

    # Scenario
    scenario = build_example_scenario(
        data.get("nvd", {}).get("description"),
        data.get("nvd", {}).get("cwe"),
        cvss
    )
    lines.append("\n## Example Attack Scenario")
    lines.append(scenario)

    # Priority
    prio, rationale = pick_priority(cvss, epss, kev)
    lines.append("\n## Triage Priority")
    lines.append(f"**{prio}** — {rationale}")

    # Mitigation
    lines.append("\n## What to Do (Prioritised)")
    for i, step in enumerate(mitigation_guidance(cvss, vps), 1):
        lines.append(f"{i}. {step}")

    # References
    refs = data.get("nvd", {}).get("references", [])
    if refs:
        lines.append("\n## References")
        for r in refs[:20]:
            lines.append(f"- {r}")
        if len(refs) > 20:
            lines.append(f"- (+{len(refs)-20} more)")

    # Metadata
    lines.append("\n---")
    lines.append("_Generated by CVE Plain‑English Explainer (ThreatInsights style: less noise, more clarity)._")
    return "\n".join(lines)


def json_report(data: dict) -> str:
    return json.dumps(data, indent=2, ensure_ascii=False)


def explain_cve(cve: str, nvd_api_key: Optional[str], kev_cache: Optional[List[dict]] = None) -> dict:
    nvd_raw = get_nvd(cve, api_key=nvd_api_key)
    nvd_parsed = parse_nvd(nvd_raw or {}, cve=cve)

    epss_score, epss_pct = get_epss(cve)
    kev_list = kev_cache if kev_cache is not None else load_kev()
    kev_hit = kev_contains(cve, kev_list)
    exploitdb_hit = get_exploitdb_hit(cve)

    return {
        "cve": cve,
        "nvd": nvd_parsed,
        "epss": {"score": epss_score, "percentile": epss_pct},
        "kev": {"present": bool(kev_hit), "entry": kev_hit},
        "exploitdb": bool(exploitdb_hit),
        "generated_at": dt.datetime.utcnow().isoformat() + "Z",
        "sources": {
            "nvd": NVD_URL,
            "epss": EPSS_URL,
            "kev": KEV_URL,
            "exploitdb_csv": EXPLOITDB_CSV,
        },
    }


def main():
    ap = argparse.ArgumentParser(description="CVE → Plain‑English Business Impact Explainer")
    ap.add_argument("cve", nargs="+", help="CVE IDs, e.g., CVE-2023-12345")
    ap.add_argument("--nvd-api-key", default=os.environ.get("NVD_API_KEY"), help="Optional NVD API key for higher rate limits.")
    ap.add_argument("--json", action="store_true", help="Output JSON instead of Markdown.")
    ap.add_argument("--save", help="Save output to file (e.g., report.md). If multiple CVEs, a portfolio report is created.")
    args = ap.parse_args()

    kev_cache = load_kev()
    results = []
    for cve in args.cve:
        results.append(explain_cve(cve, nvd_api_key=args.nvd_api_key, kev_cache=kev_cache))

    if args.json:
        if len(results) == 1:
            out = json_report(results[0])
        else:
            out = json.dumps(results, indent=2, ensure_ascii=False)
    else:
        if len(results) == 1:
            out = md_report(results[0])
        else:
            # Portfolio: minimal header + per-CVE sections
            parts = ["# CVE Portfolio — Plain‑English Explainers"]
            for r in results:
                parts.append(md_report(r))
                parts.append("\n")
            out = "\n".join(parts)

    if args.save:
        with open(args.save, "w", encoding="utf-8") as f:
            f.write(out)
        print(f"Saved to {args.save}")
    else:
        print(out)


if __name__ == "__main__":
    main()
