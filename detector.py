"""
detector.py  —  WhoisFreaks Phishing Domain Detector
=====================================================
Detects newly registered domains that suspiciously resemble known brands
using the WhoisFreaks "With WHOIS" NRD daily files (gTLD + ccTLD merged).

The NRD files already contain full WHOIS data per domain row — registrant,
registrar, dates, nameservers, and status flags. No separate API calls needed.

Workflow:
  1. Download the daily gTLD NRD file  (gzipped CSV, WHOIS embedded)
  2. Download the daily ccTLD NRD file (gzipped CSV, WHOIS embedded)
  3. Merge both into one dataset
  4. Fuzzy-match every domain against your brand list (local, no API)
  5. Score risk from WHOIS signals already in the file
  6. Print a report and save findings.json

NRD endpoints (With WHOIS):
  GET https://files.whoisfreaks.com/v3.1/download/domainer/gtld
      ?apiKey=YOUR_KEY&whois=true[&date=yyyy-MM-dd]
  GET https://files.whoisfreaks.com/v3.1/download/domainer/cctld
      ?apiKey=YOUR_KEY&whois=true[&date=yyyy-MM-dd]

Docs: https://whoisfreaks.com/documentation/newly-registered-domains
"""

import csv
import gzip
import io
import json
import re
import sys
import time
from datetime import datetime, timezone

import requests
from thefuzz import fuzz

import config

# ─────────────────────────────────────────────────────────
#  Constants
# ─────────────────────────────────────────────────────────

NRD_BASE = "https://files.whoisfreaks.com/v3.1/download/domainer"

PRIVACY_KEYWORDS = [
    "privacy", "redacted", "protected", "proxy", "whoisguard",
    "withheld", "private", "confidential", "data protected",
    "data redacted", "not disclosed", "gdpr", "masked",
]

NOISE_WORDS = {
    "account", "accounts", "secure", "security", "login", "signin",
    "sign", "verify", "verification", "support", "update", "updates",
    "official", "online", "service", "services", "portal", "help",
    "center", "centre", "my", "get", "the", "new", "web", "site",
    "page", "app", "apps", "access", "activate", "activation",
    "confirm", "confirmation", "customer", "care", "info",
}

TLD_PATTERN = re.compile(
    r'\.(com|net|org|io|co|info|biz|online|site|app|xyz|store|shop|'
    r'uk|us|ca|au|de|fr|in|pk|eu|me|dev|ai|tech|digital|live|club|'
    r'pro|vip|top|click|link|email|mail|pay|bank|card|one|fit|icu|'
    r'top|rentals|bond|ru|cn|jp|br|nl|es|pl|se|no|dk|fi|be|at|ch|'
    r'nz|sg|hk|tw|kr|mx|ar|za|ng|ke|gh)$',
    re.IGNORECASE,
)

LABEL_COLORS = {
    "CRITICAL": "\033[91m",
    "HIGH":     "\033[93m",
    "MEDIUM":   "\033[94m",
    "LOW":      "\033[92m",
    "RESET":    "\033[0m",
}


# ─────────────────────────────────────────────────────────
#  Step 1 & 2 — Download gTLD + ccTLD files and merge
# ─────────────────────────────────────────────────────────

def download_nrd_file(tld_type: str, date: str | None) -> list[dict]:
    """
    Download one NRD With-WHOIS gzipped CSV file and return parsed rows.

    tld_type : "gtld" or "cctld"
    date     : "yyyy-MM-dd" or None for the most recent available file
    """
    url    = f"{NRD_BASE}/{tld_type}"
    params = {"apiKey": config.API_KEY, "whois": "true"}
    if date:
        params["date"] = date

    date_label = date or "latest"
    print(f"  Downloading {tld_type.upper()} file ({date_label})...")

    try:
        resp = requests.get(url, params=params, timeout=300, stream=True)
    except requests.exceptions.RequestException as e:
        sys.exit(f"\n[ERROR] Network error while fetching {tld_type}: {e}")

    if resp.status_code == 401:
        sys.exit("\n[ERROR] Invalid or inactive API key. "
                 "Check config.py and your WhoisFreaks billing dashboard.")
    if resp.status_code == 403:
        sys.exit(f"\n[ERROR] Access denied for {tld_type} endpoint. "
                 "Check your subscription plan.")
    if resp.status_code == 413:
        sys.exit("\n[ERROR] API credit or plan limit exceeded. "
                 "Please upgrade your WhoisFreaks plan.")
    if resp.status_code != 200:
        sys.exit(f"\n[ERROR] HTTP {resp.status_code} for {tld_type}: "
                 f"{resp.text[:300]}")

    raw = resp.content
    print(f"    Downloaded {len(raw) / 1024 / 1024:.1f} MB")

    # Decompress
    try:
        content = gzip.decompress(raw).decode("utf-8", errors="replace")
    except gzip.BadGzipFile:
        content = raw.decode("utf-8", errors="replace")

    rows = list(csv.DictReader(io.StringIO(content)))
    print(f"    Parsed {len(rows):,} rows")
    return rows


def download_and_merge(date: str | None) -> list[dict]:
    """
    Download gTLD and ccTLD NRD files and return a single merged list.
    Duplicate domain_name entries (same domain in both files) are deduplicated.
    """
    print("[1/4] Downloading NRD files (gTLD + ccTLD)...")

    gtld_rows  = download_nrd_file("gtld",  date)
    cctld_rows = download_nrd_file("cctld", date)

    # Merge and deduplicate by domain_name
    seen   = set()
    merged = []
    for row in gtld_rows + cctld_rows:
        domain = row.get("domain_name", "").strip().lower()
        if domain and domain not in seen:
            seen.add(domain)
            merged.append(row)

    print(f"\n  Merged total: {len(merged):,} unique domains "
          f"({len(gtld_rows):,} gTLD + {len(cctld_rows):,} ccTLD, "
          f"{len(gtld_rows) + len(cctld_rows) - len(merged):,} duplicates removed)\n")
    return merged


# ─────────────────────────────────────────────────────────
#  Step 3 — Fuzzy similarity scoring (local, no API calls)
# ─────────────────────────────────────────────────────────

def normalize_domain(domain: str) -> str:
    """
    Strip TLD, separators, digits, and noise words to expose the
    brand-like core of a domain name for fuzzy comparison.

    Examples:
      "paypa1-secure-verify.com"  →  "paypa"
      "amaz0n-prime-deal.net"     →  "amzn"
      "netflix-account-login.io"  →  "netflix"
      "miconsoftonline.com"       →  "miconsoftline"
    """
    core  = TLD_PATTERN.sub("", domain.lower())
    parts = re.split(r"[-_.]", core)
    parts = [re.sub(r"\d", "", p) for p in parts]   # strip digits within tokens
    parts = [p for p in parts if p and p not in NOISE_WORDS]
    return "".join(parts)


def score_domain(domain: str) -> tuple[int, str]:
    """Return (best_score 0-100, matched_brand) against all configured brands."""
    normalized = normalize_domain(domain)
    if not normalized:
        return 0, ""

    best_score, best_brand = 0, ""
    for brand in config.BRANDS:
        score = max(
            fuzz.ratio(normalized, brand),
            fuzz.partial_ratio(normalized, brand),
            fuzz.token_sort_ratio(normalized, brand),
        )
        if score > best_score:
            best_score, best_brand = score, brand

    return best_score, best_brand


def find_candidates(rows: list[dict]) -> list[dict]:
    """
    Score every domain in the merged NRD dataset.
    Returns rows that exceed the similarity threshold, with WHOIS fields attached.
    """
    total = len(rows)
    print(f"[2/4] Scoring all {total:,} domains "
          f"(threshold ≥ {config.SIMILARITY_THRESHOLD}%)...")

    candidates = []
    for i, row in enumerate(rows, 1):
        if i % 50000 == 0:
            print(f"    ...{i:,} / {total:,} scored")

        domain = row.get("domain_name", "").strip().lower()
        if not domain:
            continue

        score, brand = score_domain(domain)
        if score < config.SIMILARITY_THRESHOLD:
            continue

        candidates.append({
            "domain":             domain,
            "score":              score,
            "matched_brand":      brand,
            # WHOIS fields already embedded in the NRD file row
            "create_date":        row.get("create_date", ""),
            "expiry_date":        row.get("expiry_date", ""),
            "registrar":          row.get("domain_registrar_name", ""),
            "registrar_url":      row.get("domain_registrar_url", ""),
            "registrant_name":    row.get("registrant_name", ""),
            "registrant_country": row.get("registrant_country", ""),
            "registrant_country_code": row.get("registrant_country_code", ""),
            "registrant_email":   row.get("registrant_email", ""),
            "ns1":                row.get("name_server_1", ""),
            "ns2":                row.get("name_server_2", ""),
            "status1":            row.get("domain_status_1", ""),
            "status2":            row.get("domain_status_2", ""),
        })

    print(f"    {len(candidates)} candidates found.\n")
    return candidates


# ─────────────────────────────────────────────────────────
#  Step 4 — Risk scoring from embedded WHOIS fields
# ─────────────────────────────────────────────────────────

def calculate_risk(c: dict) -> tuple[int, str]:
    """
    Combine similarity score + WHOIS signals into a 0-100 risk score.

    Points breakdown:
      Similarity score     → up to 40 pts  (score × 0.4)
      Domain very new      → up to 20 pts  (< 7 days = 20, < 30 days = 10)
      Privacy protection   →      15 pts
      No registrant name   →       5 pts
    """
    pts = int(c["score"] * 0.4)   # similarity → max 40

    # Domain age
    create_raw = c.get("create_date", "")
    if create_raw:
        try:
            created  = datetime.strptime(create_raw[:10], "%Y-%m-%d").replace(tzinfo=timezone.utc)
            age_days = (datetime.now(timezone.utc) - created).days
            if age_days < 7:
                pts += 20
            elif age_days < 30:
                pts += 10
        except ValueError:
            pass

    # Registrant privacy / redaction
    reg_name = c.get("registrant_name", "").lower()
    if any(kw in reg_name for kw in PRIVACY_KEYWORDS):
        pts += 15
    elif not reg_name.strip():
        pts += 5

    risk_score = min(pts, 100)
    label = (
        "CRITICAL" if risk_score >= 80 else
        "HIGH"     if risk_score >= 60 else
        "MEDIUM"   if risk_score >= 40 else
        "LOW"
    )
    return risk_score, label


def score_all_candidates(candidates: list[dict]) -> list[dict]:
    print("[3/4] Calculating risk scores...")
    for c in candidates:
        c["risk_score"], c["risk_label"] = calculate_risk(c)
    candidates.sort(key=lambda x: x["risk_score"], reverse=True)
    print(f"    Done.\n")
    return candidates


# ─────────────────────────────────────────────────────────
#  Step 5 — Report + save
# ─────────────────────────────────────────────────────────

def print_report(candidates: list[dict]) -> None:
    reset = LABEL_COLORS["RESET"]

    print("═" * 62)
    print("  PHISHING DOMAIN DETECTOR — RESULTS")
    print("═" * 62)

    if not candidates:
        print("  No suspicious domains found today. ✓")
        print("═" * 62)
        return

    for c in candidates:
        col = LABEL_COLORS.get(c["risk_label"], "")
        print(f"\n  {col}[{c['risk_label']}]{reset}  {c['domain']}")
        print(f"    Similarity to '{c['matched_brand']}'  : {c['score']}%")
        print(f"    Risk score                     : {c['risk_score']}/100")
        print(f"    Registered                     : {c['create_date'] or '—'}")
        print(f"    Expires                        : {c['expiry_date'] or '—'}")
        print(f"    Registrar                      : {c['registrar'] or '—'}")
        print(f"    Registrant name                : {c['registrant_name'] or '—'}")
        print(f"    Registrant country             : {c['registrant_country'] or '—'}")
        print(f"    Nameservers                    : {c['ns1'] or '—'}  {c['ns2'] or ''}")
        print(f"    Domain status                  : {c['status1'] or '—'}")

    total    = len(candidates)
    critical = sum(1 for c in candidates if c["risk_label"] == "CRITICAL")
    high     = sum(1 for c in candidates if c["risk_label"] == "HIGH")
    medium   = sum(1 for c in candidates if c["risk_label"] == "MEDIUM")
    low      = sum(1 for c in candidates if c["risk_label"] == "LOW")

    print("\n" + "═" * 62)
    print(
        f"  Total : {total}   "
        f"{LABEL_COLORS['CRITICAL']}CRITICAL: {critical}{reset}   "
        f"{LABEL_COLORS['HIGH']}HIGH: {high}{reset}   "
        f"MEDIUM: {medium}   LOW: {low}"
    )
    print("═" * 62)


def save_findings(candidates: list[dict], path: str = "findings.json") -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(candidates, f, indent=2, ensure_ascii=False)
    print(f"\n  Findings saved → {path}  ({len(candidates)} records)")


# ─────────────────────────────────────────────────────────
#  Main
# ─────────────────────────────────────────────────────────

def main():
    print("\n╔══════════════════════════════════════════════════╗")
    print("║   WhoisFreaks Phishing Domain Detector           ║")
    print("║   Powered by WhoisFreaks NRD With-WHOIS Feed     ║")
    print("╚══════════════════════════════════════════════════╝\n")

    if config.API_KEY == "YOUR_API_KEY_HERE":
        sys.exit("[ERROR] Please set your API_KEY in config.py before running.")

    # Steps 1 & 2 — Download gTLD + ccTLD and merge
    rows = download_and_merge(date=config.FETCH_DATE)

    if not rows:
        sys.exit("[ERROR] No rows after merging. "
                 "Check your API key and subscription.")

    # Step 3 — Score all domains (no API calls — pure local fuzzy matching)
    candidates = find_candidates(rows)

    if not candidates:
        print("  No candidates above threshold. All clear!")
        return

    # Step 4 — Risk score from embedded WHOIS fields
    candidates = score_all_candidates(candidates)

    # Step 5 — Report + save
    print("[4/4] Generating report...")
    print_report(candidates)
    save_findings(candidates)


if __name__ == "__main__":
    main()
