# Phishing Domain Detector

A Python tool that detects newly registered domains resembling known brands using the [WhoisFreaks](https://whoisfreaks.com) Newly Registered Domains (NRD) feed.

Every day, attackers register hundreds of lookalike domains — `paypa1-verify.com`, `amaz0n-support.net` — to run phishing campaigns. This tool scans the full daily NRD feed, scores every domain for brand similarity, and flags suspicious ones before they are used in an attack.

## How It Works

```
Download gTLD + ccTLD NRD files (WHOIS already embedded)
                    |
        Merge into one dataset
                    |
   Fuzzy-match every domain against your brand list
         (runs locally, zero extra API calls)
                    |
    Score risk from similarity + WHOIS signals
                    |
     Print report + save findings.json
```

WhoisFreaks NRD files ship with full WHOIS data embedded per row — registrant name, registrar, registration date, nameservers, and domain status. There is no need to call a separate WHOIS API for each domain. One download covers the entire day's global registrations.

## Requirements

- Python 3.10+
- A [WhoisFreaks](https://whoisfreaks.com) API key with NRD access

## Installation

```bash
git clone https://github.com/WhoisFreaks/phishing-domain-detector.git
cd phishing-domain-detector
pip install -r requirements.txt
```

## Configuration

Open `config.py` and set your values:

```python
API_KEY = "your_whoisfreaks_api_key"

BRANDS = [
    "yourbrand",
    "yourproduct",
]

SIMILARITY_THRESHOLD = 70   # 0-100, lower means more results
FETCH_DATE = None            # None = most recent; or "2026-06-07"
```

| Setting | Description |
|---|---|
| `API_KEY` | Your WhoisFreaks API key |
| `BRANDS` | List of brand names to protect, lowercase, no TLD |
| `SIMILARITY_THRESHOLD` | Minimum fuzzy similarity score to flag a domain (default: 70) |
| `FETCH_DATE` | Date to fetch in `yyyy-MM-dd` format, or `None` for the latest file |

## Usage

```bash
python detector.py
```

The script will:
1. Download the gTLD file (`.com`, `.net`, `.org`, `.io`, etc.)
2. Download the ccTLD file (`.uk`, `.de`, `.pk`, `.ca`, etc.)
3. Merge and deduplicate both datasets
4. Score every domain against your brand list
5. Print a color-coded report to the console
6. Save all findings to `findings.json`

## Sample Output

```
╔══════════════════════════════════════════════════╗
║   WhoisFreaks Phishing Domain Detector           ║
║   Powered by WhoisFreaks NRD With-WHOIS Feed     ║
╚══════════════════════════════════════════════════╝

[1/4] Downloading NRD files (gTLD + ccTLD)...
  Downloading GTLD file (latest)...
    Downloaded 18.4 MB
    Parsed 142,803 rows
  Downloading CCTLD file (latest)...
    Downloaded 6.1 MB
    Parsed 48,204 rows

  Merged total: 190,891 unique domains (142,803 gTLD + 48,204 ccTLD, 116 duplicates removed)

[2/4] Scoring all 190,891 domains (threshold >= 70%)...
    ...50,000 / 190,891 scored
    ...100,000 / 190,891 scored
    ...150,000 / 190,891 scored
    312 candidates found.

[3/4] Calculating risk scores...
    Done.

[4/4] Generating report...
══════════════════════════════════════════════════════════════
  PHISHING DOMAIN DETECTOR - RESULTS
══════════════════════════════════════════════════════════════

  [CRITICAL]  paypa1-verify-account.com
    Similarity to 'paypal'  : 88%
    Risk score              : 91/100
    Registered              : 2026-06-06
    Expires                 : 2027-06-06
    Registrar               : Porkbun LLC
    Registrant name         : REDACTED FOR PRIVACY
    Registrant country      : United States
    Nameservers             : ns1.porkbun.com  ns2.porkbun.com
    Domain status           : clienttransferprohibited

  [HIGH]  amaz0n-prime-renewal.net
    Similarity to 'amazon'  : 83%
    Risk score              : 67/100
    ...

══════════════════════════════════════════════════════════════
  Total : 312   CRITICAL: 18   HIGH: 74   MEDIUM: 156   LOW: 64
══════════════════════════════════════════════════════════════

  Findings saved -> findings.json  (312 records)
```

## Risk Score Breakdown

Each flagged domain gets a risk score from 0 to 100 based on three signals:

| Signal | Points |
|---|---|
| Brand similarity score | Up to 40 pts (score x 0.4) |
| Domain registered less than 7 days ago | 20 pts |
| Domain registered less than 30 days ago | 10 pts |
| Privacy-protected registrant | 15 pts |
| No registrant name at all | 5 pts |

| Label | Score range |
|---|---|
| CRITICAL | 80 - 100 |
| HIGH | 60 - 79 |
| MEDIUM | 40 - 59 |
| LOW | 0 - 39 |

## Output: findings.json

All flagged domains are saved to `findings.json` in the working directory. Each record includes:

```json
{
  "domain": "paypa1-verify-account.com",
  "matched_brand": "paypal",
  "score": 88,
  "risk_score": 91,
  "risk_label": "CRITICAL",
  "create_date": "2026-06-06",
  "expiry_date": "2027-06-06",
  "registrar": "Porkbun LLC",
  "registrant_name": "REDACTED FOR PRIVACY",
  "registrant_country": "United States",
  "registrant_country_code": "US",
  "registrant_email": "",
  "ns1": "ns1.porkbun.com",
  "ns2": "ns2.porkbun.com",
  "status1": "clienttransferprohibited",
  "status2": ""
}
```

## Automate Daily Monitoring

Add a cron job to run the detector every morning:

```bash
# Run at 8 AM every day
0 8 * * * cd /path/to/phishing-domain-detector && python detector.py >> logs/detector.log 2>&1
```

## Project Structure

```
phishing-domain-detector/
├── detector.py        # Main script
├── config.py          # Your API key, brands, and settings
├── requirements.txt   # Python dependencies
├── findings.json      # Generated on each run (gitignored)
└── README.md
```

## Data Source

This tool uses the [WhoisFreaks Newly Registered Domains](https://whoisfreaks.com/products/newly-registered-domains) product. The daily files cover all global domain registrations with full WHOIS data embedded, updated every 24 hours.

API documentation: https://whoisfreaks.com/documentation/newly-registered-domains

## License

MIT