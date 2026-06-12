# =============================================================
#  config.example.py
#  Copy this file to config.py and fill in your values.
#  config.py is gitignored so your API key is never committed.
# =============================================================

# Your WhoisFreaks API key.
# Get one at https://whoisfreaks.com
API_KEY = "YOUR_API_KEY_HERE"

# Brands you want to protect — lowercase, no TLD.
BRANDS = [
    "yourbrand",
    "yourproduct",
]

# Minimum fuzzy similarity score to flag a domain (0-100).
# 70 is a balanced default. Lower = more results, more false positives.
SIMILARITY_THRESHOLD = 70

# Date to fetch (format: yyyy-MM-dd).
# Set to None to fetch the most recent available file.
FETCH_DATE = None