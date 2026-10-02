# Basic scan
python3 cf-origin-hunter.py -d example.com

# With Tor and decoys
python3 cf-origin-hunter.py -d example.com --tor --decoy --decoy-count 30

# Large wordlist, more threads, JSON output
python3 cf-origin-hunter.py -d example.com -w subdomains.txt -t 50 --json

# Skip slow phases
python3 cf-origin-hunter.py -d example.com --skip-brute --skip-verify