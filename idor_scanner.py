#!/usr/bin/env python3
"""
idor_scanner.py
Simple IDOR scanning helper (defensive, for authorized testing).

Features:
 - Sends a "baseline" request for a target object ID (must be an authenticated session)
 - Tries a set of candidate IDs (numeric enumeration, offsets, and optional words)
 - Tries base64-encoded variants if header/body/param looks encoded
 - Compares status codes and response body similarity (SequenceMatcher)
 - Reports possible IDOR candidates for manual review

Usage:
  python idor_scanner.py \
    --url "https://example.com/profile?user_id=123" \
    --cookie "session=XXXX" \
    --param user_id \
    --candidates 122,124,125,200-210 \
    --wordlist ids.txt
"""

import argparse
import requests
import time
import re
import base64
from difflib import SequenceMatcher
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, ParseResult

# --- helpers ---
def similarity(a: str, b: str) -> float:
    return SequenceMatcher(None, a, b).ratio()

def parse_candidates(s: str):
    """Parse comma separated numbers and ranges e.g. 100,101,200-210"""
    out = []
    if not s:
        return out
    parts = [p.strip() for p in s.split(',')]
    for p in parts:
        if '-' in p:
            a,b = p.split('-',1)
            out.extend(range(int(a), int(b)+1))
        else:
            out.append(int(p))
    return sorted(set(out))

def try_base64_variants(val: str):
    """Return list of candidate encodings for a value (if numeric => ascii -> base64)"""
    res = [val]
    # try ascii base64
    try:
        b = val.encode('ascii')
        b64 = base64.b64encode(b).decode('ascii')
        res.append(b64)
    except Exception:
        pass
    # try decoding then re-encoding (handles when original is base64)
    try:
        decoded = base64.b64decode(val)
        reenc = base64.b64encode(decoded).decode('ascii')
        if reenc not in res:
            res.append(reenc)
    except Exception:
        pass
    return res

# --- scanner core ---
def load_wordlist(path):
    with open(path,'r',encoding='utf-8') as f:
        return [line.strip() for line in f if line.strip() and not line.startswith('#')]

def send_request(session, method, url, headers, data):
    try:
        if method.upper() == 'GET':
            r = session.get(url, headers=headers, timeout=15, allow_redirects=True)
        else:
            r = session.post(url, headers=headers, data=data, timeout=15, allow_redirects=True)
        return r
    except requests.RequestException as e:
        print(f"[!] Request error: {e}")
        return None

def replace_param_in_url(url, param_name, new_value):
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param_name] = [str(new_value)]
    new_q = urlencode(qs, doseq=True)
    newp = ParseResult(parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_q, parsed.fragment)
    return urlunparse(newp)

def main():
    parser = argparse.ArgumentParser(description="Simple IDOR scanner (authorized testing only).")
    parser.add_argument('--url', required=True, help='Full URL (include the parameter to test, e.g. https://x/app?file=123)')
    parser.add_argument('--param', required=True, help='Parameter name to tamper (e.g. file, id, user_id)')
    parser.add_argument('--cookie', help='Cookie header value (e.g. session=xxx); ignored if --auth is used')
    parser.add_argument('--auth', help='Authorization header value (e.g. "Bearer TOKEN")')
    parser.add_argument('--method', default='GET', choices=['GET','POST'], help='HTTP method')
    parser.add_argument('--data', help='POST body as key1=val1&key2=val2 (if method POST). Use {param} as placeholder for injection.')
    parser.add_argument('--candidates', help='Comma list or ranges of numeric candidates (e.g. 100,101,200-210)')
    parser.add_argument('--wordlist', help='Path to wordlist file with candidate IDs (one per line)')
    parser.add_argument('--sleep', type=float, default=0.2, help='Delay between requests (s)')
    parser.add_argument('--sim-threshold', type=float, default=0.85, help='Similarity threshold to consider "same content" (0..1)')
    args = parser.parse_args()

    session = requests.Session()
    headers = {'User-Agent':'idor-scanner/0.1'}
    if args.auth:
        headers['Authorization'] = args.auth
    if args.cookie:
        headers['Cookie'] = args.cookie

    # Baseline: get original ID response
    print("[*] Fetching baseline response for original URL...")
    base_resp = send_request(session, args.method, args.url, headers, args.data)
    if not base_resp:
        print("[!] Baseline request failed; aborting.")
        return
    base_status = base_resp.status_code
    base_body = base_resp.text[:20000]  # limit huge bodies
    print(f"[*] Baseline status: {base_status}; body length: {len(base_body)} chars")

    # Build candidate list
    candidates = []
    if args.candidates:
        candidates += parse_candidates(args.candidates)
    if args.wordlist:
        candidates += load_wordlist(args.wordlist)
    # dedupe & stringify
    candidates = [str(c) for c in dict.fromkeys(candidates)]

    if not candidates:
        print("[!] No candidates specified. Provide --candidates or --wordlist")
        return

    findings = []
    for cand in candidates:
        # try plain and base64 variants
        variants = try_base64_variants(cand)
        for v in variants:
            # construct URL or body
            if args.method.upper() == 'GET':
                test_url = replace_param_in_url(args.url, args.param, v)
                test_data = None
            else:
                if not args.data:
                    print("[!] For POST you must provide --data (use {param} placeholder).")
                    return
                # replace param placeholder
                body = args.data.replace('{' + args.param + '}', v)
                test_url = args.url
                test_data = body

            r = send_request(session, args.method, test_url, headers, test_data)
            if r is None:
                continue
            # quick checks
            status = r.status_code
            body = r.text[:20000]
            sim = similarity(base_body, body)
            # Heuristics: same status and high similarity can mean accessible object
            if status == base_status and sim >= args.sim_threshold:
                print(f"[+] POSSIBLE IDOR: candidate={v} status={status} sim={sim:.3f} url={test_url}")
                findings.append({'candidate':v, 'status':status, 'sim':sim, 'url':test_url})
            else:
                # optionally print lower-level differences for debugging
                print(f" - tried {v}: status {status}, sim {sim:.3f}")
            time.sleep(args.sleep)

    print("\n=== SUMMARY ===")
    if findings:
        print(f"[!] Potential IDORs found: {len(findings)}")
        for f in findings:
            print(f" - {f['candidate']} | status={f['status']} | sim={f['sim']:.3f} | {f['url']}")
        print("\n[!] IMPORTANT: These are only heuristics. Manually verify the flagged cases (auth, owner, side effects).")
    else:
        print("[*] No obvious candidates found with the provided lists/threshold.")

if __name__ == '__main__':
    main()
