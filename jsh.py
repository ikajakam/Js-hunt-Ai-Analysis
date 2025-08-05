#!/usr/bin/env python3

import os
os.environ["TRANSFORMERS_VERBOSITY"] = "error"
import re
import requests
import argparse
import hashlib
import jsbeautifier
from urllib.parse import urlparse
from subprocess import Popen, PIPE
from halo import Halo
from tqdm import tqdm
import time
import torch
from transformers import AutoModelForCausalLM, AutoTokenizer
from playwright.sync_api import sync_playwright
import json
import csv

LINKFINDER_BIN = "linkfinder"

# === DEVICE SETUP ===
model = None
tokenizer = None
device = None

def lazy_init_model():
    global model, tokenizer, device
    if model is None or tokenizer is None:
        print("\n🧠 G P U hardon verified")
        import torch
        torch.backends.cuda.matmul.allow_tf32 = True
        torch.backends.cudnn.allow_tf32 = True
        torch.backends.cudnn.benchmark = True

        device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        print(f"ﾒ૦ﾒ૦ 💋 💋 💋 ﾒ૦ﾒ૦ jizzed : {device}")
        if device.type == "cuda":
            print(f"꩜ ꩜ 🌕 ꩜ ꩜  jiiiizzzzzzziiiingggggg : {torch.cuda.get_device_name(0)}")

        model_path = "Qwen/Qwen2.5-1.5B-Instruct"
        from transformers import AutoModelForCausalLM, AutoTokenizer
        tokenizer = AutoTokenizer.from_pretrained(model_path, trust_remote_code=True)
        model = AutoModelForCausalLM.from_pretrained(
            model_path,
            trust_remote_code=True,
            torch_dtype=torch.float16
        ).to(device).eval()

        print("🍰 🍰 🍰 🍰 jizzingjizzingjizzingjizzing local AI model")


# === OUTPUT DIR SETUP (DYNAMIC) ===
def prepare_output_dir(domain):
    base_name = domain.strip().replace("https://", "").replace("http://", "").strip("/")
    output_base = os.path.join("jshunt_output", base_name)
    count = 1
    final_path = output_base
    while os.path.exists(final_path):
        count += 1
        final_path = f"{output_base}{count}"
    os.makedirs(os.path.join(final_path, "js_files"), exist_ok=True)
    return final_path

# === INIT GLOBAL VAR (WILL BE OVERRIDDEN IN MAIN) ===
output_dir = None


# === COLLECT JS URLS ===
def get_domains_from_target(domain):
    js_urls = set()

    commands = [
        {
            "desc": "📡 Running Subfinder + Waybackurls (for subdomains)",
            "cmd": f"echo {domain} | subfinder -silent | waybackurls | grep '\\.js$'"
        },
        {
            "desc": "🌐 Running Waybackurls (main domain only)",
            "cmd": f"echo {domain} | waybackurls | grep '\\.js$'"
        }
    ]

    for task in commands:
        print(f"\n{task['desc']}")
        p = Popen(task["cmd"], stdout=PIPE, shell=True)
        output = p.stdout.read().decode().splitlines()
        found = [url.strip() for url in output if url.strip()]
        print(f"🫦 Found {len(found)} JS URLs from this source.\n")
        js_urls.update(found)

    return list(js_urls)

# === DOWNLOAD JS FILES (WITH FULL LOGGING) ===
def download_js_files(js_urls, output_dir, proxy=None):
    downloaded = []
    all_js_path = os.path.join(output_dir, "all_js_urls.txt")
    failed_js_path = os.path.join(output_dir, "failed_js_urls.txt")
    downloaded_js_path = os.path.join(output_dir, "downloaded_js_urls.txt")

    with open(all_js_path, "w", encoding="utf-8") as all_f, \
         open(failed_js_path, "w", encoding="utf-8") as fail_f, \
         open(downloaded_js_path, "w", encoding="utf-8") as down_f:

        for idx, url in enumerate(js_urls, 1):
            all_f.write(url + "\n")

            try:
                headers = {'User-Agent': 'Mozilla'}
                proxies = {"http": proxy, "https": proxy} if proxy else {}
                resp = requests.get(url, headers=headers, proxies=proxies, timeout=10, verify=True)

                if resp.status_code == 200 and len(resp.text) > 50:
                    fname = urlparse(url).path.split("/")[-1].split("?")[0] or "index.js"
                    hashed = hashlib.md5(url.encode()).hexdigest()[:8]
                    filename = f"{fname}_{hashed}.js"
                    path = os.path.join(output_dir, "js_files", filename)
                    with open(path, "w", encoding="utf-8") as f:
                        f.write(resp.text)
                    downloaded.append(path)
                    down_f.write(url + "\n")
                    print(f"  ├─ [{idx}/{len(js_urls)}] {filename}")
                else:
                    fail_f.write(f"{url} => HTTP {resp.status_code}\n")

            except Exception as e:
                fail_f.write(f"{url} => Exception: {e}\n")
                print(f"[!] Failed to download {url}: {e}")
    return downloaded



# === EXTRACT ENDPOINTS ===
def extract_endpoints(js_file):
    cmd = f"{LINKFINDER_BIN} -i {js_file} -o cli"
    process = Popen(cmd, stdout=PIPE, shell=True)
    output = process.stdout.read().decode()
    endpoints = re.findall(r"(https?://[^\s\"'<>]+)", output)

    # Filter out known irrelevant entries
    junk_patterns = [
        "w3.org", "schema.org", "xmlns", "example.com", "localhost", ".svg"
    ]
    clean_endpoints = []
    for ep in sorted(set(endpoints)):
        if not any(junk in ep for junk in junk_patterns):
            clean_endpoints.append(ep)

    with open(f"{output_dir}/endpoints.txt", "a") as f:
        for ep in clean_endpoints:
            f.write(ep + "\n")


# === FIND SECRETS ===
def find_secrets(js_file):
    with open(js_file, "r", encoding="utf-8") as f:
        content = f.read()
    patterns = [
        r"(?i)(apikey|api_key|token|secret|passwd|pwd|auth)[\"'\s:=]+[\"']?([A-Za-z0-9\-_]{10,})[\"']?",
        r"AKIA[0-9A-Z]{16}", r"AIza[0-9A-Za-z\-_]{35}"
    ]
    for pattern in patterns:
        for match in re.findall(pattern, content):
            with open(f"{output_dir}/secrets.txt", "a") as out:
                out.write(f"{js_file} => {match if isinstance(match, str) else match[0]} => {match[-1]}\n")

# === DETECT DANGEROUS PATTERNS ===
def grep_payloads(js_file):
    keywords = [
        "eval", "document.write", "innerHTML", "setTimeout", "setInterval",
        "Function(", "XMLHttpRequest", "fetch", "window.location", "localStorage", "postMessage"
    ]
    with open(js_file, "r", encoding="utf-8") as f:
        content = f.read()
    for word in keywords:
        if word in content:
            with open(f"{output_dir}/summary.log", "a") as log:
                log.write(f"[+] {js_file} uses suspicious JS pattern: {word}\n")

def verify_dangerous_patterns(js_file):
    dangerous_patterns = {
        "eval": r"\beval\s*\(",
        "document.write": r"\bdocument\.write\s*\(",
        "innerHTML": r"\binnerHTML\b",
        "Function": r"\bFunction\s*\(",
        "setTimeout": r"\bsetTimeout\s*\(",
        "setInterval": r"\bsetInterval\s*\(",
        "XMLHttpRequest": r"\bXMLHttpRequest\b",
        "localStorage": r"\blocalStorage\b",
        "postMessage": r"\bpostMessage\b"
    }

    dom_sink_patterns = {
        "location.href": r"\blocation\.href\b",
        "location.hash": r"\blocation\.hash\b",
        "document.URL": r"\bdocument\.URL\b",
        "document.documentURI": r"\bdocument\.documentURI\b",
        "window.name": r"\bwindow\.name\b",
        "document.referrer": r"\bdocument\.referrer\b"
    }

    # Beautify the JS first
    with open(js_file, "r", encoding="utf-8") as f:
        raw_code = f.read()
    beautified = jsbeautifier.beautify(raw_code)
    lines = beautified.splitlines()

    findings = []

    for idx, line in enumerate(lines):
        # Search dangerous JS usage
        for label, pattern in dangerous_patterns.items():
            if re.search(pattern, line):
                record = {
                    "type": "dangerous_function",
                    "pattern": label,
                    "file": js_file,
                    "line": idx + 1,
                    "code": line.strip()
                }
                findings.append(record)
                with open(os.path.join(output_dir, "dangerous_functions_verified.txt"), "a") as out:
                    out.write(f"[{label}] {js_file}:{idx + 1} — {line.strip()}\n")

        # Search DOM sinks
        for label, pattern in dom_sink_patterns.items():
            if re.search(pattern, line):
                record = {
                    "type": "dom_sink",
                    "pattern": label,
                    "file": js_file,
                    "line": idx + 1,
                    "code": line.strip()
                }
                findings.append(record)
                with open(os.path.join(output_dir, "dom_sinks_verified.txt"), "a") as out:
                    out.write(f"[{label}] {js_file}:{idx + 1} — {line.strip()}\n")

    # Export JSON
    if findings:
        json_path = os.path.join(output_dir, "js_vulns.json")
        csv_path = os.path.join(output_dir, "js_vulns.csv")

        with open(json_path, "w", encoding="utf-8") as json_out:
            json.dump(findings, json_out, indent=2)

        with open(csv_path, "w", newline='', encoding="utf-8") as csv_out:
            writer = csv.DictWriter(csv_out, fieldnames=["type", "pattern", "file", "line", "code"])
            writer.writeheader()
            writer.writerows(findings)


# === AI ANALYSIS ===
# === AI ANALYSIS (Updated with Chunking + Memory Optimizations) ===
def analyze_with_ai(js_file):
    #lazy_init_model()  # <--- NEW LINE
    def clean_js(js_code):
        # Only extract useful patterns (API calls, endpoints, secrets, etc.)
        return "\n".join(re.findall(
    r'(https?://[^"\']+|fetch\([^)]*\)|axios\.[a-z]+\([^)]*\)|[A-Za-z_]{3,}\s*=\s*["\'].*?["\'])',
    js_code))


    def chunk_text(text, max_tokens=2048):
        lines = text.splitlines()
        chunks, current_chunk = [], []
        token_count = 0
        for line in lines:
            token_count += len(line.split())
            current_chunk.append(line)
            if token_count >= max_tokens:
                chunks.append("\n".join(current_chunk))
                current_chunk, token_count = [], 0
        if current_chunk:
            chunks.append("\n".join(current_chunk))
        return chunks

    with open(js_file, "r", encoding="utf-8") as f:
        raw = f.read()

    # Step 1: Filter unnecessary JS
    useful_js = clean_js(raw)
    chunks = chunk_text(useful_js, max_tokens=768)

    for idx, chunk in enumerate(chunks):
        prompt = f"""
You are a professional JavaScript security auditor and bug bounty hunter.

Analyze the following JavaScript file for the following:
- API endpoints, URLs, hardcoded credentials, secrets, tokens
- DOM manipulations that involve user input (classList, innerHTML, insertAdjacentHTML, etc.)
- Use of URLSearchParams, window.location, or other sources of user input
- Insecure storage handling (localStorage, sessionStorage, cookies)
- Dangerous functions (eval, Function, setTimeout with strings)
- Fetch or XMLHttpRequest usage with dynamic or user-controlled URLs
- DOM-based XSS, open redirect, SSRF, prototype pollution, or any exploitable client-side issue
- Any juicy information disclosure that might help in reconnaissance or exploitation

Give a report including:
- [VULN] Title
- [SEVERITY]
- [DESCRIPTION]
- [CODE CONTEXT]
- [RECOMMENDATION]

:\n\n{chunk}\n\nResponse:
"""

        inputs = tokenizer(prompt, return_tensors="pt", padding=True, truncation=True, max_length=1024).to(device)
        with torch.no_grad():
            output = model.generate(
                input_ids=inputs["input_ids"],
                attention_mask=inputs["attention_mask"],
                max_new_tokens=256,
                do_sample=False,
                pad_token_id=tokenizer.eos_token_id,
                eos_token_id=tokenizer.eos_token_id,
            )

        decoded = tokenizer.decode(output[0], skip_special_tokens=True)
        #  Remove prompt repetition if model echoes it back
        if prompt.strip() in decoded:
            decoded = decoded.split(prompt.strip(), 1)[-1].strip()

        with open(f"{output_dir}/ai_analysis.txt", "a") as f:
            f.write(f"--- {js_file} (chunk {idx+1}/{len(chunks)}) ---\n{decoded}\n\n")


# === CSP HEADER CHECK ===
def check_csp(domain, proxy=None):
    headers = {'User-Agent': 'Mozilla'}
    proxies = {"http": proxy, "https": proxy} if proxy else {}
    for scheme in ["http", "https"]:
        try:
            r = requests.get(f"{scheme}://{domain}", headers=headers, proxies=proxies, timeout=5, verify=True)
            csp = r.headers.get("Content-Security-Policy")
            with open(f"{output_dir}/csp_headers.txt", "a") as out:
                out.write(f"{scheme}://{domain} => {csp if csp else 'None'}\n")
            break
        except Exception:
            continue

# === GITHUB DORKING ===
def github_dork(domain):
    dorks = [f'"{domain}" ext:js', f'"{domain}" token', f'"{domain}" api_key']
    with open(f"{output_dir}/github_dorks.txt", "w") as f:
        for d in dorks:
            f.write(f"https://github.com/search?q={d.replace(' ', '+')}\n")

# === INTEGRATION PLACEHOLDER ===
def integrate_burp_zap(js_file):
    with open(f"{output_dir}/dynamic_scan_todo.txt", "a") as f:
        f.write(f"Send to Burp/ZAP: {js_file}\n")

# === PLAYWRIGHT DOM TRACER ===
def dom_tracer(domain):
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        trace_log = f"{output_dir}/dom_trace.txt"
        try:
            page.on("request", lambda req: open(trace_log, "a").write(f"[REQ] {req.method} {req.url}\n"))
            page.on("response", lambda res: open(trace_log, "a").write(f"[RES] {res.status} {res.url}\n"))
            page.goto(f"http://{domain}", timeout=10000)
            page.wait_for_timeout(5000)
        except Exception as e:
            with open(trace_log, "a") as f:
                f.write(f"[!] Playwright error: {str(e)}\n")
        finally:
            browser.close()

# === DOM SINK DETECTION ===
def detect_dom_sinks(page, trace_log):
    sinks = [
        "location.hash", "location.href", "document.URL",
        "document.documentURI", "window.name", "document.referrer"
    ]
    for sink in sinks:
        try:
            value = page.evaluate(f"() => {sink}")
            with open(trace_log, "a") as f:
                f.write(f"[DOM-SINK] {sink} => {value}\n")
        except Exception as e:
            with open(trace_log, "a") as f:
                f.write(f"[DOM-SINK ERROR] {sink}: {e}\n")

# === TOKEN FLOW TRACING ===
def token_flow_trace(js_file):
    with open(js_file, "r", encoding="utf-8") as f:
        content = f.read()
    jwt_pattern = r"eyJ[a-zA-Z0-9-_]{10,}\\.[a-zA-Z0-9-_]{10,}\\.[a-zA-Z0-9-_]{10,}"
    tokens = re.findall(jwt_pattern, content)
    if tokens:
        with open(f"{output_dir}/token_flows.txt", "a") as f:
            for token in tokens:
                f.write(f"{js_file} => {token}\n")

# === CDP SNAPSHOT PLACEHOLDER ===
def chrome_devtools_snapshot(domain):
    with open(f"{output_dir}/cdp_snapshots.txt", "a") as f:
        f.write(f"[CDP-SNAPSHOT] Placeholder for {domain} (needs pychrome or websocket client)\n")

# === MAIN ===
from datetime import datetime

def progress_log(message):
    print(message)


def main():
    global output_dir
    parser = argparse.ArgumentParser(description="🧠 JS Recon Tool + AI + DOM Trace + Playwright")
    parser.add_argument("--domain", required=True, help="Target domain (e.g. example.com)")
    parser.add_argument("--proxy", help="Proxy (http://127.0.0.1:8080)")
    parser.add_argument("--analysis", nargs="?", const=True, help="Resume analysis from existing path")
    args = parser.parse_args()

    if args.analysis is True:
        print("❌ Please provide path to existing scan directory.")
        return
    elif args.analysis:
        output_dir = args.analysis
        js_dir = os.path.join(output_dir, "js_files")
        if not os.path.exists(js_dir):
            print(f"❌ JS directory not found in: {js_dir}")
            return
        downloaded = [os.path.join(js_dir, f) for f in os.listdir(js_dir) if f.endswith(".js")]
        start_time = datetime.now()
        print(f"\n☢  Resuming analysis at: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"☢  Using directory: {output_dir}")
        print(f"☢  Found {len(downloaded)} JS files to analyze...")
    else:
        output_dir = prepare_output_dir(args.domain)
        start_time = datetime.now()
        print(f"\n☢  Scan started at: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"\n   ⛩  Omae Wa Mou Shindeiru お前はもう死んでいる\n")
        print("☢  Gathering JS URLs...")
        js_urls = get_domains_from_target(args.domain)
        print("☢  Downloading JS files :")
        downloaded = download_js_files(js_urls, output_dir, args.proxy)

        print("\n📩 Do youstill have hardon for AI Analysis? or wanna jizz later [y/N]: ", end="")
        choice = input().strip().lower()
        if choice != 'y':
            print("\n⏹️ Halting after JS file download. You can continue later using:")
            print(f"   python3 jsh_updated.py --domain {args.domain} --analysis {output_dir}\n")
            return

    lazy_init_model()
    print("\n☢  Analyzing JS files...")
    for idx, js_file in enumerate(downloaded, 1):
        print(f"  ├─ [{idx}/{len(downloaded)}] Processing: {os.path.basename(js_file)}")
        extract_endpoints(js_file)
        find_secrets(js_file)
        grep_payloads(js_file)
        verify_dangerous_patterns(js_file)
        analyze_with_ai(js_file)
        integrate_burp_zap(js_file)

    print("\n☢  Checking CSP headers...")
    check_csp(args.domain, args.proxy)

    print("☢  Generating GitHub dorks...")
    github_dork(args.domain)

    print("☢  Running DOM tracer with Playwright...")
    dom_tracer(args.domain)

    end_time = datetime.now()
    print(f"\n☢  Scan ended at: {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"☢  Total Duration: {end_time - start_time}")
    print(f"\n🫦 jizzed everything in {output_dir}")
    print("🕷️ Happy hunting and keep jizzing your recon\n")
if __name__ == "__main__":
    main()
