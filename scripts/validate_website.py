#!/usr/bin/env python3
"""Validate SentinelForge public website files, links, and demo data."""
import json
import re
import sys
from pathlib import Path

public_dir = Path("public")

errors = []

# 1. All required files exist and are non-empty (.nojekyll is intentionally empty)
required = [
    "public/index.html", "public/overview.html", "public/features.html",
    "public/architecture.html", "public/detection.html",
    "public/soc-workflows.html", "public/demo.html", "public/docs.html",
    "public/installation.html", "public/security.html",
    "public/roadmap.html", "public/about.html", "public/demo/index.html",
    "public/css/main.css", "public/js/nav.js", "public/img/favicon.svg",
    "public/local-dashboard.html", "public/.nojekyll",
    "public/robots.txt", "public/sitemap.xml",
]
for f in required:
    p = Path(f)
    if not p.exists():
        errors.append(f"Missing: {f}")
    elif p.stat().st_size == 0 and f != "public/.nojekyll":
        errors.append(f"Empty: {f}")
if errors:
    for e in errors:
        print(f"FAIL: {e}")
    sys.exit(1)
print("All website files present and non-empty")

# 2. Demo data JSON parses and scenarios are labeled precomputed
with open("public/demo/data/scenarios.json") as f:
    data = json.load(f)
scenarios = data["scenarios"]
expected = {
    "failed-login-burst", "password-spraying", "suspicious-powershell",
    "suspicious-processtree", "c2-beacon",
}
actual = {s["id"] for s in scenarios}
if actual != expected:
    print(f"FAIL: Missing scenarios: {expected - actual}")
    sys.exit(1)
for s in scenarios:
    if "sourceNote" not in s:
        print(f"FAIL: Scenario {s['id']} missing sourceNote label")
        sys.exit(1)
    if "precomputed" not in s.get("sourceNote", "").lower():
        print(f"FAIL: Scenario {s['id']} not labeled as precomputed")
        sys.exit(1)
print(f"Demo JSON valid: {len(scenarios)} scenarios, all labeled precomputed")

# 3. No placeholder href="#" links
for html_file in public_dir.rglob("*.html"):
    content = html_file.read_text()
    if 'href="#"' in content:
        rel = html_file.relative_to(public_dir).as_posix()
        print(f"FAIL: Placeholder href=\"#\" in {rel}")
        sys.exit(1)
print("No placeholder href=\"#\" links found")

# 4. Internal links resolve
html_files = list(public_dir.rglob("*.html"))
existing = {f.relative_to(public_dir).as_posix() for f in public_dir.rglob("*") if f.is_file()}
link_errors = []
for hf in html_files:
    rel = hf.relative_to(public_dir).as_posix()
    content = hf.read_text()
    for m in re.finditer(r'(?:href|src)=["]([^"]+)["]', content):
        t = m.group(1)
        if t.startswith("http://") or t.startswith("https://"):
            continue
        if t.startswith("#"):
            continue
        tp = (hf.parent / t).resolve()
        try:
            tr = tp.relative_to(public_dir.resolve()).as_posix()
        except ValueError:
            link_errors.append(f"{rel}: unresolved {t}")
            continue
        if tr not in existing:
            link_errors.append(f"{rel}: missing {t} -> {tr}")
if link_errors:
    for e in link_errors:
        print(f"BROKEN: {e}")
    sys.exit(1)
print(f"All internal links resolve across {len(html_files)} HTML files")
