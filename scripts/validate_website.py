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
    "public/roadmap.html", "public/about.html",    "public/demo/index.html",
    "public/detection-showcase.html",
    "public/css/main.css", "public/css/chat-widget.css", "public/js/nav.js",
    "public/js/chat-widget.js", "public/img/favicon.svg",
    "public/img/architecture.svg",
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

# 2. Every public HTML page contains the support entry point (chat widget)
html_files = sorted(public_dir.rglob("*.html"))
for hf in html_files:
    content = hf.read_text()
    rel = hf.relative_to(public_dir).as_posix()
    if 'id="sentinelforge-support"' not in content:
        errors.append(f"Missing support widget: {rel}")
    if 'src="js/chat-widget.js"' not in content and 'src="../js/chat-widget.js"' not in content:
        errors.append(f"Missing chat-widget.js: {rel}")
    if 'href="css/chat-widget.css"' not in content and 'href="../css/chat-widget.css"' not in content:
        errors.append(f"Missing chat-widget.css: {rel}")
if errors:
    for e in errors:
        print(f"FAIL: {e}")
    sys.exit(1)
print(f"All {len(html_files)} HTML pages contain the support entry point")

# 3. Demo data JSON parses and scenarios are labeled precomputed
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

# 4. No placeholder href="#" links
for html_file in html_files:
    content = html_file.read_text()
    if 'href="#"' in content:
        rel = html_file.relative_to(public_dir).as_posix()
        print(f"FAIL: Placeholder href=\"#\" in {rel}")
        sys.exit(1)
print("No placeholder href=\"#\" links found")

# 5. Internal links resolve
existing = {f.relative_to(public_dir).as_posix() for f in public_dir.rglob("*") if f.is_file()}
link_errors = []
for hf in html_files:
    rel = hf.relative_to(public_dir).as_posix()
    content = hf.read_text()
    for m in re.finditer(r'(?:href|src)=["]([^"]+)["]', content):
        t = m.group(1)
        if t.startswith(("http://", "https://")):
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

# 6. No broken or malformed image references
img_errors = []
for hf in html_files:
    rel = hf.relative_to(public_dir).as_posix()
    content = hf.read_text()
    for m in re.finditer(r'<img\s+[^>]*>', content):
        img_tag = m.group(0)
        # Check for invalid src attribute usage (e.g., <svg src=...>)
        if 'src=' not in img_tag:
            img_errors.append(f"{rel}: img tag without src: {img_tag[:80]}")
            continue
        sm = re.search(r'src=["]([^"]+)["]', img_tag)
        if sm:
            t = sm.group(1)
            if t.startswith(("http://", "https://")):
                continue
            tp = (hf.parent / t).resolve()
            try:
                tr = tp.relative_to(public_dir.resolve()).as_posix()
            except ValueError:
                img_errors.append(f"{rel}: unresolved image src {t}")
                continue
            if tr not in existing:
                img_errors.append(f"{rel}: missing image {t} -> {tr}")
    # Check for <svg src="..."> which is invalid HTML
    for m in re.finditer(r'<svg\s+[^>]*src=', content):
        img_errors.append(f"{rel}: invalid <svg src=...> tag (use <img>)")
if img_errors:
    for e in img_errors:
        print(f"BAD IMAGE: {e}")
    sys.exit(1)
print("No broken or malformed image references")

# 7. No undefined CSS variables referenced in HTML inline styles
css_vars = set()
main_css = Path("public/css/main.css")
if main_css.exists():
    css_content = main_css.read_text()
    for m in re.finditer(r'--[a-zA-Z0-9_-]+:', css_content):
        css_vars.add(m.group(0).rstrip(':'))

chat_css = Path("public/css/chat-widget.css")
if chat_css.exists():
    css_content = chat_css.read_text()
    for m in re.finditer(r'--[a-zA-Z0-9_-]+:', css_content):
        css_vars.add(m.group(0).rstrip(':'))

var_errors = []
for hf in html_files:
    rel = hf.relative_to(public_dir).as_posix()
    content = hf.read_text()
    for m in re.finditer(r'var\(--([a-zA-Z0-9_-]+)', content):
        var_name = '--' + m.group(1)
        if var_name not in css_vars:
            var_errors.append(f"{rel}: undefined CSS variable {var_name}")
if var_errors:
    for e in var_errors:
        print(f"UNDEFINED VAR: {e}")
    sys.exit(1)
print("No undefined CSS variables referenced in HTML")

# 8. Responsive styling present (media queries in CSS)
css_files = [public_dir / "css" / "main.css", public_dir / "css" / "chat-widget.css"]
has_media_query = False
for cf in css_files:
    if cf.exists() and '@media' in cf.read_text():
        has_media_query = True
        break
if not has_media_query:
    print("FAIL: No responsive media queries found in CSS")
    sys.exit(1)
print("Responsive media queries present in CSS")
print("ALL WEBSITE VALIDATION CHECKS PASSED")
