# Contributing to SentinelForge AI

**Project:** SentinelForge AI  
**Version:** 0.1.0 (prototype)  
**Classification:** Demonstrable SOC Prototype

---

## 1. How to Contribute

### Step 1: Fork the repository

Create your own fork of the SentinelForge AI repository on GitHub.

### Step 2: Clone and set up

```bash
git clone https://github.com/your-username/sentinelforge-ai.git
cd sentinelforge-ai
```

### Step 3: Create a feature branch

```bash
git checkout -b feature/your-feature-name
```

### Step 4: Make changes

Implement your feature, fix a bug, or improve documentation. Add tests for any new functionality.

### Step 5: Run the test suite

```bash
python -m pytest
```

Test totals change as tests are added; compare the local result against the current GitHub Actions CI run (Python 3.12 and 3.13) rather than a hardcoded count.

### Step 6: Run validation checks

```bash
ruff check sentinelforge/ tests/
ruff format --check sentinelforge/ tests/
mypy sentinelforge/
```

When the optional scanning dependencies are installed, also run `bandit -r sentinelforge/` and `pip-audit -r requirements.txt`. Confirm the current GitHub Actions CI result before submitting a pull request.

### Step 7: Submit a pull request

Open a pull request against the main branch. Describe your changes and any test results.

---

## 2. Contribution Guidelines

### Do

- Write tests for new detection rules or normalizer changes
- Run the full pytest suite before submitting
- Document new configuration options in README.md
- Use `SENTINELFORGE_*` environment variables for configuration
- Preserve raw log evidence verbatim in all code paths
- Report security issues privately (see SECURITY.md)

### Do Not

- Add credentials, API keys, tokens, or secrets to source code
- Modify detection thresholds without updating validation scripts
- Claim production readiness or real-time capabilities
- Fabricate benchmark or detection metrics
- Describe batch replay as live streaming or real-time
- Modify EvidenceForge or any other external project

---

## 3. Code Style

- Follow PEP 8 for Python code
- Use type hints where practical
- Document public classes and methods with docstrings
- Keep detection rules focused on a single technique
- Evidence must cite original log events; no invented indicators

---

## 4. Reporting Issues

### Bug Reports

Open a GitHub issue with:
- Steps to reproduce
- Expected vs. actual behavior
- Python version and OS
- Relevant log excerpts (sanitized — no real credentials or PII)

### Security Issues

**Do not open public issues for security vulnerabilities.** Contact the project maintainer directly.

See [SECURITY.md](SECURITY.md) for details.

---

## 5. Recognition

Contributors are acknowledged in release notes. All contributions are made under the project's MIT License.