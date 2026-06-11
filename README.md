<p align="center">
  <img src="assets/banner.png" alt="SuspicionKit banner" width="100%" />
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-0.0.3-2ecc71?style=for-the-badge" alt="version" />
  <img src="https://img.shields.io/badge/python-3.10%2B-blue?style=for-the-badge" alt="python" />
  <img src="https://img.shields.io/badge/license-MIT-yellow?style=for-the-badge" alt="license" />
  <img src="https://img.shields.io/badge/CLI-Rich-purple?style=for-the-badge" alt="rich" />
</p>

---

## ✨ What is SuspicionKit?

**SuspicionKit** is a terminal-first threat analysis toolkit that helps you inspect suspicious URLs before opening them in a browser.

It combines multiple signals into a readable risk report:

- URL structure
- domain signals
- DNS checks
- redirects
- WHOIS/domain age
- TLS certificate status
- basic HTML/page inspection
- phishing-style indicators

SuspicionKit does **not** promise perfect detection. No lightweight CLI tool can guarantee that a URL is safe with 99% certainty. The goal is to give you a practical early-warning report and explain why a link looks normal, suspicious, or risky.

---

## ⚡ Features in v0.0.3

- 🔗 URL normalization
- 🔒 HTTPS check
- 🌐 DNS resolution checks
- 🧭 Redirect detection
- 🕵️ URL shortener detection
- 🧬 Punycode / IDN warning
- 🚩 suspicious TLD detection
- 🧾 sensitive query parameter detection
- 🧠 brand impersonation heuristics
- 📊 local popularity estimation
- 🗓️ WHOIS/domain age checks
- 🧑‍💼 registrar and domain expiry checks
- 🔐 TLS certificate expiry checks
- 🧪 basic HTML inspection
- 🔑 password form detection
- 🧰 external form action detection
- 🧱 basic security header checks
- 🎯 risk score from **0 to 100**
- 📡 evidence coverage score
- 🎨 beautiful terminal report powered by **Rich**
- 🧾 JSON output for automation
- 💾 save JSON reports with `--output`
- ✅ legitimate-domain allowlist to reduce false positives
- 📦 installable with **pipx**

---

## 🖼️ Preview

<img src="assets/example.png" alt="SuspicionKit example report" width="100%" />

---

## 📦 Installation

### Install with pipx from GitHub

SuspicionKit is currently installed directly from GitHub:

```bash
python -m pip install --user pipx
python -m pipx ensurepath
```

Restart your terminal after `ensurepath`, then install SuspicionKit:

```bash
pipx install git+https://github.com/notimechoki/suspicionkit.git
```

Check that everything works:

```bash
suspicionkit --version
```

You can also use the short command:

```bash
skit --version
```

---

## 🔄 Upgrade

```bash
pipx upgrade suspicionkit
```

Or reinstall from GitHub:

```bash
pipx uninstall suspicionkit
pipx install git+https://github.com/notimechoki/suspicionkit.git
```

---

## 🗑️ Uninstall

```bash
pipx uninstall suspicionkit
```

---

## 🧪 Local development

Clone the repository:

```bash
git clone https://github.com/notimechoki/suspicionkit.git
cd suspicionkit
```

Create a virtual environment:

```bash
python -m venv .venv
source .venv/bin/activate
```

Install in editable mode:

```bash
pip install -e ".[dev]"
```

Run tests:

```bash
pytest -q
```

Run linting:

```bash
ruff check .
```

---

## 🚀 Usage

Check a URL with full network-based analysis:

```bash
suspicionkit url "https://github.com"
```

Check a suspicious-looking URL:

```bash
suspicionkit url "http://delivery-track-support.top/track?token=123"
```

Run local-only checks without DNS, HTTP, WHOIS, TLS or content inspection:

```bash
suspicionkit url "https://example.com" --no-network
```

Run network checks but skip HTML body inspection:

```bash
suspicionkit url "https://example.com" --no-content
```

Set custom timeout:

```bash
suspicionkit url "https://example.com" --timeout 15
```

Print a machine-readable JSON report:

```bash
suspicionkit url "http://delivery-track-support.top/track?token=123" --json
```

Save a JSON report to a file:

```bash
suspicionkit url "http://delivery-track-support.top/track?token=123" --json --output reports/url-report.json
```

---

## 🧠 How scoring works

SuspicionKit starts with a score of `0` and adds or subtracts points based on collected signals.

Examples:

- HTTPS lowers risk slightly
- HTTP increases risk
- suspicious keywords increase risk
- URL shorteners increase risk
- punycode increases risk
- sensitive query parameters increase risk
- new domains increase risk
- expired or broken TLS certificates increase risk
- password forms increase risk
- external form submissions increase risk
- known popular domains lower risk slightly

Final score:

| Score | Level |
|---:|---|
| 0–25 | Low |
| 26–55 | Medium |
| 56–80 | High |
| 81–100 | Critical |

SuspicionKit also shows **Evidence coverage**. This is not an accuracy guarantee. It only means how much evidence the tool managed to collect. For example, `--no-network` lowers coverage because WHOIS, DNS, TLS and HTTP checks are skipped.

---

## 🔒 Privacy note

By default, SuspicionKit may contact the target host for DNS, HTTP, TLS and WHOIS checks. That can reveal your public IP address to the target infrastructure.

For local-only inspection, use:

```bash
suspicionkit url "https://example.com" --no-network
```

---

## 🧰 Tech stack

- **Python 3.10+**
- **Typer** — CLI commands
- **Rich** — beautiful terminal output
- **HTTPX** — HTTP probing
- **tldextract** — domain parsing
- **dnspython** — DNS checks
- **python-whois** — WHOIS checks
- **BeautifulSoup4** — basic HTML inspection
- **pytest** — tests
- **ruff** — linting

---

## ⚠️ Important disclaimer

SuspicionKit is an early-warning tool. It cannot guarantee that a URL is safe or dangerous.

It is not an antivirus, browser sandbox, malware scanner, or replacement for professional threat intelligence services.

---

## Changelog

See [CHANGELOG.md](CHANGELOG.md).

---

## 📄 License

MIT License.
