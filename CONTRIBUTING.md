# Contributing

Contributions are welcome: new commands, workflows, NSE script examples, corrections, and improvements to existing content.

---

## Ways to contribute

- **New command or workflow:** Open an [issue](https://github.com/Nervi0z/Nmap-Blueteam/issues/new) describing the use case
- **Fix:** Wrong flag, outdated syntax, broken example — submit a pull request directly
- **New script:** Open an issue first to discuss scope
- **Typos and formatting:** Small fixes as pull requests without an issue

---

## Submitting a pull request

1. Fork the repository
2. Clone your fork and create a descriptive branch:
   ```bash
   git checkout -b add-snmp-nse-examples
   git checkout -b fix-udp-scan-flags
   ```
3. Make changes in `README.md` or `scripts/`
4. Commit with [Conventional Commits](https://www.conventionalcommits.org/) prefixes:
   ```bash
   git commit -m "feat: add SNMP NSE script examples"
   git commit -m "fix: correct UDP scan timing flag"
   ```
5. Open a pull request against `main`

---

## Quality criteria

- Commands must be tested and functional
- All examples must use private IP ranges (`192.168.x.x`, `10.x.x.x`) or clearly marked placeholders
- No real hostnames or IP addresses in examples
- No emojis, no filler language
- Keep the junior-friendly tone — explain what each flag does, not just what to copy
