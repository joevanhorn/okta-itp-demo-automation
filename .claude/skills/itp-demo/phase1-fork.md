# Phase 1: Fork & Clone

Get the user's own copy of the repo set up locally.

## Steps

### 1.1 Check GitHub authentication

```bash
gh auth status
```

Capture the GitHub username from the output. If not authenticated, tell the user to run `gh auth login` first.

### 1.2 Fork the repo

Check if they've already forked:

```bash
gh repo list --fork --json nameWithOwner --jq '.[].nameWithOwner' | grep -i itp-demo
```

If not forked yet:

```bash
gh repo fork joevanhorn/okta-itp-demo-automation --clone --remote
cd okta-itp-demo-automation
```

If already forked, just clone:

```bash
gh repo clone <username>/okta-itp-demo-automation
cd okta-itp-demo-automation
```

### 1.3 Verify the repo structure

```bash
ls scripts/trigger_itp_demo.py terraform/provider.tf .github/workflows/itp-demo-trigger.yml
```

All three should exist. If any are missing, the fork may be outdated — suggest `git pull upstream main`.

### 1.4 Install Python dependencies

```bash
pip install -r requirements.txt
```

For real mode only (Playwright):
```bash
playwright install chromium
```

### 1.5 Verify Python scripts parse cleanly

```bash
python3 -c "import scripts.trigger_itp_demo; print('OK')" 2>/dev/null || python3 -m py_compile scripts/trigger_itp_demo.py && echo "Scripts OK"
```

## Outputs

- User has a local clone of their forked repo
- Python dependencies installed
- Ready for Phase 2 (AWS) or Phase 4 (quick mode, which needs no infrastructure)

## Quick Mode Shortcut

If the user only wants to run quick mode (no infrastructure needed), they can skip directly to Phase 4 after this phase. Quick mode just needs:
- `OKTA_ORG_NAME`
- `OKTA_BASE_URL`
- `OKTA_API_TOKEN`
- A target user email

Tell the user: "Quick mode works right now with just your Okta API token — no AWS infrastructure needed. Want to try it, or set up the full infrastructure for real and SSF modes?"
