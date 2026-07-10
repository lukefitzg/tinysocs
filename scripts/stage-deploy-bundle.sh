#!/usr/bin/env bash
# Stage a self-contained deploy bundle for validating the detection ruleset on a
# Windows VM. Builds the win-x64 agent, then assembles a folder you copy to the
# VM and run two commands in. Output goes to dist/ (gitignored).
#
# Run on the build host (macOS/Linux with the .NET SDK):
#     scripts/stage-deploy-bundle.sh
#
# Then copy dist/deploy-bundle/ to the VM and follow dist/deploy-bundle/RUN-ON-VM.md.
#
# This validates the DETECTION CONTENT (rules.yml, the fallback path the agent
# runs by default). It does NOT exercise the signed-feed delivery path — that is
# a separate test (Pack.Enabled=true + a signed .canonical/.sig on the VM).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

AGENT_CSPROJ="src/TinySocs.Agent/TinySocs.Agent.csproj"
PUBLISH_DIR="dist/agent-win-x64"
BUNDLE="dist/deploy-bundle"

echo "==> Building self-contained win-x64 agent (Release)…"
dotnet publish "$AGENT_CSPROJ" -c Release -o "$PUBLISH_DIR" --nologo -v q \
  | grep -Ei 'error|warning CS' || true

EXE="$PUBLISH_DIR/TinySocs.Agent.exe"
if [[ ! -f "$EXE" ]]; then
  echo "ERROR: build did not produce $EXE" >&2
  exit 1
fi
echo "    built $EXE ($(du -h "$EXE" | cut -f1))"

echo "==> Assembling bundle at $BUNDLE …"
rm -rf "$BUNDLE"
mkdir -p "$BUNDLE/scripts" "$BUNDLE/tests" "$BUNDLE/docs"

# Agent + rules (deploy script reads <SourceDir>/TinySocs.Agent.exe and <SourceDir>/rules.yml)
cp "$EXE" "$BUNDLE/TinySocs.Agent.exe"
cp packaging/detection/rules.yml "$BUNDLE/rules.yml"

# Deploy + harness (harness treats its parent as repoRoot: writes tests/atomic-results.json
# and docs/detection-efficacy.md, so it needs the tests/ and docs/ dirs beside it)
cp scripts/Deploy-AgentUpdate.ps1 "$BUNDLE/scripts/"
cp scripts/Demo-Ransomware.ps1 "$BUNDLE/scripts/"
cp tests/*.ps1 "$BUNDLE/tests/"
cp tests/atomic-tests.yaml "$BUNDLE/tests/"

# Agent config with FIM enabled (for the ransomware demo). Deploying it turns on
# File Integrity Monitoring + the seeded canary. Kept separate so the operator
# opts in (it overwrites the VM's agent-config.yml).
cp config/agent-config.yml "$BUNDLE/agent-config.yml"

# Snapshot of the enabled ruleset for a sanity check on the VM.
ENABLED_COUNT="$(python3 - <<'PY'
import yaml
d = yaml.safe_load(open("packaging/detection/rules.yml"))
print(sum(1 for r in d["rules"] if r.get("enabled")))
PY
)"

cat > "$BUNDLE/RUN-ON-VM.md" <<EOF
# Validate the pilot ruleset on the Windows VM

This bundle deploys the current \`rules.yml\` ($ENABLED_COUNT enabled rules) to an
already-installed TinySocs agent and runs the Atomic Red Team harness against it.
No installer rebuild, no pack signing — the agent runs the rules.yml path by default.

## Prerequisites (already true on your validation VM)
- TinySocs is installed (agent + bundled OpenSearch running).
- You are in an **elevated PowerShell** (Run as Administrator).
- Copy this whole folder to the VM first, then \`cd\` into it.

## Steps

1. **Deploy the new binary + rules and enable audit policies:**
   \`\`\`powershell
   .\\scripts\\Deploy-AgentUpdate.ps1 -SourceDir .
   \`\`\`
   Watch for: \`Detection engine updated with $ENABLED_COUNT rule(s)\` — that confirms
   the pilot set loaded. If you see fewer, the agent read an older rules.yml.

2. **Run the harness (skips the ART install if already present):**
   \`\`\`powershell
   .\\tests\\Test-AtomicDetection.ps1 -SkipInstall
   \`\`\`
   Results are written to \`tests\\atomic-results.json\` and a report to
   \`docs\\detection-efficacy.md\`.

3. **Send \`tests\\atomic-results.json\` back** for the efficacy write-up.

## What to expect (not failures)
- **6 techniques report as gaps** (deferred by design): T1003.001, T1547.001,
  T1218.011, T1055, T1027, T1047.
- **3 SKIPs**: T1562.001 (needs Tamper Protection off), T1003.003 (needs a DC),
  T1565.001 (needs the FIM module enabled).
- **TS-020** (scheduled task) is the one to watch: a MISS there confirms the
  suspected 4698 XML-parsing bug — a pipeline issue, not a rule issue.

## Ransomware demo (TS-113) — the showcase

FIM (File Integrity Monitoring) powers the ransomware canary. To enable it and run
the demo:

1. **Deploy the FIM-enabled config and restart the agent** (elevated):
   \`\`\`powershell
   Copy-Item .\\agent-config.yml 'C:\\ProgramData\\TinySocs\\Collector\\agent-config.yml' -Force
   Restart-Service TinySocsAgent
   Start-Sleep 20   # let the agent seed the canary + build the FIM baseline
   \`\`\`
   The agent seeds ~60 decoy files in \`C:\\ProgramData\\TinySocs\\Canary\`.

2. **Run the simulated ransomware sweep:**
   \`\`\`powershell
   .\\scripts\\Demo-Ransomware.ps1
   \`\`\`
   It modifies every decoy (safe — only the canary is touched). Watch a CRITICAL
   \`fim_mass_modification\` alert land on the dashboard. Pass \`-Password <opensearch>\`
   to also get an automated DETECTED confirmation in the console.

## Notes
- Most enabled rules are Security-log based, so Sysmon is largely optional. If the
  VM has Sysmon, add \`-SysmonAvailable\` to step 2 to also run the Sysmon-gated tests.
- To run a single technique quickly: \`Test-AtomicDetection.ps1 -SkipInstall -OnlyTechnique T1087.001\`.
EOF

echo "    wrote $BUNDLE/RUN-ON-VM.md"
echo ""
echo "==> Bundle ready: $BUNDLE"
find "$BUNDLE" -type f | sort | sed 's/^/    /'
echo ""
echo "Next: copy $BUNDLE/ to the VM and follow RUN-ON-VM.md"
