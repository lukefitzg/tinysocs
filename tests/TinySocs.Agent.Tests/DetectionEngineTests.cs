using Microsoft.Extensions.Logging.Abstractions;
using TinySocs.Agent.Configuration;
using TinySocs.Agent.Detection;
using TinySocs.Agent.Models;
using Xunit;

namespace TinySocs.Agent.Tests
{
    /// <summary>
    /// Behavioural tests for the shipped pilot ruleset. These load the REAL
    /// packaging/detection/rules.yml through RuleLoader and fire synthetic
    /// events at the DetectionEngine — no Windows Event Log required — so they
    /// verify the actual definitions we ship, not hand-copied ones.
    ///
    /// Focus: the four fidelity fixes (TS-070/071/090/062) that added a
    /// field_match so the rule matches its description instead of matching every
    /// event, plus the enabled/disabled set of the pilot base pack.
    /// </summary>
    public class DetectionEngineTests
    {
        // ---- fixtures ----------------------------------------------------

        private static string RepoRoot()
        {
            var dir = new DirectoryInfo(AppContext.BaseDirectory);
            while (dir != null)
            {
                if (File.Exists(Path.Combine(dir.FullName, "packaging", "detection", "rules.yml")))
                {
                    return dir.FullName;
                }
                dir = dir.Parent;
            }
            throw new DirectoryNotFoundException("could not locate repo root (packaging/detection/rules.yml)");
        }

        private static string RulesYmlPath() =>
            Path.Combine(RepoRoot(), "packaging", "detection", "rules.yml");

        private static List<DetectionRule> LoadShippedRules() =>
            new RuleLoader(NullLogger<RuleLoader>.Instance).LoadRules(RulesYmlPath());

        private static DetectionEngine EngineWith(params string[] ruleIds)
        {
            var all = LoadShippedRules();
            var picked = ruleIds.Length == 0
                ? all
                : all.Where(r => ruleIds.Contains(r.Id)).ToList();
            var engine = new DetectionEngine(NullLogger<DetectionEngine>.Instance);
            engine.UpdateRules(picked);
            return engine;
        }

        // Build a Windows Security-style event with nested winlog.event_data.
        private static AgentEvent WinEvent(int eventId, string channel,
            Dictionary<string, object?> eventData, string computer = "PC-01")
        {
            return new AgentEvent
            {
                Ts = DateTimeOffset.UtcNow,
                Channel = channel,
                EventId = eventId,
                Body = new Dictionary<string, object?>
                {
                    ["winlog"] = new Dictionary<string, object?>
                    {
                        ["computer_name"] = computer,
                        ["event_data"] = eventData,
                    },
                },
            };
        }

        // Feed the same event n times; return the number of alerts produced.
        private static int FireN(DetectionEngine engine, Func<AgentEvent> make, int n)
        {
            int alerts = 0;
            for (int i = 0; i < n; i++)
            {
                alerts += engine.EvaluateEvent(make()).Count;
            }
            return alerts;
        }

        // ---- TS-071 rdp_brute_force: LogonType 10 filter -----------------

        [Fact]
        public void Ts071_FiresOnRdpLogonType10()
        {
            var engine = EngineWith("TS-071");
            // threshold 10 within 10 min, grouped by IP, LogonType must be 10.
            int alerts = FireN(engine, () => WinEvent(4625, "Security",
                new() { ["IpAddress"] = "203.0.113.9", ["LogonType"] = "10" }), 10);
            Assert.True(alerts >= 1, "RDP (LogonType 10) brute force should fire TS-071");
        }

        [Fact]
        public void Ts071_DoesNotFireOnNetworkLogonType3()
        {
            var engine = EngineWith("TS-071");
            // Same volume, but LogonType 3 (network) — must NOT fire. This is the
            // fidelity fix: before the filter, TS-071 double-alerted on any 4625 burst.
            int alerts = FireN(engine, () => WinEvent(4625, "Security",
                new() { ["IpAddress"] = "203.0.113.9", ["LogonType"] = "3" }), 20);
            Assert.Equal(0, alerts);
        }

        // ---- TS-070 psexec_usage: PSEXESVC service-name filter -----------

        [Fact]
        public void Ts070_FiresOnPsexesvcServiceInstall()
        {
            var engine = EngineWith("TS-070");
            int alerts = engine.EvaluateEvent(WinEvent(7045, "System",
                new() { ["ServiceName"] = "PSEXESVC", ["ImagePath"] = @"C:\Windows\PSEXESVC.exe" })).Count;
            Assert.Equal(1, alerts);
        }

        [Fact]
        public void Ts070_DoesNotFireOnOrdinaryServiceInstall()
        {
            var engine = EngineWith("TS-070");
            int alerts = engine.EvaluateEvent(WinEvent(7045, "System",
                new() { ["ServiceName"] = "AdobeUpdateService", ["ImagePath"] = @"C:\Program Files\Adobe\update.exe" })).Count;
            Assert.Equal(0, alerts);
        }

        // ---- TS-090 service_install_suspicious: ImagePath filter ---------

        [Fact]
        public void Ts090_FiresOnServiceFromTempPath()
        {
            var engine = EngineWith("TS-090");
            int alerts = engine.EvaluateEvent(WinEvent(7045, "System",
                new() { ["ServiceName"] = "TotallyLegit", ["ImagePath"] = @"C:\Windows\Temp\art-test.exe" })).Count;
            Assert.Equal(1, alerts);
        }

        [Fact]
        public void Ts090_DoesNotFireOnServiceFromProgramFiles()
        {
            var engine = EngineWith("TS-090");
            int alerts = engine.EvaluateEvent(WinEvent(7045, "System",
                new() { ["ServiceName"] = "MSSQLSERVER", ["ImagePath"] = @"C:\Program Files\Microsoft SQL Server\sqlservr.exe" })).Count;
            Assert.Equal(0, alerts);
        }

        // ---- TS-062 ntds_dit_access: ObjectName filter -------------------

        [Fact]
        public void Ts062_FiresOnNtdsOrHiveAccess()
        {
            var engine = EngineWith("TS-062");
            int ntds = engine.EvaluateEvent(WinEvent(4663, "Security",
                new() { ["ObjectName"] = @"C:\Windows\NTDS\ntds.dit" })).Count;
            var engine2 = EngineWith("TS-062");
            int sam = engine2.EvaluateEvent(WinEvent(4663, "Security",
                new() { ["ObjectName"] = @"C:\Windows\System32\config\SAM" })).Count;
            Assert.Equal(1, ntds);
            Assert.Equal(1, sam);
        }

        [Fact]
        public void Ts062_DoesNotFireOnOrdinaryFileAccess()
        {
            var engine = EngineWith("TS-062");
            // Broad file-system SACLs would storm 4663 without the filter.
            int alerts = FireN(engine, () => WinEvent(4663, "Security",
                new() { ["ObjectName"] = @"C:\Users\alice\Documents\quarterly.xlsx" }), 5);
            Assert.Equal(0, alerts);
        }

        // ---- core sanity: TS-001 threshold, TS-082 AMSI -----------------

        [Fact]
        public void Ts001_FiresAtThresholdNotBelow()
        {
            var below = EngineWith("TS-001");
            int a1 = FireN(below, () => WinEvent(4625, "Security",
                new() { ["TargetUserName"] = "victimacct" }), 14);
            Assert.Equal(0, a1);

            var at = EngineWith("TS-001");
            int a2 = FireN(at, () => WinEvent(4625, "Security",
                new() { ["TargetUserName"] = "victimacct" }), 15);
            Assert.True(a2 >= 1, "15 failed logons for one account should fire TS-001");
        }

        [Fact]
        public void Ts082_FiresOnAmsiBypassStringOnly()
        {
            var hit = EngineWith("TS-082");
            int a1 = hit.EvaluateEvent(WinEvent(4104, "Microsoft-Windows-PowerShell/Operational",
                new() { ["ScriptBlockText"] = "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')" })).Count;
            Assert.Equal(1, a1);

            var miss = EngineWith("TS-082");
            int a2 = miss.EvaluateEvent(WinEvent(4104, "Microsoft-Windows-PowerShell/Operational",
                new() { ["ScriptBlockText"] = "Get-Process | Sort-Object CPU" })).Count;
            Assert.Equal(0, a2);
        }

        // ---- pilot base-pack composition --------------------------------

        [Fact]
        public void PilotSet_EnablesExactlyTheHighFidelityRules()
        {
            var enabled = LoadShippedRules().Select(r => r.Id).OrderBy(x => x).ToArray();

            var expected = new[]
            {
                "TS-001", "TS-002", "TS-010", "TS-020", "TS-061", "TS-062",
                "TS-070", "TS-071", "TS-080", "TS-080-sys", "TS-081", "TS-082",
                "TS-090", "TS-110", "TS-113", "TS-114", "TS-120", "TS-130",
                "TS-131", "TS-132",
            }.OrderBy(x => x).ToArray();

            Assert.Equal(expected, enabled);
        }

        [Theory]
        [InlineData("TS-060")]  // dead: Sysmon Event 10 not logged
        [InlineData("TS-072")]  // matched every 7045
        [InlineData("TS-091")]  // matched every Sysmon registry event
        [InlineData("TS-092")]  // matched every Sysmon FileCreate
        [InlineData("TS-134")]  // encoded-command FP storm from RMM
        [InlineData("TS-135")]  // rundll32 noise
        [InlineData("TS-136")]  // WMI-spawn noise
        [InlineData("TS-111")]  // duplicate of TS-110
        [InlineData("TS-112")]  // duplicate of TS-110
        public void PilotSet_ExcludesNoisyRules(string ruleId)
        {
            var enabled = LoadShippedRules().Select(r => r.Id).ToHashSet();
            Assert.DoesNotContain(ruleId, enabled);
        }

        // ---- cross-language signing proof (local artifact; skipped in CI) --

        [Fact]
        public void SignedBasePack_VerifiesAndLoadsInCSharp()
        {
            // The .canonical/.sig are gitignored build artifacts (signed by the
            // dev key). When present locally, prove the C# PackLoader accepts the
            // Python-signed bytes and loads exactly the enabled pilot set.
            var canonical = Path.Combine(RepoRoot(), "packs", "base", "2026.27", "pack.yml.canonical");
            if (!File.Exists(canonical))
            {
                return; // signing artifact absent (e.g. CI) — covered by PackLoaderTests
            }

            var pubKey = File.ReadAllText(Path.Combine(RepoRoot(), "keys", "tinysocs-2026.pub")).Trim();
            var cfg = new ContentPackConfig
            {
                Enabled = true,
                PackFile = canonical,
                PublicKey = pubKey,
                SigningKeyId = "tinysocs-2026",
            };

            var result = new PackLoader(NullLogger<PackLoader>.Instance, cfg).Load();

            Assert.True(result.Ok, result.Reason);
            Assert.Equal(20, result.Rules.Count); // enabled rules only
            Assert.DoesNotContain(result.Rules, r => r.Id == "TS-134");
            Assert.Contains(result.Rules, r => r.Id == "TS-071" && r.Condition.FieldMatch != null);
        }
    }
}
