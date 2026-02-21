# tests/Test-InstallerModule.ps1
# Pester 5 smoke tests for TinySocs.Installer.psm1
# Validates that the module loads and exports expected functions.
#
# Usage:
#   Install-Module Pester -Force -MinimumVersion 5.0
#   Invoke-Pester -Path tests/Test-InstallerModule.ps1 -Output Detailed

BeforeAll {
    $modulePath = Join-Path $PSScriptRoot ".." "modules" "TinySocs.Installer.psm1"
    if (-not (Test-Path $modulePath)) {
        throw "TinySocs.Installer.psm1 not found at: $modulePath"
    }
    Import-Module $modulePath -Force -ErrorAction Stop
}

Describe "TinySocs.Installer Module Import" {
    It "imports without errors" {
        Get-Module TinySocs.Installer | Should -Not -BeNullOrEmpty
    }
}

Describe "Core Function Exports" {
    It "exports Get-TinySocsDataRoot" {
        Get-Command Get-TinySocsDataRoot -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
    }
    It "exports Test-TinySocsHealth" {
        Get-Command Test-TinySocsHealth -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
    }
    It "exports Invoke-TinySocsSmokeTest" {
        Get-Command Invoke-TinySocsSmokeTest -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
    }
    It "exports Set-TinySocsYamlScalar" {
        Get-Command Set-TinySocsYamlScalar -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
    }
}

Describe "Phase 14 Function Exports" {
    It "exports New-TinySocsDashboardCert" {
        Get-Command New-TinySocsDashboardCert -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
    }
    It "exports Install-TinySocsSysmon" {
        Get-Command Install-TinySocsSysmon -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
    }
    It "exports Uninstall-TinySocsSysmon" {
        Get-Command Uninstall-TinySocsSysmon -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
    }
}

Describe "Set-TinySocsYamlScalar" {
    It "sets a scalar value in a YAML file" {
        $tempFile = [System.IO.Path]::GetTempFileName()
        try {
            Set-Content -Path $tempFile -Value "key1: old_value`nkey2: keep_me" -Encoding UTF8
            Set-TinySocsYamlScalar -Path $tempFile -Key "key1" -Value "new_value"
            $content = Get-Content $tempFile -Raw
            $content | Should -Match "key1: new_value"
            $content | Should -Match "key2: keep_me"
        } finally {
            Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
        }
    }

    It "adds a new key if not present" {
        $tempFile = [System.IO.Path]::GetTempFileName()
        try {
            Set-Content -Path $tempFile -Value "existing: value" -Encoding UTF8
            Set-TinySocsYamlScalar -Path $tempFile -Key "new_key" -Value "new_value"
            $content = Get-Content $tempFile -Raw
            $content | Should -Match "existing: value"
            $content | Should -Match "new_key: new_value"
        } finally {
            Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
        }
    }
}
