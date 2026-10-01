<#
.SYNOPSIS
    Live verification for SentinelEDR's 8 newest Sigma rules (SIG-080..SIG-087).

.DESCRIPTION
    Unlike tests/alert_simulator.py, which injects Alert objects directly and
    never touches the real detection code, this script triggers each pattern
    for real: it spawns real (harmless) processes with the exact process
    name / command-line signature each rule looks for, so your actual running
    SentinelEDR instance has to catch them via genuine psutil scanning.

    SAFE BY DESIGN:
      - No real file is downloaded — the one network call (SIG-082) points at
        an unreachable local port (127.0.0.1:1) and fails instantly.
      - No real persistence is created (no registry keys, no WMI subscription,
        no scheduled task) — the "attack" commands are queried/no-op forms or
        just echoed as arguments, never actually executed.
      - SIG-080 / SIG-081 need a process to be *named* winword.exe / fodhelper.exe
        specifically (that's what those rules match on) — since we don't have
        Office or a real UAC-bypass target here, we copy the legitimate,
        signed cmd.exe to a temp file with that name. This is the standard
        "atomic test" technique: it exercises the name-matching logic without
        needing the real application, and does nothing cmd.exe wouldn't
        normally do.

.USAGE
    1. In one terminal: python sentinel.py --dry-run
    2. In another terminal (same machine): .\tests\live_rule_check.ps1
    3. Watch http://localhost:8888 (Live Alerts tab) or sentinel_edr.log —
       you should see SIG-080 through SIG-087 appear within ~10s of each step.
    4. Run with -Cleanup afterward to remove the two copied temp binaries.
#>

param(
    [switch]$Cleanup,
    [string]$Only = ""   # e.g. -Only "80,81,83,86"
)

$temp = $env:TEMP
$hold = "ping -n 19 127.0.0.1 >nul"

if ($Cleanup) {
    Remove-Item "$temp\winword.exe", "$temp\fodhelper.exe" -Force -ErrorAction SilentlyContinue
    Write-Host "Cleaned up temp copies."
    exit
}

# Deliberately NOT typed as [int[]]$Only above: when this script is invoked
# externally via `-File` (as opposed to typed directly inside a PowerShell
# session), an array-typed parameter doesn't receive "80,81,83,86" as four
# numbers — it gets the raw string and falls back to converting it
# character-by-character, silently dropping the commas and producing eight
# stray single-digit values. Taking it as a plain string and splitting it
# ourselves works the same regardless of how the script is launched.
$OnlyIds = @()
if ($Only) {
    $OnlyIds = $Only -split ',' | ForEach-Object { [int]$_.Trim() }
}

function ShouldRun($id) {
    return ($OnlyIds.Count -eq 0) -or ($OnlyIds -contains $id)
}

function Step($id, $name, [scriptblock]$action) {
    if (-not (ShouldRun $id)) { return }
    Write-Host "`n--> SIG-$id`: $name"
    try {
        $proc = & $action
        if ($proc -and $proc.Id) {
            Start-Sleep -Milliseconds 500
            $stillAlive = Get-Process -Id $proc.Id -ErrorAction SilentlyContinue
            if ($stillAlive) {
                Write-Host "    started PID $($proc.Id), still running after 0.5s - good"
            } else {
                Write-Host "    WARNING: PID $($proc.Id) already exited almost immediately"
            }
        }
    } catch {
        Write-Host "    ERROR: $($_.Exception.Message)"
    }
    Start-Sleep -Seconds 19
}

Write-Host "== SentinelEDR live rule verification =="
Write-Host "Make sure 'python sentinel.py --dry-run' is running in another window."
if ($OnlyIds.Count -gt 0) {
    $onlyDisplay = $OnlyIds -join ', '
    Write-Host "Running only: $onlyDisplay"
}
Write-Host "Watch http://localhost:8888 while this runs.`n"

Step 80 "fake winword.exe -> powershell.exe" {
    Copy-Item "$env:WINDIR\System32\cmd.exe" "$temp\winword.exe" -Force
    if (-not (Test-Path "$temp\winword.exe")) {
        Write-Host "    Copy failed or was removed (Defender may have quarantined it) - skipping"
        return
    }
    Start-Process "$temp\winword.exe" -ArgumentList "/c powershell.exe -NoProfile -Command Start-Sleep -Seconds 18" -WindowStyle Hidden -PassThru
}

Step 81 "fake fodhelper.exe -> cmd.exe" {
    Copy-Item "$env:WINDIR\System32\cmd.exe" "$temp\fodhelper.exe" -Force
    if (-not (Test-Path "$temp\fodhelper.exe")) {
        Write-Host "    Copy failed or was removed (Defender may have quarantined it) - skipping"
        return
    }
    # The inner cmd.exe (child of fake fodhelper.exe) must be the SAME
    # process that stays alive for the hold duration - previously "whoami"
    # and the hold ping were two separate sequential children of fodhelper,
    # so the one matching the rule (cmd.exe) exited in milliseconds while
    # the long-lived one (ping.exe) didn't match the rule at all. Nesting
    # both inside the inner cmd.exe's own quoted /c argument keeps the
    # actually-matching child alive the whole time, mirroring SIG-080.
    Start-Process "$temp\fodhelper.exe" -ArgumentList "/c cmd.exe /c ""whoami & $hold""" -WindowStyle Hidden -PassThru
}

Step 82 "bitsadmin /transfer (loopback, fails instantly)" {
    Start-Process "bitsadmin.exe" `
        -ArgumentList "/transfer sentinelcheck /download /priority normal http://127.0.0.1:1/nofile.txt $temp\nofile.txt" `
        -WindowStyle Hidden -PassThru
}

# Rewritten to avoid actually invoking the AmsiUtils reflection call, which
# Defender/AMSI's own real-time protection blocked outright last run
# ("Access is denied") before the process lived long enough to be scanned.
# The rule only checks the cmdline SUBSTRING, so echoing it via cmd.exe
# validates the same detection without tripping AMSI itself.
Step 83 "amsiutils string (real powershell.exe process, inert text only)" {
    # SIG-083 requires the PROCESS to actually be named powershell.exe/pwsh.exe
    # - running cmd.exe and merely echoing the word "amsiutils" never matched
    # the rule's process_name_any at all, regardless of the cmdline text.
    # This launches a real powershell.exe whose command line contains the
    # trigger substring as an inert string literal - never actually calling
    # [Ref].Assembly.GetType(...AmsiUtils), so it shouldn't trip AMSI itself
    # the way the original version did ("Access is denied").
    $args = @("-NoProfile", "-Command", "'amsiutils reference test' | Out-Null; Start-Sleep -Seconds 18")
    Start-Process "powershell.exe" -ArgumentList $args -WindowStyle Hidden -PassThru
}

Step 84 "WMI __EventFilter cmdline pattern (help query / echo only)" {
    if (Get-Command wmic.exe -ErrorAction SilentlyContinue) {
        Start-Process "wmic.exe" -ArgumentList '/namespace:\\root\subscription PATH __EventFilter /?' -WindowStyle Hidden -PassThru
    } else {
        $args = @("-NoProfile", "-Command",
                  "'__EventFilter root\subscription CommandLineEventConsumer' | Out-Null; Start-Sleep -Seconds 18")
        Start-Process "powershell.exe" -ArgumentList $args -WindowStyle Hidden -PassThru
    }
}

Step 85 "kerberoast-style cmdline (echoed, not executed)" {
    Start-Process "cmd.exe" -ArgumentList "/c echo rubeus kerberoast /outfile:hashes.txt & $hold" -WindowStyle Hidden -PassThru
}

Step 86 "wmiexec.py-style cmdline (echoed, not executed)" {
    Start-Process "cmd.exe" -ArgumentList "/c echo python wmiexec.py test:test@127.0.0.1 & $hold" -WindowStyle Hidden -PassThru
}

Step 87 "Get-Clipboard capture" {
    $args = @("-NoProfile", "-Command", "Get-Clipboard | Out-Null; Start-Sleep -Seconds 18")
    Start-Process "powershell.exe" -ArgumentList $args -WindowStyle Hidden -PassThru
}

Write-Host "`nDone. Give the dashboard ~5-10s to refresh, then check Live Alerts."
Write-Host "Run '.\tests\live_rule_check.ps1 -Cleanup' afterward to remove the two copied temp binaries."
