# ACRS v2 helper for Windows PowerShell (no make needed). SIMULATION ONLY.
# Usage:  .\acrs.ps1 up | open | down | logs | test | seed | reset | scenarios
#         .\acrs.ps1 demo tier1_c2_hr            (success path)
#         .\acrs.ps1 demo tier1_c2_hr failure    (default failure mode of the scenario)
param(
  [Parameter(Position = 0)][string]$Command = "help",
  [Parameter(Position = 1)][string]$Scenario = "tier1_c2_hr",
  [Parameter(Position = 2)][string]$Mode = "success"
)
$ErrorActionPreference = "Stop"
$Api = "http://localhost:8000/api/v1"

function Get-EnvValue([string]$Name) {
  $line = Get-Content .env | Where-Object { $_ -match "^$Name=" } | Select-Object -First 1
  return ($line -replace "^$Name=", "").Trim()
}

function Get-Headers([string]$User = "analyst") {
  $body = @{ username = $User; password = (Get-EnvValue "ACRS_SEED_PASSWORD") } | ConvertTo-Json
  $tok = (Invoke-RestMethod -Method Post -Uri "$Api/auth/login" -ContentType "application/json" -Body $body).access_token
  return @{ Authorization = "Bearer $tok" }
}

switch ($Command) {
  "up" {
    if (-not (Test-Path .env)) {
      Copy-Item .env.example .env
      Write-Host "Created .env from .env.example. Change the change-me values, then run again." -ForegroundColor Yellow
      exit 1
    }
    docker compose up --build -d
    Write-Host "Console:  http://localhost:8080" -ForegroundColor Cyan
    Write-Host "API docs: http://localhost:8000/docs" -ForegroundColor Cyan
  }
  "down" { docker compose down }
  "logs" { docker compose logs -f backend }
  "test" { docker compose exec backend python -m pytest -q }
  "open" { Start-Process "http://localhost:8080" }
  "seed" { docker compose exec backend python -m app.seed }
  "reset" { docker compose down -v }
  "scenarios" {
    Invoke-RestMethod -Uri "$Api/sim/scenarios" -Headers (Get-Headers "viewer") |
      Format-Table id, category, default_failure, edge_case, title_en -AutoSize
  }
  "demo" {
    $h = Get-Headers "analyst"
    $body = @{ mode = $Mode } | ConvertTo-Json
    $run = Invoke-RestMethod -Method Post -Uri "$Api/sim/scenarios/$Scenario/run" -Headers $h `
      -ContentType "application/json" -Body $body
    Write-Host "Scenario $Scenario ($Mode, failure=$($run.failure)) -> incidents: $($run.incident_ids -join ', ')" -ForegroundColor Cyan
    $seen = @{}
    $done = @{}
    $stop = @("CLOSE", "ESCALATED", "ROLLED_BACK", "PENDING_APPROVAL", "MONITOR")
    $until = (Get-Date).AddSeconds(240)
    while ($done.Count -lt $run.incident_ids.Count -and (Get-Date) -lt $until) {
      foreach ($id in $run.incident_ids) {
        if ($done.ContainsKey($id)) { continue }
        $d = Invoke-RestMethod -Uri "$Api/incidents/$id" -Headers $h
        $n = if ($seen.ContainsKey($id)) { $seen[$id] } else { 0 }
        $tr = @($d.transitions)
        for ($i = $n; $i -lt $tr.Count; $i++) {
          $t = $tr[$i]
          Write-Host ("{0}  {1,-8} {2,-16} by {3}" -f $t.at.Substring(11, 12), $id.Substring(0, 8), $t.to_state, $t.actor)
        }
        $seen[$id] = $tr.Count
        $inc = $d.incident
        if ($stop -contains $inc.state -or $inc.hold_reason) {
          $done[$id] = $true
          Write-Host ("  => {0} | level={1} risk={2} conf={3}% mttc={4}ms" -f $inc.state, $inc.level, $inc.risk_score, $inc.confidence, $inc.mttc_ms) -ForegroundColor Green
          if ($inc.hold_reason) { Write-Host "  => paused: $($inc.hold_reason)" -ForegroundColor Yellow }
          if ($inc.escalation_reason) { Write-Host "  => EMERGENCY QUEUE: $($inc.escalation_reason)" -ForegroundColor Red }
        }
      }
      Start-Sleep -Milliseconds 700
    }
  }
  default {
    Write-Host "Commands: up, open, down, logs, test, seed, reset, scenarios, demo <scenario> [success|failure]"
  }
}
