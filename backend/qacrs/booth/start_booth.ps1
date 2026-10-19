# HASSAN booth on the Windows laptop (display + decisions).
#   powershell -ExecutionPolicy Bypass -File start_booth.ps1                      # simulation only
#   powershell -ExecutionPolicy Bypass -File start_booth.ps1 -Agent 192.168.1.50   # with the Linux mini hospital
param([string]$Agent = "", [double]$SolverBudget = 0)
$ErrorActionPreference = "Stop"
$backend = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$secret = Join-Path $env:USERPROFILE ".hassan"
if (-not (Test-Path $secret)) { New-Item -ItemType Directory $secret | Out-Null }
# secrets readable by this user only
icacls $secret /inheritance:r /grant:r "$($env:USERNAME):(OI)(CI)F" | Out-Null
if ($Agent -and -not (Test-Path (Join-Path $secret "plan_key"))) {
  Write-Host "Copy plan_key from the Linux laptop (USB) to $secret\plan_key first." -ForegroundColor Red; exit 1
}
$pyArgs = @("-m", "qacrs.booth.server", "--port", "8800", "--auto-budget")
if ($Agent) { $pyArgs += @("--agent", "$($Agent):8900") }
if ($SolverBudget -gt 0) { $pyArgs += @("--solver-budget", "$SolverBudget") }
Set-Location $backend
Start-Process "http://127.0.0.1:8800/"
python @pyArgs
