param(
  [ValidateSet("start", "stop", "restart", "status")]
  [string]$Action = "start",
  [int]$Port = 5001
)

$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$pidFile = Join-Path $root ".server.pid"
$entry = Join-Path $root "backend\server.js"

function Write-Info([string]$msg) { Write-Host $msg }
function Write-Warn([string]$msg) { Write-Host $msg -ForegroundColor Yellow }
function Write-Err([string]$msg)  { Write-Host $msg -ForegroundColor Red }

function Get-PidFromFile() {
  if (!(Test-Path $pidFile)) { return $null }
  try {
    $raw = (Get-Content -Path $pidFile -ErrorAction Stop | Select-Object -First 1).Trim()
    if ($raw -match "^\d+$") { return [int]$raw }
  } catch { }
  return $null
}

function Get-PidListeningOnPort([int]$p) {
  try {
    $conn = Get-NetTCPConnection -LocalPort $p -State Listen -ErrorAction Stop | Select-Object -First 1
    if ($conn -and $conn.OwningProcess) { return [int]$conn.OwningProcess }
  } catch { }
  return $null
}

function Is-Running([int]$pid) {
  if (!$pid) { return $false }
  try {
    $p = Get-Process -Id $pid -ErrorAction Stop
    return $true
  } catch {
    return $false
  }
}

function Start-Server() {
  if (!(Test-Path $entry)) {
    Write-Err "Cannot find backend entry: $entry"
    exit 1
  }

  $existingPid = Get-PidFromFile
  if (Is-Running $existingPid) {
    Write-Info "Server already running (PID $existingPid)."
    return
  }

  $portPid = Get-PidListeningOnPort $Port
  if ($portPid -and (Is-Running $portPid)) {
    Write-Warn "Port $Port is already in use by PID $portPid. Use: .\server-control.ps1 stop -Port $Port"
    return
  }

  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = "node"
  $psi.Arguments = "`"$entry`""
  $psi.WorkingDirectory = $root
  $psi.UseShellExecute = $false
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError = $true
  $psi.CreateNoWindow = $false

  $proc = New-Object System.Diagnostics.Process
  $proc.StartInfo = $psi
  $null = $proc.Start()

  # Save PID so we can stop it later
  Set-Content -Path $pidFile -Value $proc.Id -Encoding ASCII

  Write-Info "Server started (PID $($proc.Id))."
  Write-Info "Open: http://localhost:$Port"
  Write-Info "Log:  .\logs\ (server writes here)"
}

function Stop-Server() {
  $pid = Get-PidFromFile
  if (Is-Running $pid) {
    try {
      Stop-Process -Id $pid -Force -ErrorAction Stop
      Write-Info "Stopped server (PID $pid)."
    } catch {
      Write-Warn "Failed to stop PID $pid: $($_.Exception.Message)"
    }
  } else {
    $portPid = Get-PidListeningOnPort $Port
    if (Is-Running $portPid) {
      try {
        Stop-Process -Id $portPid -Force -ErrorAction Stop
        Write-Info "Stopped process on port $Port (PID $portPid)."
      } catch {
        Write-Warn "Failed to stop PID $portPid on port $Port: $($_.Exception.Message)"
      }
    } else {
      Write-Info "No running server found (pid file missing/stale, port $Port not listening)."
    }
  }

  if (Test-Path $pidFile) {
    try { Remove-Item -Path $pidFile -Force -ErrorAction SilentlyContinue } catch { }
  }
}

function Status-Server() {
  $pid = Get-PidFromFile
  if (Is-Running $pid) {
    Write-Info "RUNNING (PID $pid) → http://localhost:$Port"
    return
  }
  $portPid = Get-PidListeningOnPort $Port
  if (Is-Running $portPid) {
    Write-Info "RUNNING (PID $portPid listening on $Port) → http://localhost:$Port"
    Write-Warn "Note: pid file missing/stale. Run stop to clean up."
    return
  }
  Write-Info "STOPPED"
}

switch ($Action) {
  "start"   { Start-Server }
  "stop"    { Stop-Server }
  "restart" { Stop-Server; Start-Server }
  "status"  { Status-Server }
}

