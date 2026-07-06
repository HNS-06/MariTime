# ╔══════════════════════════════════════════════════════════════╗
# ║          MARI TIME — One-Command Launcher                    ║
# ║          Starts all components and opens the TUI             ║
# ╚══════════════════════════════════════════════════════════════╝

param(
    [switch]$Demo,       # Force demo mode (no backend needed)
    [switch]$Live,       # Force live mode
    [switch]$TuiOnly,    # Launch only the TUI dashboard
    [switch]$InstallDeps # Install Python TUI dependencies first
)

$ErrorActionPreference = "Stop"
$Root    = Split-Path -Parent $PSScriptRoot
$Scripts = Join-Path $Root "scripts"
$Backend = Join-Path $Root "backend"

# ── Colors ──────────────────────────────────────────────────────────────────
function Write-Violet  { param($msg) Write-Host $msg -ForegroundColor Magenta }
function Write-Success { param($msg) Write-Host $msg -ForegroundColor Green }
function Write-Warn    { param($msg) Write-Host $msg -ForegroundColor Yellow }
function Write-Err     { param($msg) Write-Host $msg -ForegroundColor Red }

# ── Banner ──────────────────────────────────────────────────────────────────
function Show-Banner {
    Write-Host ""
    Write-Violet "  ███╗   ███╗ █████╗ ██████╗ ██╗    ████████╗██╗███╗   ███╗███████╗"
    Write-Violet "  ████╗ ████║██╔══██╗██╔══██╗██║    ╚══██╔══╝██║████╗ ████║██╔════╝"
    Write-Violet "  ██╔████╔██║███████║██████╔╝██║       ██║   ██║██╔████╔██║█████╗  "
    Write-Violet "  ██║╚██╔╝██║██╔══██║██╔══██╗██║       ██║   ██║██║╚██╔╝██║██╔══╝  "
    Write-Violet "  ██║ ╚═╝ ██║██║  ██║██║  ██║███████╗  ██║   ██║██║ ╚═╝ ██║███████╗"
    Write-Violet "  ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝  ╚═╝   ╚═╝╚═╝     ╚═╝╚══════╝"
    Write-Host ""
    Write-Host "  Modbus OT/ICS Security Monitor  |  Terminal Dashboard Launcher" -ForegroundColor DarkMagenta
    Write-Host "  ─────────────────────────────────────────────────────────────" -ForegroundColor DarkMagenta
    Write-Host ""
}

# ── Install Python TUI deps ──────────────────────────────────────────────────
function Install-TuiDeps {
    Write-Violet "  [1/1] Installing Python TUI dependencies..."
    $req = Join-Path $Scripts "requirements_tui.txt"
    if (Test-Path $req) {
        py -m pip install -r $req --quiet
        Write-Success "  ✔ Dependencies installed"
    } else {
        Write-Warn "  ⚠ requirements_tui.txt not found, installing manually..."
        py -m pip install "textual>=0.47.0" "rich>=13.0.0" "websockets>=11.0" "httpx>=0.24.0" --quiet
        Write-Success "  ✔ Dependencies installed"
    }
}

# ── Start backend in new window ──────────────────────────────────────────────
function Start-Backend {
    Write-Violet "  [1/3] Starting Node.js backend (port 3000)..."
    if (-not (Test-Path (Join-Path $Backend "node_modules"))) {
        Write-Warn "  ⚠ node_modules not found — running npm install first..."
        Push-Location $Backend
        npm install --silent
        Pop-Location
    }
    Start-Process powershell -ArgumentList `
        "-NoExit", "-Command", "cd '$Backend'; Write-Host 'MARI TIME Backend' -ForegroundColor Magenta; npm run dev" `
        -WindowStyle Normal
    Write-Success "  ✔ Backend window launched"
    Start-Sleep -Seconds 2
}

# ── Start PLC server ─────────────────────────────────────────────────────────
function Start-PlcServer {
    Write-Violet "  [2/3] Starting PLC server (Modbus port 502)..."
    $plc = Join-Path $Scripts "plc_server.py"
    if (Test-Path $plc) {
        Start-Process powershell -ArgumentList `
            "-NoExit", "-Command", "cd '$Root'; Write-Host 'MARI TIME PLC Server' -ForegroundColor Magenta; py scripts/plc_server.py" `
            -WindowStyle Normal
        Write-Success "  ✔ PLC server window launched"
    } else {
        Write-Warn "  ⚠ plc_server.py not found — skipping"
    }
    Start-Sleep -Seconds 1
}

# ── Start HMI client ─────────────────────────────────────────────────────────
function Start-HmiClient {
    Write-Violet "  [3/3] Starting HMI client..."
    $hmi = Join-Path $Scripts "hmi_client.py"
    if (Test-Path $hmi) {
        Start-Process powershell -ArgumentList `
            "-NoExit", "-Command", "cd '$Root'; Write-Host 'MARI TIME HMI Client' -ForegroundColor Magenta; py scripts/hmi_client.py" `
            -WindowStyle Normal
        Write-Success "  ✔ HMI client window launched"
    } else {
        Write-Warn "  ⚠ hmi_client.py not found — skipping"
    }
    Start-Sleep -Seconds 1
}

# ── Launch TUI ───────────────────────────────────────────────────────────────
function Start-Tui {
    param([string]$ModeArg)
    Write-Host ""
    Write-Violet "  Launching MARI TIME TUI Dashboard..."
    Write-Host "  ─────────────────────────────────────────────────────────────" -ForegroundColor DarkMagenta
    Write-Host ""

    $tui = Join-Path $Scripts "tui_dashboard.py"
    if (-not (Test-Path $tui)) {
        Write-Err "  ✘ tui_dashboard.py not found at $tui"
        exit 1
    }

    $cmd = "py `"$tui`""
    if ($ModeArg) { $cmd += " $ModeArg" }
    Invoke-Expression $cmd
}

# ── Main ─────────────────────────────────────────────────────────────────────
Show-Banner

if ($InstallDeps) {
    Install-TuiDeps
    Write-Host ""
}

$modeArg = ""
if ($Demo)  { $modeArg = "--demo" }
if ($Live)  { $modeArg = "--live" }

if ($TuiOnly) {
    Write-Warn "  [TUI Only mode — skipping backend and Python components]"
    Write-Host ""
    Start-Tui -ModeArg $modeArg
} else {
    Start-Backend
    Start-PlcServer
    Start-HmiClient

    Write-Host ""
    Write-Success "  ✔ All components started"
    Write-Host "  Waiting 3 seconds for services to initialize..." -ForegroundColor DarkMagenta
    Start-Sleep -Seconds 3

    Start-Tui -ModeArg $modeArg
}
