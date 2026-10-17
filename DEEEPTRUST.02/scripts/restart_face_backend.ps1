param([switch]$CheckOnly)

$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$ports = @(5000, 8000, 5050)

function Get-DeepTrustListeners {
    $connections = Get-NetTCPConnection -State Listen -ErrorAction Stop |
        Where-Object { $ports -contains [int]$_.LocalPort -and $_.OwningProcess -gt 0 }
    foreach ($connection in $connections) {
        $process = Get-CimInstance Win32_Process -Filter "ProcessId=$($connection.OwningProcess)" -ErrorAction Stop
        if (-not $process) { throw "Cannot identify process on port $($connection.LocalPort)." }
        [pscustomobject]@{
            Port = [int]$connection.LocalPort
            Pid = [int]$connection.OwningProcess
            Name = [string]$process.Name
            CommandLine = [string]$process.CommandLine
        }
    }
}

$listeners = @(Get-DeepTrustListeners | Sort-Object Pid -Unique)
if ($CheckOnly) {
    $listeners | Format-Table Port, Pid, Name, CommandLine -AutoSize
    exit 0
}

foreach ($listener in $listeners) {
    $command = $listener.CommandLine
    $isDeepTrust = ($command -match 'DEEEPTRUST\.02|deeptrust_launcher|server[\\/]server\.js|server\.ai_service\.face_service|protected_demo_app\.py')
    $isRuntime = ($listener.Name -match '^(node|node\.exe|python|python\.exe|pythonw\.exe)$')
    if (-not ($isDeepTrust -and $isRuntime)) {
        throw "Port $($listener.Port) is owned by an unrecognized process ($($listener.Name), PID $($listener.Pid)). Refusing to stop it."
    }
}

foreach ($listener in $listeners) {
    Write-Host "Stopping old DeepTrust $($listener.Name) process $($listener.Pid) on port $($listener.Port)..."
    & taskkill.exe /F /T /PID $listener.Pid | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Could not stop process $($listener.Pid)." }
}

$deadline = (Get-Date).AddSeconds(20)
do {
    Start-Sleep -Milliseconds 500
    $remaining = @(Get-DeepTrustListeners)
} while ($remaining.Count -gt 0 -and (Get-Date) -lt $deadline)
if ($remaining.Count -gt 0) {
    throw "DeepTrust ports are still occupied: $(($remaining | ForEach-Object { $_.Port }) -join ', ')."
}

Write-Host 'Old DeepTrust ports are free. Starting the corrected project...'
Start-Process -FilePath 'node.exe' -ArgumentList @('server\scripts\deeptrust_launcher.js', 'start') -WorkingDirectory $projectRoot -WindowStyle Hidden
