$conn = Get-NetTCPConnection -LocalPort 3000 -ErrorAction SilentlyContinue
if ($conn) {
    foreach ($c in $conn) {
        $proc = Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue
        Write-Host "Port 3000 owned by PID $($c.OwningProcess) - $($proc.Name) - $($proc.Path)"
        Stop-Process -Id $c.OwningProcess -Force -ErrorAction SilentlyContinue
        Write-Host "Killed PID $($c.OwningProcess)"
    }
} else {
    Write-Host "No process found on port 3000"
}
