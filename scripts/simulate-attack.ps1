param(
    [string]$Target = "127.0.0.1",
    [int]$Port = 9999,
    [int]$Count = 5,
    [int]$DelayMs = 250
)

Write-Host "Sending $Count demo attack connection attempts to $Target`:$Port..."
for ($i = 0; $i -lt $Count; $i++) {
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $client.ConnectAsync($Target, $Port).Wait(250)
    } catch {
        # A refused connection is fine; the SYN packet is what Suricata detects.
    } finally {
        $client.Dispose()
    }
    Start-Sleep -Milliseconds $DelayMs
}
Write-Host "Demo traffic sent. Check TamperGuard Overview and Live events."
