# Demo only: append a clearly marked synthetic tamper event while Suricata runs.
# Run from an Administrator PowerShell if the Suricata log is under Program Files.
$p = $env:EVE_PATH
if (-not $p) { throw 'EVE_PATH is not configured' }

$e = @{
    timestamp = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
    event_type = 'alert'
    src_ip = '192.168.1.50'
    dest_ip = '192.168.1.10'
    proto = 'TCP'
    cyberforensics_test_tampered = $true
    alert = @{
        action = 'allowed'
        gid = 1
        signature_id = 999999
        rev = 1
        signature = 'TEST ONLY - Synthetic tampering test'
        category = 'Test Log Integrity Alert'
        severity = 1
    }
} | ConvertTo-Json -Compress

Add-Content -Path $p -Value $e -Encoding utf8
Write-Host "Synthetic tamper event appended to $p"
Write-Host "TamperGuard should show SYNTHETIC_TAMPER_TEST after the next poll."
