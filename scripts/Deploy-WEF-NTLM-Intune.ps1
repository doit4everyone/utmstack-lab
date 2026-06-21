#Requires -RunAsAdministrator
# Deploy-WEF-NTLM-Intune.ps1
# Deploiement WEF pour collecte Microsoft-Windows-NTLM/Operational
# Version pour environnements Intune (AAD-joined ou Hybrid AAD-joined)
# XML de souscription embarque en Base64 - pas de dependance SYSVOL
# Version : 1.1 - Corrections deployement terrain (2026-06-20)

$SubscriptionName       = "NTLM-Operational-Local"
$XmlPath                = "$env:TEMP\ntlm-subscription.xml"
$LogFile                = "C:\Windows\Logs\Deploy-WEF-NTLM.log"
$ForwardedEventsMaxSize = 524288000
$MachineFQDN            = "$env:COMPUTERNAME.$((Get-WmiObject Win32_ComputerSystem).Domain)"

# XML de souscription embarque (Base64)
$XmlBase64 = "PFN1YnNjcmlwdGlvbiB4bWxucz0iaHR0cDovL3NjaGVtYXMubWljcm9zb2Z0LmNvbS8yMDA2LzAzL3dpbmRvd3MvZXZlbnRzL3N1YnNjcmlwdGlvbiI+CiAgPFN1YnNjcmlwdGlvbklkPk5UTE0tT3BlcmF0aW9uYWwtTG9jYWw8L1N1YnNjcmlwdGlvbklkPgogIDxTdWJzY3JpcHRpb25UeXBlPlNvdXJjZUluaXRpYXRlZDwvU3Vic2NyaXB0aW9uVHlwZT4KICA8RGVzY3JpcHRpb24+Rm9yd2FyZCBOVExNIE9wZXJhdGlvbmFsIGV2ZW50cyB0byBGb3J3YXJkZWRFdmVudHM8L0Rlc2NyaXB0aW9uPgogIDxFbmFibGVkPnRydWU8L0VuYWJsZWQ+CiAgPFVyaT5odHRwOi8vc2NoZW1hcy5taWNyb3NvZnQuY29tL3diZW0vd3NtYW4vMS93aW5kb3dzL0V2ZW50TG9nPC9Vcmk+CiAgPENvbmZpZ3VyYXRpb25Nb2RlPk5vcm1hbDwvQ29uZmlndXJhdGlvbk1vZGU+CiAgPERlbGl2ZXJ5IE1vZGU9IlB1c2giPgogICAgPEJhdGNoaW5nPgogICAgICA8TWF4TGF0ZW5jeVRpbWU+MzAwMDA8L01heExhdGVuY3lUaW1lPgogICAgPC9CYXRjaGluZz4KICAgIDxQdXNoU2V0dGluZ3M+CiAgICAgIDxIZWFydGJlYXQgSW50ZXJ2YWw9IjM2MDAwMDAiLz4KICAgIDwvUHVzaFNldHRpbmdzPgogIDwvRGVsaXZlcnk+CiAgPFF1ZXJ5PgogICAgPCFbQ0RBVEFbCiAgICAgIDxRdWVyeUxpc3Q+CiAgICAgICAgPFF1ZXJ5IElkPSIwIj4KICAgICAgICAgIDxTZWxlY3QgUGF0aD0iTWljcm9zb2Z0LVdpbmRvd3MtTlRMTS9PcGVyYXRpb25hbCI+CiAgICAgICAgICAgICpbU3lzdGVtW0V2ZW50SUQ9NDAyMCBvciBFdmVudElEPTQwMjEgb3IgRXZlbnRJRD00MDIyIG9yIEV2ZW50SUQ9NDAyMyBvciBFdmVudElEPTQwMjQgb3IgRXZlbnRJRD00MDI1XV0KICAgICAgICAgIDwvU2VsZWN0PgogICAgICAgIDwvUXVlcnk+CiAgICAgIDwvUXVlcnlMaXN0PgogICAgXV0+CiAgPC9RdWVyeT4KICA8UmVhZEV4aXN0aW5nRXZlbnRzPmZhbHNlPC9SZWFkRXhpc3RpbmdFdmVudHM+CiAgPFRyYW5zcG9ydE5hbWU+SFRUUDwvVHJhbnNwb3J0TmFtZT4KICA8Q29udGVudEZvcm1hdD5SZW5kZXJlZFRleHQ8L0NvbnRlbnRGb3JtYXQ+CiAgPExvY2FsZSBMYW5ndWFnZT0iZW4tVVMiLz4KICA8TG9nRmlsZT5Gb3J3YXJkZWRFdmVudHM8L0xvZ0ZpbGU+CiAgPEFsbG93ZWRTb3VyY2VOb25Eb21haW5Db21wdXRlcnMvPgogIDxBbGxvd2VkU291cmNlRG9tYWluQ29tcHV0ZXJzPk86TlNHOk5TRDooQTs7R0E7OztEQykoQTs7R0E7OztOUyk8L0FsbG93ZWRTb3VyY2VEb21haW5Db21wdXRlcnM+CjwvU3Vic2NyaXB0aW9uPgo="

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $entry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$Level] $Message"
    Add-Content -Path $LogFile -Value $entry -Encoding UTF8
    Write-Output $entry
}

Write-Log "=== Deploy-WEF-NTLM-Intune demarre sur $env:COMPUTERNAME ($MachineFQDN) ==="

# 1. Idempotence
$null = wecutil gs $SubscriptionName 2>$null
if ($LASTEXITCODE -eq 0) {
    Write-Log "Souscription deja presente - aucune action requise."
    exit 0
}

Write-Log "Souscription absente - deploiement en cours..."

# 2. Activer le service Windows Event Collector
try {
    Set-Service -Name Wecsvc -StartupType Automatic -ErrorAction Stop
    $svc = Get-Service -Name Wecsvc
    if ($svc.Status -ne 'Running') {
        Start-Service -Name Wecsvc -ErrorAction Stop
        Write-Log "Service Wecsvc demarre."
    } else {
        Write-Log "Service Wecsvc deja en cours."
    }
} catch {
    Write-Log "ERREUR demarrage Wecsvc : $_" "ERROR"
    exit 1
}

# 3. Configurer WinRM local
try {
    $null = winrm quickconfig -quiet 2>&1
    Write-Log "WinRM configure."
} catch {
    Write-Log "AVERTISSEMENT WinRM : $_" "WARN"
}

# 4. ACL canal NTLM/Operational
try {
    $acl = "O:BAG:SYD:(A;;0xf0007;;;SY)(A;;0x7;;;BA)(A;;0x1;;;BO)(A;;0x1;;;SO)(A;;0x1;;;S-1-5-32-573)(A;;0x1;;;NS)"
    $null = wevtutil sl "Microsoft-Windows-NTLM/Operational" /ca:$acl 2>&1
    Write-Log "ACL canal NTLM/Operational appliquees."
} catch {
    Write-Log "ERREUR ACL : $_" "ERROR"
    exit 1
}

# 5. Activer et agrandir le canal ForwardedEvents
try {
    $null = wevtutil sl ForwardedEvents /e:true 2>&1
    $null = wevtutil sl ForwardedEvents /ms:$ForwardedEventsMaxSize 2>&1
    Write-Log "Canal ForwardedEvents active et agrandi a 500 MB."
} catch {
    Write-Log "AVERTISSEMENT ForwardedEvents : $_" "WARN"
}

# 6. Decoder le XML embarque vers un fichier temporaire
try {
    $xmlBytes = [Convert]::FromBase64String($XmlBase64)
    [System.IO.File]::WriteAllBytes($XmlPath, $xmlBytes)
    Write-Log "XML decode vers $XmlPath ($($xmlBytes.Length) bytes)."
} catch {
    Write-Log "ERREUR decodage Base64 : $_" "ERROR"
    exit 1
}

# 7. Initialiser le collecteur WEC
try {
    $null = wecutil qc /quiet 2>&1
    Write-Log "Collecteur WEC initialise."
} catch {
    Write-Log "AVERTISSEMENT wecutil qc : $_" "WARN"
}

# 8. Configurer le Subscription Manager (FQDN dynamique, pas localhost)
try {
    $smKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager"
    $smValue = "Server=http://${MachineFQDN}:5985/wsman/SubscriptionManager/WEC"
    if (-not (Test-Path $smKey)) {
        New-Item -Path $smKey -Force | Out-Null
    }
    Set-ItemProperty -Path $smKey -Name "1" -Value $smValue -Type String
    Write-Log "Subscription Manager configure : $smValue"
} catch {
    Write-Log "ERREUR Subscription Manager : $_" "ERROR"
}

# 9. Creer la souscription WEF
try {
    $null = wecutil cs $XmlPath 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Log "ERREUR wecutil cs (exit code $LASTEXITCODE)" "ERROR"
        Remove-Item $XmlPath -Force -ErrorAction SilentlyContinue
        exit 1
    }
    Write-Log "Souscription creee avec succes."
} catch {
    Write-Log "ERREUR creation souscription : $_" "ERROR"
    Remove-Item $XmlPath -Force -ErrorAction SilentlyContinue
    exit 1
}

# 10. Nettoyer le fichier temporaire
Remove-Item $XmlPath -Force -ErrorAction SilentlyContinue
Write-Log "Fichier temporaire nettoye."

# 11. Verification finale
Start-Sleep -Seconds 5
$status = wecutil gr $SubscriptionName 2>&1
Write-Log "Statut souscription : $status"

Write-Log "=== Deploiement termine sur $env:COMPUTERNAME ==="
exit 0
