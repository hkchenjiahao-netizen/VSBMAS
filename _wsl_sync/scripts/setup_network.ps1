#Requires -RunAsAdministrator
# Maps Windows :8080 -> current WSL2 instance IPv4 so phones on the same Wi-Fi can open the demo.
$Port = 8080
$Distro = $args[0]
if (-not $Distro) { $Distro = (wsl -l -q | Select-Object -First 1).Trim() }

$WslIp = (wsl -d $Distro -e bash -lc "hostname -I | awk '{print \$1}'").Trim()
if (-not $WslIp) { Write-Error "Could not read WSL IP. Specify distro: .\setup_network.ps1 Ubuntu"; exit 1 }

Write-Host "WSL distro: $Distro"
Write-Host "WSL IP:     $WslIp"
Write-Host "Port:       $Port"

netsh interface portproxy delete v4tov4 listenport=$Port listenaddress=0.0.0.0 2>$null
netsh interface portproxy add v4tov4 listenport=$Port listenaddress=0.0.0.0 connectport=$Port connectaddress=$WslIp

New-NetFirewallRule -DisplayName "VSBMAS WSL $Port" -Direction Inbound -Action Allow -Protocol TCP -LocalPort $Port -ErrorAction SilentlyContinue | Out-Null

$wlan = Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -match 'Wi-?Fi|WLAN|Wireless' } | Select-Object -First 1
$winIp = if ($wlan) { $wlan.IPAddress } else { "(run ipconfig and pick your LAN IPv4)" }

Write-Host ""
$shareJson = Join-Path $PSScriptRoot "..\web\share.json"
$shareUrl  = "http://${winIp}:$Port/"
Set-Content -Path $shareJson -Value (@{ share_url = $shareUrl } | ConvertTo-Json -Compress) -Encoding UTF8
Write-Host "Wrote share.json -> $shareJson"
Write-Host "Done. Share with students: http://${winIp}:$Port/"
Write-Host "If WSL IP changes after reboot, re-run this script."
Write-Host "Conflicts with VPN/tunnels (e.g. singbox_tun) may block LAN access — try disabling VPN for class."
