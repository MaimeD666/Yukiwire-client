param([Parameter(Mandatory=$true)][string]$AdapterName, [Parameter(Mandatory=$true)][string]$Description)
$ErrorActionPreference = 'Stop'
if ($AdapterName -notmatch '^Yukiwire-[0-9a-f]{12}$' -or $Description -ne ('Yukiwire ' + $AdapterName.Substring(9))) { exit 2 }
$ownedAdapter = Get-NetAdapter -IncludeHidden | Where-Object { $_.Name -eq $AdapterName }
if (-not $ownedAdapter) { exit 0 }
if (@($ownedAdapter).Count -ne 1 -or $ownedAdapter.InterfaceDescription -ne ($Description + ' Tunnel')) { exit 3 }
# Never flush a physical adapter or restore a whole route table.
$ownedPrefixes = @('0.0.0.0/1', '128.0.0.0/1', '::/1', '8000::/1')
$ownedRoutes = Get-NetRoute -PolicyStore ActiveStore | Where-Object {
    $_.InterfaceIndex -eq $ownedAdapter.ifIndex -and $_.DestinationPrefix -in $ownedPrefixes -and
    $_.RouteMetric -eq 0 -and $_.NextHop -in @('0.0.0.0', '::')
}
$ownedRoutes | Remove-NetRoute -Confirm:$false
# Remove our addresses/DNS as well: a disabled adapter must not reserve the next session's subnet.
$ownedAddresses = Get-NetIPAddress -PolicyStore ActiveStore | Where-Object {
    $_.InterfaceIndex -eq $ownedAdapter.ifIndex -and (
    ($_.IPAddress -eq '172.29.250.1' -and $_.PrefixLength -eq 30) -or
    ($_.IPAddress -eq 'fd72:756b:6977::1' -and $_.PrefixLength -eq 126))
}
$ownedAddresses | Remove-NetIPAddress -Confirm:$false
Set-DnsClientServerAddress -InterfaceIndex $ownedAdapter.ifIndex -ResetServerAddresses
# A leftover Wintun adapter is ours alone; disabling it prevents stale DNS use.
Disable-NetAdapter -Name $AdapterName -Confirm:$false
$remainingRoutes = Get-NetRoute -PolicyStore ActiveStore | Where-Object {
    $_.InterfaceIndex -eq $ownedAdapter.ifIndex -and $_.DestinationPrefix -in $ownedPrefixes
}
if ($remainingRoutes) { exit 4 }
$remainingAddresses = Get-NetIPAddress -PolicyStore ActiveStore | Where-Object {
    $_.InterfaceIndex -eq $ownedAdapter.ifIndex -and $_.IPAddress -in @('172.29.250.1','fd72:756b:6977::1')
}
if ($remainingAddresses) { exit 5 }
exit 0
