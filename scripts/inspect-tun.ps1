param([ValidateSet('Preflight','Ready','Snapshot')][string]$Mode, [string]$AdapterName, [string]$Description)
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
if ($Mode -eq 'Snapshot') {
    $foreign = @(Get-NetAdapter -IncludeHidden | Where-Object { $_.Name -notmatch '^Yukiwire-[0-9a-f]{12}$' } | Select-Object -ExpandProperty ifIndex)
    $addresses = @(Get-NetIPAddress -PolicyStore ActiveStore | Where-Object { $_.InterfaceIndex -in $foreign } |
        Sort-Object InterfaceIndex,IPAddress | Select-Object InterfaceIndex,IPAddress,PrefixLength)
    $routes = @(Get-NetRoute -PolicyStore ActiveStore | Where-Object { $_.InterfaceIndex -in $foreign } |
        Sort-Object InterfaceIndex,DestinationPrefix,NextHop | Select-Object InterfaceIndex,DestinationPrefix,NextHop,RouteMetric)
    $dns = @(Get-DnsClientServerAddress | Where-Object { $_.InterfaceIndex -in $foreign } |
        Sort-Object InterfaceIndex,AddressFamily | Select-Object InterfaceIndex,AddressFamily,ServerAddresses)
    @{ addresses = $addresses; routes = $routes; dns = $dns } | ConvertTo-Json -Depth 6 -Compress
    exit 0
}
if ($Mode -eq 'Preflight') {
    $addresses = @(Get-NetIPAddress -PolicyStore ActiveStore | ForEach-Object { "$($_.IPAddress)/$($_.PrefixLength)" })
    @{ addresses = $addresses } | ConvertTo-Json -Compress
    exit 0
}
$adapter = Get-NetAdapter -IncludeHidden | Where-Object { $_.Name -eq $AdapterName }
if (-not $adapter) { @{ ready = $false } | ConvertTo-Json -Compress; exit 0 }
if (@($adapter).Count -ne 1 -or $AdapterName -notmatch '^Yukiwire-[0-9a-f]{12}$' -or
    $Description -ne ('Yukiwire ' + $AdapterName.Substring(9)) -or
    $adapter.InterfaceDescription -ne ($Description + ' Tunnel')) { throw 'Adapter identity mismatch' }
$routes = @(Get-NetRoute -InterfaceIndex $adapter.ifIndex -PolicyStore ActiveStore)
$found = @($routes | Where-Object {
    $_.DestinationPrefix -in @('0.0.0.0/1','128.0.0.0/1','::/1','8000::/1') -and
    $_.NextHop -in @('0.0.0.0','::') -and $_.RouteMetric -eq 0
} | Select-Object -ExpandProperty DestinationPrefix -Unique)
$addresses = @(Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -PolicyStore ActiveStore)
$ipv4 = @($addresses | Where-Object { $_.IPAddress -eq '172.29.250.1' -and $_.PrefixLength -eq 30 })
$ipv6 = @($addresses | Where-Object { $_.IPAddress -eq 'fd72:756b:6977::1' -and $_.PrefixLength -eq 126 })
$dns = @((Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4).ServerAddresses)
@{ ready = ($adapter.Status -eq 'Up' -and $found.Count -eq 4 -and $ipv4.Count -eq 1 -and
    $ipv6.Count -eq 1 -and $dns.Count -eq 1 -and $dns[0] -eq '172.29.250.2') } | ConvertTo-Json -Compress
