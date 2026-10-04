param([ValidateSet('Register','Remove')][string]$Mode, [Parameter(Mandatory=$true)][string]$PayloadB64)
$ErrorActionPreference = 'Stop'
$spec = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($PayloadB64)) | ConvertFrom-Json
if ($spec.name -notmatch '^Yukiwire\.Recovery-[0-9a-f]{20}$' -or $spec.level -notin @('Limited','Highest')) { throw 'Invalid task identity' }
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$marker = 'Yukiwire temporary network recovery ' + $spec.name
$existing = Get-ScheduledTask -TaskPath '\' -ErrorAction Stop | Where-Object { $_.TaskName -eq $spec.name }
if ($existing) {
    $actions = @($existing.Actions)
    # Task Scheduler may return an account name even when registration used a SID.
    # Compare security identities, never display-name strings.
    $existingUser = [string]$existing.Principal.UserId
    if ($existingUser -match '^S-1-') {
        $existingSid = ([Security.Principal.SecurityIdentifier]::new($existingUser)).Value
    } else {
        $existingSid = ([Security.Principal.NTAccount]::new($existingUser)).Translate([Security.Principal.SecurityIdentifier]).Value
    }
    if ($existing.Description -ne $marker -or $actions.Count -ne 1 -or
        $actions[0].Execute -ne $spec.executable -or $actions[0].Arguments -ne $spec.arguments -or
        $actions[0].WorkingDirectory -ne $spec.directory -or $existingSid -ne $sid) {
        throw 'Existing task belongs to a different installation or user'
    }
}
if ($Mode -eq 'Remove') {
    if ($existing) { Unregister-ScheduledTask -TaskPath '\' -TaskName $spec.name -Confirm:$false }
    exit 0
}
$action = New-ScheduledTaskAction -Execute $spec.executable -Argument $spec.arguments -WorkingDirectory $spec.directory
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $sid
$principal = New-ScheduledTaskPrincipal -UserId $sid -LogonType Interactive -RunLevel $spec.level
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 2) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskPath '\' -TaskName $spec.name -Action $action -Trigger $trigger -Principal $principal `
    -Settings $settings -Description $marker -Force | Out-Null
