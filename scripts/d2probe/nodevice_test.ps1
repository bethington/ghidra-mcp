# Temporarily disable every audio endpoint, run the probe, then ALWAYS restore.
#
# This is the one question the Session 0 run could not answer: it enumerated 8
# endpoints because this machine has audio, so it proved Session 0 is not the
# obstacle -- not that DirectSound survives with no device, which is the actual
# container case.
#
# SAFETY: the restore is in finally{} so it runs even if the probe crashes or
# this script is interrupted, and the endpoint list is written to disk BEFORE
# anything is disabled so a manual restore is always possible.

$ErrorActionPreference = 'Stop'
$saved    = 'C:\tmp\d2probe\disabled_endpoints.txt'
$result   = 'C:\tmp\d2probe\nodevice_result.txt'
$done     = 'C:\tmp\d2probe\nodevice_done.txt'
Remove-Item $done, $result -ErrorAction SilentlyContinue

$eps = @(Get-PnpDevice -Class AudioEndpoint | Where-Object { $_.Status -eq 'OK' })
# Persist the restore list FIRST -- before a single device is touched.
$eps | Select-Object -ExpandProperty InstanceId | Set-Content $saved
"saved $($eps.Count) endpoint ids" | Out-File $done -Append

try {
    foreach ($e in $eps) {
        try { Disable-PnpDevice -InstanceId $e.InstanceId -Confirm:$false -ErrorAction Stop }
        catch { "disable failed: $($e.FriendlyName)" | Out-File $done -Append }
    }
    Start-Sleep -Seconds 4          # let the audio service notice they are gone

    $still = @(Get-PnpDevice -Class AudioEndpoint | Where-Object { $_.Status -eq 'OK' })
    "endpoints still enabled during test: $($still.Count)" | Out-File $done -Append

    & 'C:\tmp\d2probe\probe.exe' | Out-Null
    Copy-Item 'C:\tmp\d2probe\probe_result.txt' $result -Force
}
finally {
    # ALWAYS put the machine back, whatever happened above.
    foreach ($id in (Get-Content $saved)) {
        try { Enable-PnpDevice -InstanceId $id -Confirm:$false -ErrorAction Stop }
        catch { "RESTORE FAILED: $id" | Out-File $done -Append }
    }
    Start-Sleep -Seconds 3
    $back = @(Get-PnpDevice -Class AudioEndpoint | Where-Object { $_.Status -eq 'OK' })
    "endpoints re-enabled: $($back.Count)" | Out-File $done -Append
    'DONE' | Out-File $done -Append
}
