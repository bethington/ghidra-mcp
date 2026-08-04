# Stop the Windows Audio services, run the probe, ALWAYS restart them.
#
# The previous attempt disabled PnP AudioEndpoint devices and was worthless:
# DirectSound still enumerated all 8, because those endpoints are a software
# abstraction and the audio engine kept serving them. Verified the wrong layer.
#
# Stopping Audiosrv + AudioEndpointBuilder is both the correct test and a
# closer model of a container, where those services are simply not running.

$ErrorActionPreference = 'Continue'
$done   = 'C:\tmp\d2probe\noaudio_done.txt'
$result = 'C:\tmp\d2probe\noaudio_result.txt'
Remove-Item $done, $result -ErrorAction SilentlyContinue

function Note($m) { $m | Out-File -FilePath $done -Append -Encoding ascii }

# Record what was running so we restore exactly that, not a guess.
$svcs = 'Audiosrv', 'AudioEndpointBuilder'
$was = @{}
foreach ($s in $svcs) {
    $o = Get-Service -Name $s -ErrorAction SilentlyContinue
    if ($o) { $was[$s] = $o.Status }
}
Note ("before: " + (($was.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ' '))

try {
    # AudioEndpointBuilder is the dependency provider; -Force takes Audiosrv with it.
    Stop-Service -Name AudioEndpointBuilder -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 3
    $now = foreach ($s in $svcs) {
        $o = Get-Service -Name $s -ErrorAction SilentlyContinue
        "$s=$($o.Status)"
    }
    Note ("during: " + ($now -join ' '))

    & 'C:\tmp\d2probe\probe.exe' | Out-Null
    Copy-Item 'C:\tmp\d2probe\probe_result.txt' $result -Force
}
finally {
    # ALWAYS bring audio back, in dependency order.
    Start-Service -Name AudioEndpointBuilder -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    Start-Service -Name Audiosrv -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 3
    $after = foreach ($s in $svcs) {
        $o = Get-Service -Name $s -ErrorAction SilentlyContinue
        "$s=$($o.Status)"
    }
    Note ("after: " + ($after -join ' '))
    Note 'DONE'
}
