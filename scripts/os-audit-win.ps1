# FileMaker Security Audit: read-only OS check for Windows Server.
# Paste the whole script into PowerShell (ideally "Run as administrator") inside your
# remote desktop session. It changes nothing, writes no files, and prints one result
# block that is also copied to the clipboard. Copy that block back to your laptop.
& {
    $ErrorActionPreference = 'Stop'
    $r = [ordered]@{
        platform     = 'windows'
        schema       = 1
        collected_at = (Get-Date).ToUniversalTime().ToString('o')
        hostname     = $env:COMPUTERNAME
        not_checked  = [ordered]@{}
    }
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $r.elevated = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    function Read-Section($key, [scriptblock]$block) {
        try { $r[$key] = & $block } catch { $r.not_checked[$key] = $_.Exception.Message }
    }

    Read-Section 'os' {
        $os = Get-CimInstance Win32_OperatingSystem
        [ordered]@{ name = $os.Caption; version = $os.Version; build = $os.BuildNumber }
    }

    Read-Section 'listeners' {
        @(Get-NetTCPConnection -State Listen | Sort-Object LocalPort, LocalAddress -Unique | ForEach-Object {
            $p = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
            [ordered]@{ port = [int]$_.LocalPort; address = $_.LocalAddress; pid = [int]$_.OwningProcess; process = $(if ($p) { $p.ProcessName } else { $null }) }
        })
    }

    Read-Section 'firewall' {
        $profiles = @(Get-NetFirewallProfile | ForEach-Object { [ordered]@{ name = $_.Name; enabled = ([string]$_.Enabled -eq 'True') } })
        $rules = @(Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True)
        $ports = @($rules | Get-NetFirewallPortFilter)
        $addrs = @($rules | Get-NetFirewallAddressFilter)
        $broad = @()
        for ($i = 0; $i -lt $rules.Count; $i++) {
            $lp = [string]($ports[$i].LocalPort -join ',')
            if ($ports[$i].Protocol -eq 'TCP' -and $lp -match '^\d' -and ([string]($addrs[$i].RemoteAddress -join ',')) -eq 'Any') {
                $broad += [ordered]@{ name = $rules[$i].DisplayName; ports = $lp }
            }
        }
        [ordered]@{ profiles = $profiles; broad_allow_rules = $broad }
    }

    Read-Section 'patching' {
        $last = Get-HotFix | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending | Select-Object -First 1
        $auto = $null
        $pol = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -ErrorAction SilentlyContinue
        if ($pol -and $null -ne $pol.NoAutoUpdate) { $auto = ($pol.NoAutoUpdate -eq 0) }
        [ordered]@{ last_installed = $(if ($last) { $last.InstalledOn.ToString('yyyy-MM-dd') } else { $null }); auto_updates = $auto }
    }

    Read-Section 'local_admins' {
        try { @(Get-LocalGroupMember -SID 'S-1-5-32-544' | ForEach-Object { $_.Name }) }
        catch { @(net localgroup administrators | Select-Object -Skip 6 | Where-Object { $_ -and $_ -notmatch 'command completed' }) }
    }

    Read-Section 'disk_encryption' {
        if (-not (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue)) { throw 'BitLocker is not installed on this server' }
        @(Get-BitLockerVolume | ForEach-Object { [ordered]@{ volume = $_.MountPoint; encrypted = ([string]$_.ProtectionStatus -eq 'On') } })
    }

    Read-Section 'antivirus' {
        $products = @()
        $mp = Get-MpComputerStatus -ErrorAction SilentlyContinue
        if ($mp) { $products += [ordered]@{ name = 'Microsoft Defender'; running = [bool]($mp.AntivirusEnabled -and $mp.RealTimeProtectionEnabled); signature_age_days = [int]$mp.AntivirusSignatureAge } }
        foreach ($s in @(Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -match 'Sophos|CrowdStrike|SentinelOne|Malwarebytes|ESET|Bitdefender|Trend Micro|McAfee|Trellix|Symantec|Webroot|Cylance|Carbon Black|Huntress' })) {
            $products += [ordered]@{ name = $s.DisplayName; running = ([string]$s.Status -eq 'Running'); signature_age_days = $null }
        }
        [ordered]@{ products = $products }
    }

    Read-Section 'av_exclusions' {
        if (-not $r.elevated) { throw 'Needs administrator rights' }
        $pref = Get-MpPreference
        @($pref.ExclusionPath | Where-Object { $_ })
    }

    $r.fms_data_paths = @('C:\Program Files\FileMaker\FileMaker Server\Data\Databases') | Where-Object { Test-Path $_ }

    $json = $r | ConvertTo-Json -Depth 6 -Compress
    $bytes = [Text.Encoding]::UTF8.GetBytes($json)
    $ms = New-Object IO.MemoryStream
    $gz = New-Object IO.Compression.GZipStream($ms, [IO.Compression.CompressionMode]::Compress)
    $gz.Write($bytes, 0, $bytes.Length); $gz.Close()
    $b64 = [Convert]::ToBase64String($ms.ToArray()) -replace '(.{76})', "`$1`n"
    $sha = -join ([Security.Cryptography.SHA256]::Create().ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') })
    $block = "----- FMS-AUDIT OS BEGIN v1 -----`n$b64`nsha256: $sha`n----- FMS-AUDIT OS END -----"
    Write-Output ''
    Write-Output $block
    try { Set-Clipboard -Value $block; Write-Output "`nCopied to the clipboard. Paste it back on your laptop with: python -m audit os-import" }
    catch { Write-Output "`nSelect everything from BEGIN to END and copy it to your laptop." }
    if (-not $r.elevated) { Write-Output 'Not running as administrator: some checks will show as Not checked.' }
}
