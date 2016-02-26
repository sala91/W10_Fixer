# Making shure we have administrative rights
If (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
{   
    $arguments = "& '" + $myinvocation.mycommand.definition + "'"
    Start-Process powershell -Verb runAs -ArgumentList $arguments
    Break
}

# Making shure that our console window is readable
[console]::backgroundcolor = "darkmagenta"
[console]::foregroundcolor = "darkyellow"
$p = $host.privatedata
$p.ErrorForegroundColor    = "Red"
$p.ErrorBackgroundColor    = "Black"
$p.WarningForegroundColor  = "Yellow"
$p.WarningBackgroundColor  = "Black"
$p.DebugForegroundColor    = "Yellow"
$p.DebugBackgroundColor    = "Black"
$p.VerboseForegroundColor  = "Yellow"
$p.VerboseBackgroundColor  = "Black"
$p.ProgressForegroundColor = "Yellow"
$p.ProgressBackgroundColor = "DarkCyan"

# clear screen
clear-host

# fancy select screen with options
do {
    do {

        $os = Get-WmiObject win32_operatingsystem
        $uptime = (Get-Date) - ($os.ConvertToDateTime($os.lastbootuptime))
        $Display = "Uptime: " + $Uptime.Days + " days, " + $Uptime.Hours + " hours, " + $Uptime.Minutes + " minutes" 
        $uptimeBuild = (Get-ItemProperty -Path c:\windows\system32\hal.dll).VersionInfo.FileVersion
        $uptimeOsName = gwmi win32_operatingsystem | % caption  
        write-host ""
            
            
        write-host "BattleIT Group LTD 2015, v0.3"
        write-host "-----------------------------"
        write-host "OS:" $uptimeOsName $uptimeBuild
        Write-Output $Display
        write-host "-----------------------------"
        write-host "" 
        write-host "Windows 10 goodies"
        write-host "G1 - Explorer: show hidden files, extensions and empty drives"
        write-host "G2 - Block telemetry via Windows Firewall & Hosts file"       
        write-host "G3 - Block telemetry via GPO (Enterprise only)"      
        write-host "G4 - Mouse acceleration fix (100% DPI only)"
        write-host "G5 - Disable StickyKeys and stuff"               
        write-host "G6 - Enable God Mode (places a shortcut on Desktop)"    
        write-host "G7 - Install fancy Sysinternals Utilities"    
        write-host "G8 - Restore old volume slider" 
        write-host "G9 - Remove default Windows apps"
        write-host "T1 - Enable Dark theme (incomplete)"
        write-host "T2 - Enable Light theme (complete)"
        write-host "" 
        write-host "Windows 10 fixer scripts"    
        write-host "F1 - Repair Windows Image (slow)"
        write-host "F2 - Gather extended log files from DISM"
        write-host "F3 - Re-register ALL Windows Store Apps"
        write-host "F4 - Reset Windows Store Cache"
        write-host "F5 - Verify driver file signatures"       
        write-host "F6 - Sync system time with Internet"        
        write-host "F7 - Reset system services"       
        write-host "F8 - Reset networking IP and flush DNS"      
        write-host "F9 - Remove invalid shortcuts from Start menu"                     
        write-host ""
        write-host ""
        write-host "Q - Get me an excuse"
        write-host "X - Exit"
        write-host ""
        write-host -nonewline "Type your choice and press Enter: "
        
        $choice = read-host
        
        write-host ""
        
        $ok = @("G1","G2","G3","G4","G5","G6","G7","G8","G9","T1","T2","F1","F2","F3","F4","F5","F5","F6","F7","F8","F9","Q", "X") -contains $choice
        if ( -not $ok) { write-host "Invalid selection" }
    } until ( $ok )
    
    switch -Regex ( $choice ) {
        "F9"
        {
            Get-Variable true | Out-Default; Clear-Host;
            write-host "Removing invalid shortcuts from Start menu"      
            $WshShell = New-Object -comObject WScript.Shell
            $Files = Get-ChildItem -recurse -Path "C:\Users\$env:USERNAME\AppData\Roaming\Microsoft\Windows\Start Menu\Programs" -Filter *.lnk
            foreach ($File in $Files) {
                $FilePath = $File.FullName
                $Shortcut = $WshShell.CreateShortcut($FilePath)
                $Target = $Shortcut.TargetPath
                if (Test-Path -Path $Target) {
                    Write-Output "Valid: $($File.BaseName)"
                } else {
                    Write-Output "Invalid: $($File.BaseName) removed."
                    try {
                    Remove-Item -Path $LnkFilePath
                    Write-Output "Removed: $($File.BaseName) removed."
                    } catch {
                    Write-Output "ERROR: $($File.BaseName) not removed."
                    }
                }
            }
            write-host "Done!"  
        }
        "T1"
        {
            Get-Variable true | Out-Default; Clear-Host;
            write-host "Enabling dark theme"      
            If (-Not (Test-Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize)) {
                New-Item -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes -Name Personalize | Out-Null
            }
            Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize -Name AppsUseLightTheme -Type DWord -Value 0
            Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize -Name AppsUseLightTheme -Type DWord -Value 0

            write-host "Done!"  
        }
        "T2"
        {
            Get-Variable true | Out-Default; Clear-Host;
            write-host "Enabling light theme"      
            Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize -Name AppsUseLightTheme -Type DWord -Value 1
            Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize -Name AppsUseLightTheme -Type DWord -Value 1
            write-host "Done!"  
        }
        "G1"
        {
            Get-Variable true | Out-Default; Clear-Host;
            write-host "Enabling Explorer to show hidden files, extensions and empty drives"      
            sp "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "Hidden" 1
            sp "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "HideFileExt" 0
            sp "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "HideDrivesWithNoMedia" 0
            write-host "Done!"  
        }
        "F1"
        {
            Get-Variable true | Out-Default; Clear-Host;
            write-host "Repairing a Windows Image and scanning for corrupted files."
            Dism /Online /Cleanup-Image /RestoreHealth
            Dism /Online /Cleanup-Image /StartComponentCleanup
            SFC /scannow
            write-host "Done!"  
        }

        "F3"
        {
            Get-Variable true | Out-Default; Clear-Host;
            write-host "Re-registering all Windows Store Apps'"
            $manifest = (Get-AppxPackage Microsoft.WindowsStore).InstallLocation + '\AppxManifest.xml' ; Add-AppxPackage -DisableDevelopmentMode -Register $manifest 
Get-AppXPackage -AllUsers |Where-Object {$_.InstallLocation -like "*SystemApps*"} | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
            powershell -ExecutionPolicy Unrestricted Add-AppxPackage -DisableDevelopmentMode -Register $Env:SystemRoot\ImmersiveControlPanel\AppxManifest.xml
            write-host "Done!"  
        }
        
        "F4"
        {
            Get-Variable true | Out-Default; Clear-Host;
            write-host "Resetting Windows Store Cache'"
            Invoke-Item WSReset.exe
            write-host "Done!"  
        }
        
        "F5"
        {
            Get-Variable true | Out-Default; Clear-Host;
            write-host "File Signature Verification started."           
            sigverif
            write-host "Done!"  
        }

        "F8"
        {
            Get-Variable true | Out-Default; Clear-Host;
            write-host "Resetting your networking IP address"
            ipconfig /release
            ipconfig /renew
            ipconfig /flushdns
            $hostname = $env:COMPUTERNAME
            $hostip = Get-NetIPAddress | Format-Table
            write-host $hostname 
            Write-Output $hostip   
            write-host "Done!"  
        }
        
        "F2"
        {
            Get-Variable true | Out-Default; Clear-Host;
            write-host "Gathering log files"
            Dism /Online /Cleanup-Image /CheckHealth
            Dism /Online /Cleanup-Image /ScanHealth
            Invoke-Item C:\Windows\Logs\DISM\dism.log
            write-host "Done!"  
        }
        
        "G7"
        {
            Get-Variable true | Out-Default; Clear-Host;
            write-host "Installing Sysinternals Utilities to C:\Sysinternals"
            $download_uri = "https://download.sysinternals.com/files/SysinternalsSuite.zip"
            $wc = new-object net.webclient
            $wc.DownloadFile($download_uri, "/SysinternalsSuite.zip")
            Add-Type -AssemblyName "system.io.compression.filesystem"
            [io.compression.zipfile]::ExtractToDirectory("/SysinternalsSuite.zip", "/Sysinternals")
            rm "/SysinternalsSuite.zip"
            write-host "Done!"  
        }
        
        "G2"
        {
            Get-Variable true | Out-Default; Clear-Host;
            write-host "Disabling Advertising ID"
            Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo -Name Enabled -Type DWord -Value 0
            write-host "Adding telemetry domains to Hosts file"
            $hosts_file = "$env:systemroot\System32\drivers\etc\hosts"
            $domains = @(
                "a-0001.a-msedge.net"
                "a1621.g.akamai.net"
                "a1856.g2.akamai.net"
                "a1961.g.akamai.net"
                "a248.e.akamai.net"
                "a978.i6g1.akamai.net"
                "any.edge.bing.com"
                "bingads.microsoft.com"
                "choice.microsoft.com"
                "choice.microsoft.com.nsatc.net"
                "compatexchange.cloudapp.net"
                "corp.sts.microsoft.com"
                "corpext.msitadfs.glbdns2.microsoft.com"
                "cs1.wpc.v0cdn.net"
                "df.telemetry.microsoft.com"
                "diagnostics.support.microsoft.com"
                "e2835.dspb.akamaiedge.net"
                "e7341.g.akamaiedge.net"
                "e7502.ce.akamaiedge.net"
                "e8218.ce.akamaiedge.net"
                "fe2.update.microsoft.com.akadns.net"
                "feedback.microsoft-hohm.com"
                "feedback.search.microsoft.com"
                "feedback.windows.com"
                "h2.msn.com"
                "hostedocsp.globalsign.com"
                "i1.services.social.microsoft.com"
                "i1.services.social.microsoft.com.nsatc.net"
                "ipv6.msftncsi.com"
                "ipv6.msftncsi.com.edgesuite.net"
                "oca.telemetry.microsoft.com"
                "oca.telemetry.microsoft.com.nsatc.net"
                "onesettings-db5.metron.live.nsatc.net"
                "pre.footprintpredict.com"
                "redir.metaservices.microsoft.com"
                "reports.wes.df.telemetry.microsoft.com"
                "services.wes.df.telemetry.microsoft.com"
                "settings-sandbox.data.microsoft.com"
                "sls.update.microsoft.com.akadns.net"
                "sqm.df.telemetry.microsoft.com"
                "sqm.telemetry.microsoft.com"
                "sqm.telemetry.microsoft.com.nsatc.net"
                "statsfe1.ws.microsoft.com"
                "statsfe2.update.microsoft.com.akadns.net"
                "statsfe2.ws.microsoft.com"
                "survey.watson.microsoft.com"
                "telecommand.telemetry.microsoft.com"
                "telecommand.telemetry.microsoft.com.nsatc.net"
                "telemetry.appex.bing.net"
                "telemetry.appex.bing.net:443"
                "telemetry.microsoft.com"
                "telemetry.urs.microsoft.com"
                "vortex-sandbox.data.microsoft.com"
                "vortex-win.data.microsoft.com"
                "vortex.data.microsoft.com"
                "watson.live.com"
                "watson.microsoft.com"
                "watson.ppe.telemetry.microsoft.com"
                "watson.telemetry.microsoft.com"
                "watson.telemetry.microsoft.com.nsatc.net"
                "wes.df.telemetry.microsoft.com"
                "win10.ipv6.microsoft.com"
                "www.bingads.microsoft.com"
                "www.go.microsoft.akadns.net"
            )
            foreach ($domain in $domains) {
                if (-Not (Select-String -Path $hosts_file -Pattern $domain)) {
                    echo "0.0.0.0 $domain" | Out-File -Encoding ASCII -Append $hosts_file
                }
            }
            
            write-host "Adding telemetry Ip's to Windows Firewall"
            $ips = @(
                "134.170.30.202"
                "137.116.81.24"
                "204.79.197.200"
                "23.218.212.69"
                "65.39.117.230"
                "65.55.108.23"
            )
            Remove-NetFirewallRule -DisplayName "Block Telemetry IPs" -ErrorAction SilentlyContinue
            New-NetFirewallRule -DisplayName "Block Telemetry IPs" -Direction Outbound `
                -Action Block -RemoteAddress ([string[]]$ips)
            write-host "Done!"
        }
        
        "G3"
        {
            Get-Variable true | Out-Default; Clear-Host;
            write-host "Disabling telemetry via Group Policies"
            write-host "NB: This will be ignored by Windows unless you have Windows Enterprise editon!"
            mkdir -Force "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
            sp "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "AllowTelemetry" 0
            write-host "Done!"
        }
        
        "G4"
        {
            Get-Variable true | Out-Default; Clear-Host;
            write-host "Apply MarkC's mouse acceleration fix"
            sp "HKCU:\Control Panel\Mouse" "MouseSensitivity" "10"
            sp "HKCU:\Control Panel\Mouse" "MouseSpeed" "0"
            sp "HKCU:\Control Panel\Mouse" "MouseThreshold1" "0"
            sp "HKCU:\Control Panel\Mouse" "MouseThreshold2" "0"
            sp "HKCU:\Control Panel\Mouse" "SmoothMouseXCurve" ([byte[]](0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0xCC, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x80, 0x99, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x66, 0x26, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x33, 0x33, 0x00, 0x00, 0x00, 0x00, 0x00))
            sp "HKCU:\Control Panel\Mouse" "SmoothMouseYCurve" ([byte[]](0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x38, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x70, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xA8, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00))
            write-host "Done!"            
        }   
                
        "G5"
        {
            Get-Variable true | Out-Default; Clear-Host;
            write-host "Disable easy access keyboard stuff"
            sp "HKCU:\Control Panel\Accessibility\StickyKeys" "Flags" "506"
            sp "HKCU:\Control Panel\Accessibility\Keyboard Response" "Flags" "122"
            sp "HKCU:\Control Panel\Accessibility\ToggleKeys" "Flags" "58"
            write-host "Done!"
        }   
        
        "G6"
        {
            Get-Variable true | Out-Default; Clear-Host;
            write-host "God Mode has been enabled, check out the new link on your Desktop"            
            mkdir "$env:UserProfile\Desktop\GodMode.{ED7BA470-8E54-465E-825C-99712043E01C}"
            write-host "Done!"
        }    
        
        "F6"
        {
            Get-Variable true | Out-Default; Clear-Host;
            write-host "Forcing a time resynchronization"    
            net start w32time
            w32tm /config /manualpeerlist:"time.nist.gov time.windows.com time-nw.nist.gov time-a.nist.gov time-b.nist.gov time-a.timefreq.bldrdoc.gov time-b.timefreq.bldrdoc.gov time-c.timefreq.bldrdoc.gov utcnist.colorado.edu" /syncfromflags:manual /update            
            W32tm /resync /force
            write-host "Done!"
        }
        
        "F7"
        {
            Get-Variable true | Out-Default; Clear-Host;
            write-host "Resetting system services" 
            net stop wuauserv 
            net stop appidsvc
            net stop cryptsvc
            Ren %systemroot%\SoftwareDistribution SoftwareDistribution.bak
            Ren %systemroot%\system32\catroot2 catroot2.bak
            net start bits
            net start wuauserv
            net start appidsvc
            net start cryptsvc
            write-host "Done!"
        }
        
        "G8"
        {
            Get-Variable true | Out-Default; Clear-Host;
            write-host "Restoring old volume slider" 
            mkdir -Force "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\MTCUVC"
            sp "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\MTCUVC" "EnableMtcUvc" 0
            write-host "Done!"
        }
        
        "Q"
        {
            Get-Variable true | Out-Default; Clear-Host;
            Write-Output (Invoke-WebRequest http://pages.cs.wisc.edu/~ballard/bofh/excuses -OutVariable excuses).content.split([Environment]::NewLine)[(get-random $excuses.content.split([Environment]::NewLine).count)]
        
            
        }
        "G9"
        {
            write-host "Uninstalling default apps"
            $apps = @(
                # default Windows 10 apps
                "Microsoft.3DBuilder"
                "Microsoft.Appconnector"
                "Microsoft.BingFinance"
                "Microsoft.BingNews"
                "Microsoft.BingSports"
                "Microsoft.BingWeather"
                "Microsoft.Getstarted"
                "Microsoft.MicrosoftOfficeHub"
                "Microsoft.MicrosoftSolitaireCollection"
                "Microsoft.Office.OneNote"
                "Microsoft.People"
                "Microsoft.SkypeApp"
                #"Microsoft.Windows.Photos"
                "Microsoft.WindowsAlarms"
                #"Microsoft.WindowsCalculator"
                "Microsoft.WindowsCamera"
                "Microsoft.WindowsMaps"
                "Microsoft.WindowsPhone"
                "Microsoft.WindowsSoundRecorder"
                #"Microsoft.WindowsStore"
                "Microsoft.XboxApp"
                "Microsoft.ZuneMusic"
                "Microsoft.ZuneVideo"
                "microsoft.windowscommunicationsapps"
                "Microsoft.MinecraftUWP"
            
                # non-Microsoft
                "9E2F88E3.Twitter"
                "Flipboard.Flipboard"
                "ShazamEntertainmentLtd.Shazam"
                "king.com.CandyCrushSaga"
                "ClearChannelRadioDigital.iHeartRadio"
            )

            foreach ($app in $apps) {
                Get-AppxPackage -Name $app -AllUsers | Remove-AppxPackage
            
                Get-AppXProvisionedPackage -Online |
                    where DisplayName -EQ $app |
                    Remove-AppxProvisionedPackage -Online
            }
        }
    }
} until ( $choice -match "X" )
