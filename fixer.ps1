If (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
{   
$arguments = "& '" + $myinvocation.mycommand.definition + "'"
Start-Process powershell -Verb runAs -ArgumentList $arguments
Break
}

do {
    do {
        write-host ""
        write-host "BattleIT Group LTD 2015, v0.2"
        write-host "Windows 10 helper script + goodies"
        write-host "" 
        write-host "A - Explorer: show hidden files, extensions and empty drives"
        write-host "B - Repair Windows Image (slow)"
        write-host "C - Re-register ALL Windows Store Apps"
        write-host "D - Reset Windows Store Cache"
        write-host "E - Verify driver file signatures"            
        write-host "F - Reset networking IP and flush DNS"
        write-host "G - Gather extended log files from DISM"
        write-host "H - Install fancy Sysinternals Utilities"
        write-host "I - Block telemetry via Windows Firewall & Hosts file"       
        write-host "J - Block telemetry via GPO (Enterprise only)"      
        write-host "K - Mouse acceleration fix (100% DPI only)"
        write-host "L - Disable StickyKeys and stuff"               
        write-host "M - Enable God Mode (places a shortcut on Desktop)"     
        write-host "N - Sync system time with Internet"        
        write-host "O - Reset system services"         
        write-host "P - Restore old volume slider"               
        write-host ""
        write-host ""
        write-host "Q - Help"
        write-host "X - Exit"
        write-host ""
        write-host -nonewline "Type your choice and press Enter: "
        
        $choice = read-host
        
        write-host ""
        
        $ok = @("A","B","C","D","E","F","G","H","I","J","K","L","M","N","O","P","Q","X") -contains $choice
        if ( -not $ok) { write-host "Invalid selection" }
    } until ( $ok )
    
    switch -Regex ( $choice ) {
        "A"
        {
            Get-Variable true | Out-Default; Clear-Host;
            write-host "Enabling Explorer to show hidden files, extensions and empty drives"      
            sp "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "Hidden" 1
            sp "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "HideFileExt" 0
            sp "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "HideDrivesWithNoMedia" 0
            write-host "Done!"  
        }
        
        "B"
        {
            Get-Variable true | Out-Default; Clear-Host;
            write-host "Repairing a Windows Image and scanning for corrupted files."
            Dism /Online /Cleanup-Image /RestoreHealth
            Dism /Online /Cleanup-Image /StartComponentCleanup
            SFC /scannow
            write-host "Done!"  
        }

        "C"
        {
            Get-Variable true | Out-Default; Clear-Host;
            write-host "Re-registering all Windows Store Apps'"
            $manifest = (Get-AppxPackage Microsoft.WindowsStore).InstallLocation + '\AppxManifest.xml' ; Add-AppxPackage -DisableDevelopmentMode -Register $manifest 
Get-AppXPackage -AllUsers |Where-Object {$_.InstallLocation -like "*SystemApps*"} | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
            powershell -ExecutionPolicy Unrestricted Add-AppxPackage -DisableDevelopmentMode -Register $Env:SystemRoot\ImmersiveControlPanel\AppxManifest.xml
            write-host "Done!"  
        }
        
        "D"
        {
            Get-Variable true | Out-Default; Clear-Host;
            write-host "Resetting Windows Store Cache'"
            Invoke-Item WSReset.exe
            write-host "Done!"  
        }
        
        "E"
        {
            Get-Variable true | Out-Default; Clear-Host;
            write-host "File Signature Verification started."           
            sigverif
            write-host "Done!"  
        }

        "F"
        {
            Get-Variable true | Out-Default; Clear-Host;
            write-host "Resetting your networking IP address"
            ipconfig /release
            ipconfig /renew
            ipconfig /flushdns
            write-host "Done!"  
        }
        
        "G"
        {
            Get-Variable true | Out-Default; Clear-Host;
            write-host "Gathering log files"
            Dism /Online /Cleanup-Image /CheckHealth
            Dism /Online /Cleanup-Image /ScanHealth
            Invoke-Item C:\Windows\Logs\DISM\dism.log
            write-host "Done!"  
        }
        
        "H"
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
        
        "I"
        {
            Get-Variable true | Out-Default; Clear-Host;
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
        
        "J"
        {
            Get-Variable true | Out-Default; Clear-Host;
            write-host "Disabling telemetry via Group Policies"
            write-host "NB: This will be ignored by Windows unless you have Windows Enterprise editon!"
            mkdir -Force "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
            sp "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "AllowTelemetry" 0
            write-host "Done!"
        }
        
        "K"
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
                
        "L"
        {
            Get-Variable true | Out-Default; Clear-Host;
            write-host "Disable easy access keyboard stuff"
            sp "HKCU:\Control Panel\Accessibility\StickyKeys" "Flags" "506"
            sp "HKCU:\Control Panel\Accessibility\Keyboard Response" "Flags" "122"
            sp "HKCU:\Control Panel\Accessibility\ToggleKeys" "Flags" "58"
            write-host "Done!"
        }   
        
        "M"
        {
            Get-Variable true | Out-Default; Clear-Host;
            write-host "God Mode has been enabled, check out the new link on your Desktop"            
            mkdir "$env:UserProfile\Desktop\GodMode.{ED7BA470-8E54-465E-825C-99712043E01C}"
            write-host "Done!"
        }    
        
        "N"
        {
            Get-Variable true | Out-Default; Clear-Host;
            write-host "Forcing a time resynchronization"    
            net start w32time
            w32tm /config /manualpeerlist:"time.nist.gov time.windows.com time-nw.nist.gov time-a.nist.gov time-b.nist.gov time-a.timefreq.bldrdoc.gov time-b.timefreq.bldrdoc.gov time-c.timefreq.bldrdoc.gov utcnist.colorado.edu" /syncfromflags:manual /update            
            W32tm /resync /force
            write-host "Done!"
        }
        
        "O"
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
        
        "P"
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
            write-host "Manual for this script"
            write-host ""  
            write-host "A - Explorer: enables showing of hidden files, extensions and empty drives"
            write-host "B - Repair Windows Image. Use this if Windows is not acting normally. This will take some time."
            write-host "C - Re-register ALL Windows Store Apps. This should fix downloading application update problems."
            write-host "D - Reset Windows Store Cache. In case option C did not help"
            write-host "E - Verify driver file signatures. In X64 all drivers must be signed properly."            
            write-host "F - Reset networking IP and flush DNS. It will fix 99% of network problems faster than Diagnostics tool"
            write-host "G - Gather extended log files from DISM. Then use those logs in forum to ask for help."
            write-host "H - Install fancy Sysinternals Utilities. These will help you a lot if you are a 'power user'"
            write-host "I - Block telemetry via Windows Firewall & Hosts file. Not guranteed 100% to work but better than nothing."       
            write-host "J - Block telemetry via GPO (Enterprise only). If you have Enterprise, you can use it for additional blocking."      
            write-host "K - Mouse acceleration fix (100% DPI only). Sadly not working with other DPI settings."
            write-host "L - Disable StickyKeys and stuff. No more any of that"               
            write-host "M - Enable God Mode (places a shortcut on Desktop). More of a gimmic if you ask me."     
            write-host "N - Sync system time with Internet. No.1 problem why you don't have internet at Store app."        
            write-host "O - Reset system services. This will make shure that services are working as needed."         
            write-host "P - Restore old volume slider. For those who crave for easier access to volume mixer"    
            write-host "" 
            
        }
    }
} until ( $choice -match "X" )
