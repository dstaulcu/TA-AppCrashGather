$ErrorActionPreference = "Stop"
# function to transform datetime objet to a string splunk can easily consume
function format-splunktime {
    param (
        [parameter(Mandatory=$false)][datetime]$inputDate=(Get-Date)
    )

    $inputDateString = $inputDate.ToString('MM-dd-yyyy HH:mm:ss zzzz')
    $inputDateParts = $inputDateString -split " "
    $inputDateZone = $inputDateParts[2] -replace ":",""
    $outputDateString  = "$($inputDateParts[0]) $($inputDateParts[1]) $($inputDateZone)"
    return $outputDateString
}
#Application
$Application = "Firefox"
#Get Paths for files
$PendingPath = "C:\users\*\AppData\Roaming\Mozilla\Firefox\Crash Reports\Pending"
    $extraFiles = Get-ChildItem -path $PendingPath -Filter "*.extra"
    foreach ($extraFile in $extraFiles)
    {
    $legacyFF = $false
    write-debug "processing file $($extraFile.name)..."
    Write-Host "processing file $($extraFile.name)..."
        try
        {
        $content = $extraFile | Get-Content | ConvertFrom-Json
        }
        catch{$legacyFF = $true}
        try
        {
        $contentLegacy = $extraFile | Get-Content
        }
        catch{}
                    
        if(($content -ne $null) -and ($legacyFF -eq $false))
            {
            Write-Host "FireFox 70 or Later Detected"
            Write-Debug "FireFox 70 or Later Detected"
            $CrashTime = $content.CrashTime
            $CrashTimeSplunk = (Get-Date 01.01.1970).ToLocalTime()+([System.TimeSpan]::fromseconds($CrashTime))
            $CrashTimeSplunk = format-splunktime -inputDate $CrashTimeSplunk
                
            $StartupTime = $content.StartupTime
            $UptimeTS = $content.UptimeTS
            $url = $content.URL
            $version = $content.Version
            $Addons = $content.'Add-ons'
            $StackTraces = $content.StackTraces
            #$ModuleSignatureInfo = $content.ModuleSignatureInfo
            $crash_info_address = $StackTraces.crash_info.address
            $crashing_thread = $StackTraces.crash_info.crashing_thread
            $crash_info_type = $StackTraces.crash_info.type

            $Event = "$($CrashTimeSplunk) -"
            $Event += " Application=`"$($Application)`""
            $Event += " Report=`"$($extraFile.Name)`""
            $Event += " User=`"$($user)`""
            $Event += " CrashTime=`"$($CrashTime)`""
            $Event += " StartupTime=`"$($StartupTime)`""
            $Event += " UptimeTS=`"$($UptimeTS)`""
            $Event += " url=`"$($url)`""
            $Event += " version=`"$($version)`""
            $Event += " crash_info_address=`"$($crash_info_address)`""
            $Event += " crash_info_thread=`"$($crashing_thread)`""
            $Event += " crash_info_type=`"$($crash_info_type)`""
            $Event += " Addons=`"$($Addons)`""
            Write-Output $Event
            }

            if(($contentLegacy -ne $null) -and ($legacyFF -eq $true))
            {
            Write-Host "FireFox 60 or Earlier Detected"
            Write-Debug "FireFox 60 or Earlier Detected"

            $CrashTime = (($contentLegacy -match "^CrashTime=") -split "^CrashTime=")[1]
            $CrashTimeSplunk = (Get-Date 01.01.1970).ToLocalTime()+([System.TimeSpan]::fromseconds($CrashTime))
            $CrashTimeSplunk = format-splunktime -inputDate $CrashTimeSplunk
            
            $StartupTime = (($contentLegacy -match "^StartupTime=") -split "^StartupTime=")[1]
            $UptimeTS = (($contentLegacy -match "^UptimeTS=") -split "^UptimeTS=")[1]
            $url = (($contentLegacy -match "^URL=") -split "^URL=")[1]
            $version = (($contentLegacy -match "^Version=") -split "^Version=")[1]
            $Addons = (($contentLegacy -match "^Add-ons=") -split "^Add-ons=")[1]
            $StackTraces = (($contentLegacy -match "^StackTraces=")  -split "^StackTraces=")[1]
            #$ModuleSignatureInfo = (($contentLegacy -match "^ModuleSignatureInfo=")  -split "^ModuleSignatureInfo=")[1]
            #$ModuleSignatureInfo = $ModuleSignatureInfo | ConvertFrom-Json
            #$ModuleSignatureInfo = $content.ModuleSignatureInfo
            $crash_info_address = $StackTraces.crash_info.address
            $crashing_thread = $StackTraces.crash_info.crashing_thread
            $crash_info_type = $StackTraces.crash_info.type

            $Event = "$($CrashTimeSplunk) -"
            $Event += " Application=`"$($Application)`""
            $Event += " Report=`"$($extraFile.Name)`""
            $Event += " User=`"$($user)`""
            $Event += " CrashTime=`"$($CrashTime)`""
            $Event += " StartupTime=`"$($StartupTime)`""
            $Event += " UptimeTS=`"$($UptimeTS)`""
            $Event += " url=`"$($url)`""
            $Event += " version=`"$($version)`""
            $Event += " crash_info_address=`"$($StackTraces.crash_info.address)`""
            $Event += " crash_info_thread=`"$($StackTraces.crash_info.crashing_thread)`""
            $Event += " crash_info_type=`"$($StackTraces.crash_info.type)`""
            $Event += " Addons=`"$($Addons)`""
            
            Write-Output $Event
    }
    }
