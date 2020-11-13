
$CrashReportAgeThreshold = 7
$DebugPreference = "Continue"


# if bookmark folder does not exist, create it
$SupportFolder = "$($env:ProgramData)\AppCrashGather"
if (!(Test-Path -Path $SupportFolder)) { New-Item -Path $SupportFolder -ItemType Directory | Out-Null }

# if bookmark file exists, get the date it contains
$BookmarkFile = "$($SupportFolder)\LastScanDate.txt"
if (Test-Path -Path $BookmarkFile) {
    [datetime]$BookmarkDate = Get-Content -Path $BookmarkFile
} else {
    $BookmarkDate =  Get-Date -Date "01/01/1970"
}


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


$UserProfiles = Get-WmiObject -Class Win32_UserProfile | ?{$_.SID.length -gt 8} | Select SID, LocalPath, LastUseTime, Loaded
foreach ($UserProfile in $UserProfiles) 
{

    $PendingPath = "$($Userprofile.Localpath)\AppData\Roaming\Mozilla\Firefox\Crash Reports\Pending"
    if (Test-Path -Path $PendingPath) 
    {

        $Application = "Firefox"

        # get the userid from the localpath
        $user = [regex]::Matches($UserProfile.LocalPath,"([^\\]+$)").groups[1].value
        $user = $User -replace "\..*",""
        $user = $user.ToUpper()

        $extraFiles = Get-ChildItem -path $PendingPath -Filter "*.extra" | Where-Object {$_.CreationTime -gt $BookmarkDate }
        foreach ($extraFile in $extraFiles) 
        {
            # todo - add logic to process files since last bookmark for profile path; or do alex's idea and just delete after processing.

            write-debug "processing file $($extraFile.name) with create date $($extrafile.CreationTime)..."
            # get file content into object               
            $content = $extraFile | Get-Content

            # initialize the event object
            $Event=@{}
            $eventParsed = $false

            # test to see if the whole file is JSON
            try 
            { 
                $content | ConvertFrom-Json | Out-Null
                $json = $true
            } 
            catch 
            {
                $json = $false
            }

            # process potential variations of json file
            if ($json -eq $true) 
            {

                $content = $content | ConvertFrom-Json

                # extract event if the mainstream schema was found
                if ($content.AdapterDeviceID -and $content.StackTraces -and $content.TelemetryEnvironment) 
                {

                    Write-Debug "signposts of mainstream schema detected"

                    $eventParsed = $true

                    $CrashTime = $content.CrashTime
                    $CrashTimeSplunk = (Get-Date 01.01.1970).ToLocalTime()+([System.TimeSpan]::fromseconds($CrashTime))
                    $CrashTimeSplunk = format-splunktime -inputDate $CrashTimeSplunk

                    $StartupTime = $content.startuptime
                    $UptimeTS = $content.UptimeTS
                    if ($UptimeTS -le 60) { $StartupCrash = "TRUE" } else { $StartupCrash = "FALSE" }

                    $url = $content.url
                    $Addons = $content.'add-ons'
                    $SecondsSinceLastCrash = $content.SecondsSinceLastCrash

                    $StackTraces = $content.StackTraces

                    $ThreadIdNameMapping = ($content.ThreadIdNameMapping) -split ","

                    $TelemetryEnvironment = $content.TelemetryEnvironment | ConvertFrom-Json
                                
                    # Find module filename whose start address is equal to or just above address of crash
                    $NearestModule = "Unknown"
                    foreach ($module in $StackTraces.modules | Sort-Object base_addr) {
                        if ($StackTraces.crash_info.address -ge $module.base_addr) {
                            $NearestModule = $module.filename
                            break
                        }
                    }
                }

            }
            else 
            {                
            
                # process potential variations of non-json format

                # extract event if the legacy schema was found
                if ($content -match "^AdapterDeviceID=" -and $content -match "^StackTraces=" -and $content -match "^TelemetryEnvironment=")
                {

                    Write-Debug "signposts of legacy schema detected"

                    $eventParsed = $true

                    $CrashTime = (($content -match "^CrashTime=") -split "^CrashTime=")[1]
                    $CrashTimeSplunk = (Get-Date 01.01.1970).ToLocalTime()+([System.TimeSpan]::fromseconds($CrashTime))
                    $CrashTimeSplunk = format-splunktime -inputDate $CrashTimeSplunk

                    $StartupTime = (($content -match "^StartupTime=") -split "^StartupTime=")[1]
                    $UptimeTS = (($content -match "^UptimeTS=") -split "^UptimeTS=")[1]
                    if ($UptimeTS -le 60) { $StartupCrash = "TRUE" } else { $StartupCrash = "FALSE" }

                    $url = (($content -match "^URL=") -split "^URL=")[1]
                    $Addons = (($content -match "^Add-ons=") -split "^Add-ons=")[1]
                    $SecondsSinceLastCrash = (($content -match "^SecondsSinceLastCrash=") -split "^SecondsSinceLastCrash=")[1]
                    $StackTraces = (($content -match "^StackTraces=") -split "^StackTraces=")[1] | ConvertFrom-Json

                    $ThreadIdNameMapping = (($content -match "^ThreadIdNameMapping=") -split "^ThreadIdNameMapping=") -split ","
                    $TelemetryEnvironment = (($content -match "^TelemetryEnvironment=") -split "^TelemetryEnvironment=")  | ConvertFrom-Json
                
                    # Find module filename whose start address is equal to or just above address of crash
                    $NearestModule = "Unknown"
                    foreach ($module in $StackTraces.modules | Sort-Object base_addr) {
                        if ($StackTraces.crash_info.address -ge $module.base_addr) {
                            $NearestModule = $module.filename
                            break
                        }
                    }
                
                }

            }


            # if we have extracted data, write out the event
            if ($eventParsed -eq $true) {

                Write-Debug "assembling report hash"

                $Event = "$($CrashTimeSplunk) -"
                $Event += " Application=`"$($Application)`""
                $Event += " version=`"$($TelemetryEnvironment.build.displayVersion)`""
                $Event += " Report=`"$($extraFile.Name)`""
                $Event += " User=`"$($user)`""
                $Event += " DefaultBrowser=`"$($TelemetryEnvironment.settings.isDefaultBrowser)`""
                $Event += " CrashTime=`"$($CrashTime)`""
                $Event += " StartupTime=`"$($StartupTime)`""
                $Event += " StartupCrash=`"$($StartupCrash)`""
                $Event += " UptimeTS=`"$($UptimeTS)`""
                $Event += " url=`"$($URL)`""
                $Event += " SecondsSinceLastCrash=`"$($SecondsSinceLastCrash)`""
                $Event += " crash_info_address=`"$($StackTraces.crash_info.address)`""
                $Event += " crash_info_thread=`"$($StackTraces.crash_info.crashing_thread)`""
                $Event += " crash_info_type=`"$($StackTraces.crash_info.type)`""
                $Event += " crash_address_module=`"$($NearestModule)`""
                $Event += " Addons=`"$($Addons)`""

                Write-Output $Event

            }
        }

        # if file is older than threshold, remove
        if ((New-TimeSpan -Start $extraFile.CreationTime).TotalDays -ge $CrashReportAgeThreshold) 
        {
            $dmpFullName = $extraFile.FullName -replace ".extra$",".dmp"
            if (Test-Path -Path $dmpFullName) { Remove-Item -Path $dmpFullName -Force -WhatIf }
            if (Test-Path -Path $extraFile.FullName) { Remove-Item -Path $extraFile.FullName -Force -WhatIf }
        }
        else
        {
            Write-Debug "$($extraFile.FullName) is newer than threshold age; keeping."
        }
    }   
}

# write-out a bookmark file indicating that we have been here before
Set-Content -Path $BookmarkFile -Value (Get-Date)
