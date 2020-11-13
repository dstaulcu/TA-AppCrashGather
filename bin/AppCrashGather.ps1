
$CrashReportAgeThreshold = 7

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

        $extraFiles = Get-ChildItem -path $PendingPath -Filter "*.extra"
        foreach ($extraFile in $extraFiles) 
        {
            # todo - add logic to process files since last bookmark for profile path; or do alex's idea and just delete after processing.

            write-debug "processing file $($extraFile.name)..."
            # get file content into object               
            $content = $extraFile | Get-Content

            if ($content -match "^AdapterDeviceID=")
            {

                $CrashTime = (($content -match "^CrashTime=") -split "^CrashTime=")[1]
                $CrashTimeSplunk = (Get-Date 01.01.1970).ToLocalTime()+([System.TimeSpan]::fromseconds($CrashTime))
                $CrashTimeSplunk = format-splunktime -inputDate $CrashTimeSplunk

                $StartupTime = (($content -match "^StartupTime=") -split "^StartupTime=")[1]
                $UptimeTS = (($content -match "^UptimeTS=") -split "^UptimeTS=")[1]
                if ($UptimeTS -le 60) { $StartupCrash = "TRUE" } else { $StartupCrash = "FALSE" }

                $url = (($content -match "^URL=") -split "^URL=")[1]
                $version = (($content -match "^Version=") -split "^Version=")[1]
                $Addons = (($content -match "^Add-ons=") -split "^Add-ons=")[1]
                $SecondsSinceLastCrash = (($content -match "^SecondsSinceLastCrash=") -split "^SecondsSinceLastCrash=")[1]
                $StackTraces = (($content -match "^StackTraces=") -split "^StackTraces=")[1] | ConvertFrom-Json

                $ThreadIdNameMapping = (($content -match "^ThreadIdNameMapping=") -split "^ThreadIdNameMapping=") -split ","
                $TelemetryEnvironment = (($content -match "^TelemetryEnvironment=") -split "^TelemetryEnvironment=")  | ConvertFrom-Json
                
                # Find module filename whose start address is equal to or just above address of crash
                $NearestModule = "Unknown"
                foreach ($module in $StackTraces.modules | Sort-Object $module.base_addr) {
                    if ($StackTraces.crash_info.address -ge $module.base_addr) {
                        $NearestModule = $module.filename
                        break
                    }
                }
                
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
                $Event += " url=`"$($url)`""
                $Event += " SecondsSinceLastCrash=`"$($SecondsSinceLastCrash)`""
                $Event += " crash_info_address=`"$($StackTraces.crash_info.address)`""
                $Event += " crash_info_thread=`"$($StackTraces.crash_info.crashing_thread)`""
                $Event += " crash_info_type=`"$($StackTraces.crash_info.type)`""
                $Event += " crash_address_module='`"$($NearestModule)`""
                $Event += " Addons=`"$($Addons)`""

                Write-Output $Event

            }
            else 
            {
                write-debug "this file is from version having unknown structure"
            }
        }
    }   
}


