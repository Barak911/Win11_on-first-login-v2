# Install-Drivers.ps1
#Requires -RunAsAdministrator

# =========================
# LOGGING CONFIGURATION
# =========================
$LogTimestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$LogFile = "C:\FirstLogon_logs_$LogTimestamp.txt"

Start-Transcript -Path $LogFile -Append

function Write-Log {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        [ValidateSet("INFO", "SUCCESS", "WARNING", "ERROR", "SECTION")]
        [string]$Level = "INFO"
    )
    
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LevelPadded = $Level.PadRight(7)
    
    switch ($Level) {
        "SECTION" { $LogEntry = "`n$("=" * 80)`n[$Timestamp] $Message`n$("=" * 80)" }
        default   { $LogEntry = "[$Timestamp] [$LevelPadded] $Message" }
    }
    
    Add-Content -Path $LogFile -Value $LogEntry -ErrorAction SilentlyContinue
    
    switch ($Level) {
        "SUCCESS" { Write-Host $LogEntry -ForegroundColor Green }
        "WARNING" { Write-Host $LogEntry -ForegroundColor Yellow }
        "ERROR"   { Write-Host $LogEntry -ForegroundColor Red }
        "SECTION" { Write-Host $LogEntry -ForegroundColor Cyan }
        default   { Write-Host $LogEntry }
    }
}

Write-Log "FIRST LOGON SCRIPT STARTED" -Level SECTION
Write-Log "Log file initialized at: $LogFile"

# Collect system info
try {
    $ComputerInfo = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
    $OSInfo = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    $BIOSInfo = Get-CimInstance Win32_BIOS -ErrorAction Stop
    
    Write-Log "Computer Name: $($ComputerInfo.Name)"
    Write-Log "Manufacturer: $($ComputerInfo.Manufacturer)"
    Write-Log "Model: $($ComputerInfo.Model)"
    Write-Log "OS: $($OSInfo.Caption) - Build $($OSInfo.BuildNumber)"
    Write-Log "BIOS Serial: $($BIOSInfo.SerialNumber)"
    Write-Log "Total RAM: $([math]::Round($ComputerInfo.TotalPhysicalMemory / 1GB, 2)) GB"
    Write-Log "Script running as: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)"
} catch {
    Write-Log "Could not retrieve some system information: $_" -Level WARNING
}

# =========================
# 0) Config
# =========================
Write-Log "CONFIGURATION" -Level SECTION
$SvcUserName    = 'DanyelService'
$SvcUserPass    = 'Danyel20Service'
$NotifyTitle    = 'System Setup'
$NotifyText     = 'Running final installation tasks. WAIT for the computer to restart.'

Write-Log "Service Username: $SvcUserName"

function Get-SysToolPath($exe) {
    $p1 = Join-Path $env:WINDIR "System32\$exe"
    $p2 = Join-Path $env:WINDIR "sysnative\$exe"
    if (Test-Path $p1) { return $p1 }
    if (Test-Path $p2) { return $p2 }
    return $exe
}

$PnPUtilPath = Get-SysToolPath 'pnputil.exe'
$MsgExePath  = Get-SysToolPath 'msg.exe'

Write-Log "PnPUtil Path: $PnPUtilPath"

# =========================
# FIX #2: Button map - store as simple hashtables with coordinates as integers
# The Point objects will be created INSIDE the function after assemblies are loaded
# =========================
$Global:ButtonMap = @(
    @{Name="Cytiva"; Tag="Cytiva"; X=10; Y=40; Index=0}, 
    @{Name="Sebia"; Tag="Sebia"; X=115; Y=40; Index=1},
    @{Name="Hamilton"; Tag="Hamilton"; X=220; Y=40; Index=2}
)


# ================================================================================
# IMAGERESOURCES BASE FILE COPY (TOP-LEVEL FILES ONLY)
# ================================================================================
Write-Log "Copying base ImageResources files (no subfolders) to C:\danyel..." -Level INFO

$ImageResourcesPath = $null

# Find ImageResources on a removable drive (DriveType = 2)
try {
    foreach ($drive in (Get-CimInstance Win32_LogicalDisk -Filter "DriveType=2" -ErrorAction SilentlyContinue)) {
        $candidate = Join-Path $drive.DeviceID 'ImageResources'
        if (Test-Path $candidate) {
            $ImageResourcesPath = $candidate
            break
        }
    }
} catch {
    Write-Log "Error while searching for ImageResources on removable drives: $($_.Exception.Message)" -Level WARNING
}

if (-not $ImageResourcesPath) {
    Write-Log "ImageResources folder not found on any removable drive. Skipping base file copy." -Level WARNING
} else {
    $destRoot = 'C:\danyel'

    # Ensure destination folder exists
    if (-not (Test-Path $destRoot)) {
        try {
            New-Item -Path $destRoot -ItemType Directory -Force | Out-Null
            Write-Log "Created destination folder: C:\danyel" -Level INFO
        } catch {
            Write-Log "Failed to create destination folder C:\danyel: $($_.Exception.Message)" -Level ERROR
        }
    }

    # Get only top-level files (no subfolders, no recursion)
    $files = Get-ChildItem -Path $ImageResourcesPath -File -ErrorAction SilentlyContinue
    $count = 0

    foreach ($file in $files) {
        try {
            Copy-Item -Path $file.FullName -Destination $destRoot -Force
            $count++
        } catch {
            Write-Log ("Failed to copy {0}: {1}" -f $file.Name, $_.Exception.Message) -Level WARNING
        }
    }

    Write-Log ("Copied {0} top-level files from {1} to {2}" -f $count, $ImageResourcesPath, $destRoot) -Level SUCCESS
}

# =========================
# 0.5) OneDrive Removal (Early - before user accounts)
# =========================
Write-Log "ONEDRIVE REMOVAL" -Level SECTION

function Remove-OneDriveCompletely {
    <#
    .SYNOPSIS
        Completely removes Microsoft OneDrive from Windows 11, including all files, registry entries, and services.
    .DESCRIPTION
        This function performs a comprehensive removal of OneDrive:
        - Stops all OneDrive processes
        - Uninstalls via OneDriveSetup.exe /uninstall
        - Removes AppX package for all users
        - Cleans up all OneDrive folders
        - Removes registry entries (including Explorer sidebar)
        - Stops and disables OneSyncSvc service
        - Prevents automatic reinstallation via Group Policy
    #>

    Write-Log "Starting comprehensive OneDrive removal..." -Level INFO

    # ===== 1. Stop OneDrive Processes =====
    Write-Log "  Stopping OneDrive processes..." -Level INFO
    $processNames = @('OneDrive', 'OneDriveSetup', 'FileCoAuth')
    foreach ($proc in $processNames) {
        Get-Process -Name $proc -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    }
    Start-Sleep -Seconds 3

    # ===== 2. Uninstall OneDrive via Setup executable =====
    Write-Log "  Running OneDrive uninstaller..." -Level INFO
    $oneDriveSetupPaths = @(
        "$env:SystemRoot\System32\OneDriveSetup.exe",
        "$env:SystemRoot\SysWOW64\OneDriveSetup.exe",
        "$env:LOCALAPPDATA\Microsoft\OneDrive\OneDriveSetup.exe",
        "$env:ProgramFiles\Microsoft OneDrive\OneDriveSetup.exe",
        "${env:ProgramFiles(x86)}\Microsoft OneDrive\OneDriveSetup.exe"
    )

    $uninstalled = $false
    foreach ($setupPath in $oneDriveSetupPaths) {
        if (Test-Path $setupPath) {
            try {
                $proc = Start-Process -FilePath $setupPath -ArgumentList '/uninstall' -Wait -PassThru -NoNewWindow -ErrorAction Stop
                if ($proc.ExitCode -eq 0) {
                    Write-Log "    Uninstalled via: $setupPath" -Level SUCCESS
                    $uninstalled = $true
                    break
                }
            } catch {
                Write-Log "    Failed to run uninstaller from: $setupPath" -Level WARNING
            }
        }
    }

    # Wait for uninstall to complete
    Start-Sleep -Seconds 5

    # ===== 3. Remove AppX Package =====
    Write-Log "  Removing OneDrive AppX packages..." -Level INFO
    try {
        Get-AppxPackage -AllUsers -Name '*OneDrive*' -ErrorAction SilentlyContinue |
            ForEach-Object {
                try {
                    Remove-AppxPackage -Package $_.PackageFullName -AllUsers -ErrorAction Stop
                    Write-Log "    Removed AppX: $($_.Name)" -Level SUCCESS
                } catch {
                    # Try without AllUsers
                    try {
                        Remove-AppxPackage -Package $_.PackageFullName -ErrorAction SilentlyContinue
                    } catch { }
                }
            }
    } catch { }

    # Remove provisioned package to prevent reinstall for new users
    try {
        Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -like '*OneDrive*' } |
            ForEach-Object {
                try {
                    Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName -ErrorAction Stop | Out-Null
                    Write-Log "    Removed provisioned package: $($_.DisplayName)" -Level SUCCESS
                } catch { }
            }
    } catch { }

    # ===== 4. Stop and Disable OneSyncSvc Service =====
    Write-Log "  Disabling OneDrive sync services..." -Level INFO
    $servicesToDisable = @('OneSyncSvc', 'OneSyncSvc_*')
    foreach ($svcPattern in $servicesToDisable) {
        Get-Service -Name $svcPattern -ErrorAction SilentlyContinue | ForEach-Object {
            try {
                Stop-Service -Name $_.Name -Force -ErrorAction SilentlyContinue
                Set-Service -Name $_.Name -StartupType Disabled -ErrorAction SilentlyContinue
                Write-Log "    Disabled service: $($_.Name)" -Level SUCCESS
            } catch { }
        }
    }

    # ===== 5. Clean Up OneDrive Folders =====
    Write-Log "  Removing OneDrive folders..." -Level INFO
    $foldersToRemove = @(
        "$env:LOCALAPPDATA\Microsoft\OneDrive",
        "$env:LOCALAPPDATA\OneDrive",
        "$env:ProgramData\Microsoft OneDrive",
        "$env:USERPROFILE\OneDrive",
        "$env:SystemDrive\OneDriveTemp",
        "$env:ProgramFiles\Microsoft OneDrive",
        "${env:ProgramFiles(x86)}\Microsoft OneDrive"
    )

    # Also remove OneDrive folders for all user profiles
    $userProfiles = Get-ChildItem -Path "$env:SystemDrive\Users" -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -notin @('Public', 'Default', 'Default User', 'All Users') }

    foreach ($profile in $userProfiles) {
        $foldersToRemove += "$($profile.FullName)\OneDrive"
        $foldersToRemove += "$($profile.FullName)\AppData\Local\Microsoft\OneDrive"
    }

    foreach ($folder in $foldersToRemove) {
        if (Test-Path $folder) {
            try {
                Remove-Item -Path $folder -Recurse -Force -ErrorAction Stop
                Write-Log "    Removed folder: $folder" -Level SUCCESS
            } catch {
                # Try with robocopy empty folder trick for stubborn folders
                try {
                    $emptyDir = "$env:TEMP\EmptyDir_$(Get-Random)"
                    New-Item -Path $emptyDir -ItemType Directory -Force | Out-Null
                    & robocopy $emptyDir $folder /MIR /R:1 /W:1 2>&1 | Out-Null
                    Remove-Item -Path $folder -Recurse -Force -ErrorAction SilentlyContinue
                    Remove-Item -Path $emptyDir -Force -ErrorAction SilentlyContinue
                } catch { }
            }
        }
    }

    # ===== 6. Clean Up Registry =====
    Write-Log "  Cleaning OneDrive registry entries..." -Level INFO

    # Remove OneDrive from Explorer sidebar (for current user and default)
    $explorerClsids = @(
        'HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}',
        'HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}',
        'Registry::HKEY_CLASSES_ROOT\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}',
        'Registry::HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}'
    )
    foreach ($clsid in $explorerClsids) {
        try {
            if (Test-Path $clsid) {
                Set-ItemProperty -Path $clsid -Name 'System.IsPinnedToNameSpaceTree' -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
                Write-Log "    Removed OneDrive from Explorer sidebar" -Level SUCCESS
            }
        } catch { }
    }

    # Remove OneDrive auto-start entries
    $autoStartPaths = @(
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
    )
    foreach ($regPath in $autoStartPaths) {
        try {
            $props = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
            if ($props.OneDrive) {
                Remove-ItemProperty -Path $regPath -Name 'OneDrive' -Force -ErrorAction SilentlyContinue
                Write-Log "    Removed OneDrive auto-start from: $regPath" -Level SUCCESS
            }
            if ($props.OneDriveSetup) {
                Remove-ItemProperty -Path $regPath -Name 'OneDriveSetup' -Force -ErrorAction SilentlyContinue
            }
        } catch { }
    }

    # Remove OneDrive configuration registry keys
    $regKeysToRemove = @(
        'HKCU:\SOFTWARE\Microsoft\OneDrive',
        'HKLM:\SOFTWARE\Microsoft\OneDrive',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\OneDrive',
        'HKLM:\SOFTWARE\Policies\Microsoft\OneDrive'
    )
    foreach ($regKey in $regKeysToRemove) {
        try {
            if (Test-Path $regKey) {
                Remove-Item -Path $regKey -Recurse -Force -ErrorAction SilentlyContinue
                Write-Log "    Removed registry key: $regKey" -Level SUCCESS
            }
        } catch { }
    }

    # ===== 7. Prevent OneDrive Reinstallation via Group Policy =====
    Write-Log "  Setting policies to prevent OneDrive reinstallation..." -Level INFO
    $policyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive'
    try {
        if (-not (Test-Path $policyPath)) {
            New-Item -Path $policyPath -Force | Out-Null
        }
        # DisableFileSyncNGSC = 1 prevents OneDrive from being used for file storage
        Set-ItemProperty -Path $policyPath -Name 'DisableFileSyncNGSC' -Value 1 -Type DWord -Force
        # DisableLibrariesDefaultSaveToOneDrive = 1 prevents default save to OneDrive
        Set-ItemProperty -Path $policyPath -Name 'DisableLibrariesDefaultSaveToOneDrive' -Value 1 -Type DWord -Force
        Write-Log "    Group Policy set to prevent OneDrive reinstallation" -Level SUCCESS
    } catch {
        Write-Log "    Failed to set OneDrive Group Policy: $($_.Exception.Message)" -Level WARNING
    }

    # ===== 8. Remove OneDrive Scheduled Tasks =====
    Write-Log "  Removing OneDrive scheduled tasks..." -Level INFO
    try {
        Get-ScheduledTask -TaskName '*OneDrive*' -ErrorAction SilentlyContinue | ForEach-Object {
            try {
                Unregister-ScheduledTask -TaskName $_.TaskName -Confirm:$false -ErrorAction Stop
                Write-Log "    Removed scheduled task: $($_.TaskName)" -Level SUCCESS
            } catch { }
        }
    } catch { }

    Write-Log "OneDrive removal complete" -Level SUCCESS
}

# Execute OneDrive removal
Remove-OneDriveCompletely

# =========================
# 1) Create local admin
# =========================
Write-Log "SERVICE ACCOUNT CREATION" -Level SECTION

# Check if service user exists
try {
    $exists = Get-LocalUser -Name $SvcUserName -ErrorAction SilentlyContinue
} catch {
    $exists = $null
}

# Prepare secure password
$SvcSecurePass = ConvertTo-SecureString $SvcUserPass -AsPlainText -Force

if (-not $exists) {
    Write-Log "User '$SvcUserName' does not exist. Creating..."
    try {
        New-LocalUser -Name $SvcUserName `
                      -Password $SvcSecurePass `
                      -PasswordNeverExpires `
                      -AccountNeverExpires `
                      -ErrorAction Stop
        Write-Log "Created." -Level SUCCESS
    } catch {
        Write-Log ("Failed to create user '{0}': {1}" -f $SvcUserName, $_.Exception.Message) -Level ERROR
    }
} else {
    Write-Log "User already exists. Updating..."
    try {
        Set-LocalUser -Name $SvcUserName `
                      -Password $SvcSecurePass `
                      -PasswordNeverExpires $true `
                      -ErrorAction Stop
        Write-Log "Password updated and set to never expire." -Level SUCCESS
    } catch {
        Write-Log ("Failed to update user '{0}': {1}" -f $SvcUserName, $_.Exception.Message) -Level WARNING
    }
}

# Ensure membership in Administrators group
Write-Log "Adding to Administrators group..."
try {
    Add-LocalGroupMember -Group 'Administrators' -Member $SvcUserName -ErrorAction Stop
    Write-Log "OK." -Level SUCCESS
} catch {
    if ($_.Exception.Message -match 'already.*member') {
        Write-Log "User is already in Administrators group." -Level INFO
    } else {
        Write-Log ("Warning: failed to add to Administrators: {0}" -f $_.Exception.Message) -Level WARNING
    }
}

# =========================
# 2) Ensure built-in User password doesn't expire
# =========================
Write-Log "USER ACCOUNT CONFIGURATION" -Level SECTION
try {
    $userAcct = Get-LocalUser -Name 'User' -ErrorAction Stop
    try {
        Set-LocalUser -Name 'User' -PasswordNeverExpires $true 
        Write-Log "'User' password never expires." -Level SUCCESS
    } catch {
        Write-Log "Failed: $_" -Level WARNING
    }
} catch {
    Write-Log "'User' account not found." -Level WARNING
}

# =========================
# 3) Notify User
# =========================
Write-Log "USER NOTIFICATION" -Level SECTION
try {
    Start-Process -FilePath $MsgExePath -ArgumentList '*', $NotifyText -WindowStyle Hidden -ErrorAction Stop
    Write-Log "msg.exe notification sent." -Level SUCCESS
} catch {
    Write-Log "msg.exe failed, trying Popup..."
    try {
        $ws = New-Object -ComObject WScript.Shell
        $null = $ws.Popup($NotifyText, 10, $NotifyTitle, 64)
        Write-Log "Popup ok." -Level SUCCESS
    } catch {
        Write-Host $NotifyText
        Write-Log "Displayed in console." -Level INFO
    }
}

# =========================
# 4) Pause Windows Updates and copy related files to C:\danyel
# =========================

function Disable-AutomaticUpdates { 
    $wuPolicyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
    $auKey        = Join-Path $wuPolicyPath 'AU'
    $uxSettings   = 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' # For Max Pause Days
    
    # 1. Ensure Policy Keys exist
    foreach ($path in @($wuPolicyPath, $auKey, $uxSettings)) {
        if (-not (Test-Path $path)) {
            New-Item -Path $path -Force | Out-Null
            Write-Log ("Created key: {0}" -f $path) -Level SUCCESS
        }
    }

    # 2. Configure Windows Update policies (Registry)
    $properties = @(
        # Standard Policy Settings (Under AU)
        @{ Key=$auKey; Name='NoAutoUpdate'; Value=1; Type='DWord'; Description='Disable Automatic Updates Client side detection/download' }, 
        @{ Key=$auKey; Name='AUOptions'; Value=2; Type='DWord'; Description='Notify for download, auto install' }, 
        @{ Key=$auKey; Name='NoAutoRebootWithLoggedOnUsers'; Value=1; Type='DWord'; Description='Prevent auto reboot when users are logged on' },
        
        # Feature Update Deferral (Long-Term Blocking - Under WindowsUpdate)
        @{ Key=$wuPolicyPath; Name='TargetReleaseVersion'; Value=1; Type='DWord'; Description='Enable blocking by TargetReleaseVersionInfo' },
        @{ Key=$wuPolicyPath; Name='TargetReleaseVersionInfo'; Value='22H2'; Type='String'; Description='Block feature updates past this version' },
        
        # ** GPO DEFERRAL SETTINGS FOR MAXIMUM PAUSE **
        # Defer Feature Updates for 365 days (max official GPO pause)
        @{ Key=$wuPolicyPath; Name='DeferFeatureUpdatesPeriodInDays'; Value=365; Type='DWord'; Description='Defer feature updates for 365 days' },
        @{ Key=$wuPolicyPath; Name='PauseFeatureUpdates'; Value=1; Type='DWord'; Description='Enable feature update pause' },
        # Defer Quality Updates for 30 days (max official GPO pause)
        @{ Key=$wuPolicyPath; Name='DeferQualityUpdatesPeriodInDays'; Value=30; Type='DWord'; Description='Defer quality updates for 30 days' },
        @{ Key=$wuPolicyPath; Name='PauseQualityUpdates'; Value=1; Type='DWord'; Description='Enable quality update pause' },
        
        # UX Settings: Set Max Pause Days to 7300 (~20 years) - Undocumented override
        @{ Key=$uxSettings; Name='FlightSettingsMaxPauseDays'; Value=7300; Type='DWord'; Description='Set maximum pause days in UI to 7300' } 
    )

    foreach ($prop in $properties) {
        try {
            New-ItemProperty -Path $prop.Key -Name $prop.Name -Value $prop.Value -PropertyType $prop.Type -Force | Out-Null
            Write-Log ("Set {0} to {1}" -f $prop.Name, $prop.Value) -Level SUCCESS
        } catch {
            Write-Log ("Failed to set {0} in {1}: {2}" -f $prop.Name, $prop.Key, $_) -Level ERROR
        }
    }
    
    # 3. Disable Windows Update Services (wuauserv & WaaSMedicSvc)
    Write-Log "Disabling Windows Update Services (wuauserv & WaaSMedicSvc)..." -Level INFO
    
    # Disable wuauserv
    try {
        Stop-Service -Name wuauserv -Force -ErrorAction SilentlyContinue
        Set-Service  -Name wuauserv -StartupType Disabled
        # Direct registry override as fail-safe (Start=4 is Disabled)
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\wuauserv" -Name "Start" -Value 4 -Type DWord -Force | Out-Null
        Write-Log "Windows Update service (wuauserv) set to Disabled." -Level SUCCESS
    } catch {
        Write-Log ("Failed to disable wuauserv: {0}" -f $_) -Level WARNING
    }

    # Disable WaaSMedicSvc (Registry bypass)
    $WaaSMedicPath = "HKLM:\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc"
    try {
        Stop-Service -Name WaaSMedicSvc -Force -ErrorAction SilentlyContinue
        
        # THE FIX: Set the 'Start' registry key to 4 (Disabled) to bypass SCM/ACL restrictions
        Set-ItemProperty -Path $WaaSMedicPath -Name "Start" -Value 4 -Type DWord -Force | Out-Null
        
        Write-Log "Windows Update Medic Service (WaaSMedicSvc) set to Disabled (Start=4)." -Level SUCCESS
    } catch {
        Write-Log ("WaaSMedicSvc registry write succeeded, but Stop-Service may have failed: {0}" -f $_) -Level WARNING
    }


    # 4. Disable related Scheduled Tasks (with PsExec SYSTEM fallback)
    Write-Log "Attempting to disable Windows Update scheduled tasks..." -Level INFO

    # --- PsExec + Enable_Windows_Updates_As_Admin.bat: locate on removable and copy to C:\danyel ---
    $PsExecPath        = $null
    $PsExecRelPath     = 'ImageResources\PsExec.exe'
    $BatRelPath        = 'ImageResources\Enable_Windows_Updates_As_Admin.bat'
    $TargetDir         = 'C:\danyel'
    $PsExecTargetPath  = Join-Path $TargetDir 'PsExec.exe'
    $BatTargetPath     = Join-Path $TargetDir 'Enable_Windows_Updates_As_Admin.bat'

    # Ensure target dir exists (for PsExec + BAT)
    if (-not (Test-Path $TargetDir)) {
        try {
            New-Item -Path $TargetDir -ItemType Directory -Force | Out-Null
        } catch {
            Write-Log ("Failed to create directory {0}: {1}" -f $TargetDir, $_.Exception.Message) -Level WARNING
        }
    }

    # --- Find PsExec on removable drives ---
    try {
        foreach ($drive in (Get-CimInstance Win32_LogicalDisk -Filter "DriveType=2" -ErrorAction SilentlyContinue)) {
            $candidate = Join-Path $drive.DeviceID $PsExecRelPath
            if (Test-Path $candidate) {
                $PsExecPath = $candidate
                break
            }
        }
    } catch {
        # Ignore discovery errors; we'll fall back to brute-force
    }

    # Fallback: brute-force D:..Z:
    if (-not $PsExecPath) {
        foreach ($letter in [char]68..90) {  # D..Z
            $candidate = "$letter`:\$PsExecRelPath"
            if (Test-Path $candidate) {
                $PsExecPath = $candidate
                break
            }
        }
    }

    # If PsExec found on removable, copy into C:\danyel\PsExec.exe
    if ($PsExecPath) {
        try {
            Copy-Item -Path $PsExecPath -Destination $PsExecTargetPath -Force
            Write-Log ("PsExec copied to {0}" -f $PsExecTargetPath) -Level SUCCESS
            $PsExecPath = $PsExecTargetPath
        } catch {
            Write-Log ("Failed to copy PsExec to {0}: {1}" -f $PsExecTargetPath, $_.Exception.Message) -Level WARNING
            # still fall back to using original removable path if copy failed
        }
    } else {
        # Not found on removable media – check if it's already present in C:\danyel
        if (Test-Path $PsExecTargetPath) {
            $PsExecPath = $PsExecTargetPath
            Write-Log ("PsExec not found on removable media; using existing {0}" -f $PsExecTargetPath) -Level INFO
        }
    }

    # --- Find & copy Enable_Windows_Updates_As_Admin.bat from removable ---
    $BatSourcePath = $null

    try {
        foreach ($drive in (Get-CimInstance Win32_LogicalDisk -Filter "DriveType=2" -ErrorAction SilentlyContinue)) {
            $candidate = Join-Path $drive.DeviceID $BatRelPath
            if (Test-Path $candidate) {
                $BatSourcePath = $candidate
                break
            }
        }
    } catch {
        # ignore
    }

    if (-not $BatSourcePath) {
        foreach ($letter in [char]68..90) {  # D..Z
            $candidate = "$letter`:\$BatRelPath"
            if (Test-Path $candidate) {
                $BatSourcePath = $candidate
                break
            }
        }
    }

    if ($BatSourcePath) {
        try {
            Copy-Item -Path $BatSourcePath -Destination $BatTargetPath -Force
            Write-Log ("Enable_Windows_Updates_As_Admin.bat copied to {0}" -f $BatTargetPath) -Level SUCCESS
        } catch {
            Write-Log ("Failed to copy Enable_Windows_Updates_As_Admin.bat to {0}: {1}" -f $BatTargetPath, $_.Exception.Message) -Level WARNING
        }
    } else {
        Write-Log "Enable_Windows_Updates_As_Admin.bat not found on removable media (ImageResources\...). Skipping copy." -Level WARNING
    }

    # --- PsExec availability status ---
    if ($PsExecPath) {
        Write-Log ("PsExec available at {0}. SYSTEM-level fallback enabled for protected tasks." -f $PsExecPath) -Level INFO
    } else {
        Write-Log "PsExec.exe not found on removable media or in C:\danyel. SYSTEM-level fallback will be skipped." -Level WARNING
    }

    # --- Disable tasks ---
    $tasksDisabled = 0

    foreach ($path in '\Microsoft\Windows\WindowsUpdate\', '\Microsoft\Windows\UpdateOrchestrator\') {
        try {
            $tasks = Get-ScheduledTask -TaskPath $path -ErrorAction SilentlyContinue
            
            foreach ($task in $tasks) {
                $fullTaskName = "$($task.TaskPath)$($task.TaskName)"  # e.g. \Microsoft\Windows\UpdateOrchestrator\Reboot

                try {
                    # First attempt: regular admin context
                    Disable-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction Stop | Out-Null
                    $tasksDisabled++
                }
                catch {
                    Write-Log ("Access denied (admin) for task: '{0}'." -f $fullTaskName) -Level WARNING

                    if ($PsExecPath) {
                        # Second attempt: run schtasks as NT AUTHORITY\SYSTEM via PsExec
                        & $PsExecPath -accepteula -s schtasks /change /tn "$fullTaskName" /disable *> $null
                        $exit = $LASTEXITCODE

                        if ($exit -eq 0) {
                            $tasksDisabled++
                            Write-Log ("Task '{0}' disabled via PsExec as SYSTEM." -f $fullTaskName) -Level SUCCESS
                        } else {
                            Write-Log ("PsExec failed to disable '{0}'. Exit Code: {1}" -f $fullTaskName, $exit) -Level WARNING
                        }
                    } else {
                        Write-Log ("Skipping PsExec fallback for '{0}' (PsExec.exe not available)." -f $fullTaskName) -Level WARNING
                    }
                }
            }
        } 
        catch { 
            Write-Log ("Failed to retrieve tasks from path '{0}': {1}" -f $path, $_.Exception.Message) -Level WARNING 
        } 
    }

    Write-Log ("Disabled {0} scheduled tasks (admin + SYSTEM via PsExec where needed)." -f $tasksDisabled) -Level SUCCESS
}


Disable-AutomaticUpdates

# =========================
# 5) Power Settings
# =========================
Write-Log "POWER SETTINGS CONFIGURATION" -Level SECTION
$powerSettings = @(
    @{Param="-monitor-timeout-ac"; Value=20},
    @{Param="-monitor-timeout-dc"; Value=20},
    @{Param="-standby-timeout-ac"; Value=0},
    @{Param="-standby-timeout-dc"; Value=0},
    @{Param="-hibernate-timeout-ac"; Value=0},
    @{Param="-hibernate-timeout-dc"; Value=0}
)

foreach ($setting in $powerSettings) {
    try {
        & powercfg /x $setting.Param $setting.Value | Out-Null
        Write-Log "Set $($setting.Param)" -Level SUCCESS
    } catch {
        Write-Log "Failed: $_" -Level ERROR
    }
}

# =========================
# 6) Bloatware Removal
# =========================
Write-Log "BLOATWARE REMOVAL" -Level SECTION

function Remove-Bloatware {
    <#
    .SYNOPSIS
        Removes Windows bloatware by name - handles AppX packages, provisioned packages, and Win32 programs.
    .PARAMETER Name
        The name (or partial name) of the software to remove. Supports wildcards.
    .EXAMPLE
        Remove-Bloatware -Name "Xbox"
        Remove-Bloatware -Name "OneDrive"
        Remove-Bloatware -Name "*Candy*"
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Name
    )

    $removed = $false
    $searchPattern = "*$Name*"

    # ===== 1. Remove AppX Packages (Modern/Store Apps) =====
    try {
        $appxPackages = Get-AppxPackage -AllUsers -Name $searchPattern -ErrorAction SilentlyContinue
        foreach ($pkg in $appxPackages) {
            try {
                Write-Log "  Removing AppX: $($pkg.Name)" -Level INFO
                Remove-AppxPackage -Package $pkg.PackageFullName -AllUsers -ErrorAction Stop
                $removed = $true
                Write-Log "    Removed AppX package" -Level SUCCESS
            } catch {
                # Try without -AllUsers for current user only
                try {
                    Remove-AppxPackage -Package $pkg.PackageFullName -ErrorAction Stop
                    $removed = $true
                    Write-Log "    Removed AppX package (current user)" -Level SUCCESS
                } catch {
                    Write-Log "    Failed to remove AppX: $($_.Exception.Message)" -Level WARNING
                }
            }
        }
    } catch {
        # Silently continue if Get-AppxPackage fails
    }

    # ===== 2. Remove Provisioned AppX Packages (Prevents reinstall for new users) =====
    try {
        $provisionedPackages = Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -like $searchPattern -or $_.PackageName -like $searchPattern }
        foreach ($pkg in $provisionedPackages) {
            try {
                Write-Log "  Removing Provisioned: $($pkg.DisplayName)" -Level INFO
                Remove-AppxProvisionedPackage -Online -PackageName $pkg.PackageName -ErrorAction Stop | Out-Null
                $removed = $true
                Write-Log "    Removed provisioned package" -Level SUCCESS
            } catch {
                Write-Log "    Failed to remove provisioned: $($_.Exception.Message)" -Level WARNING
            }
        }
    } catch {
        # Silently continue if provisioned package removal fails
    }

    # ===== 3. Remove Win32 Programs via Registry Uninstall =====
    $uninstallPaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )

    foreach ($path in $uninstallPaths) {
        try {
            $programs = Get-ItemProperty $path -ErrorAction SilentlyContinue |
                Where-Object { $_.DisplayName -like $searchPattern }

            foreach ($program in $programs) {
                $uninstallString = $program.UninstallString
                $quietUninstall = $program.QuietUninstallString

                if ($quietUninstall) {
                    $uninstallCmd = $quietUninstall
                } elseif ($uninstallString) {
                    $uninstallCmd = $uninstallString
                } else {
                    continue
                }

                Write-Log "  Removing Win32: $($program.DisplayName)" -Level INFO

                try {
                    # Handle different uninstall string formats
                    if ($uninstallCmd -match '^msiexec') {
                        # MSI uninstall - add quiet flags
                        $uninstallCmd = $uninstallCmd -replace '/I', '/X'
                        if ($uninstallCmd -notmatch '/q') {
                            $uninstallCmd += ' /qn /norestart'
                        }
                        Start-Process -FilePath 'cmd.exe' -ArgumentList "/c $uninstallCmd" -Wait -NoNewWindow -ErrorAction Stop
                    }
                    elseif ($uninstallCmd -match '\.exe') {
                        # EXE uninstall - try to run with silent flags
                        # Extract exe path (handle quoted paths)
                        if ($uninstallCmd -match '^"([^"]+)"(.*)$') {
                            $exePath = $Matches[1]
                            $args = $Matches[2].Trim()
                        } elseif ($uninstallCmd -match '^(\S+\.exe)(.*)$') {
                            $exePath = $Matches[1]
                            $args = $Matches[2].Trim()
                        } else {
                            $exePath = $uninstallCmd
                            $args = ''
                        }

                        # Add common silent flags if not present
                        if ($args -notmatch '/S|/silent|/quiet|-silent|-quiet|/qn') {
                            $args += ' /S /silent /quiet'
                        }

                        if (Test-Path $exePath) {
                            Start-Process -FilePath $exePath -ArgumentList $args -Wait -NoNewWindow -ErrorAction Stop
                        } else {
                            Start-Process -FilePath 'cmd.exe' -ArgumentList "/c `"$uninstallCmd`"" -Wait -NoNewWindow -ErrorAction Stop
                        }
                    }
                    else {
                        # Generic command
                        Start-Process -FilePath 'cmd.exe' -ArgumentList "/c $uninstallCmd" -Wait -NoNewWindow -ErrorAction Stop
                    }

                    $removed = $true
                    Write-Log "    Removed Win32 program" -Level SUCCESS
                } catch {
                    Write-Log "    Failed to remove Win32: $($_.Exception.Message)" -Level WARNING
                }
            }
        } catch {
            # Continue to next path
        }
    }

    # ===== 4. Special Case: OneDrive =====
    if ($Name -like '*OneDrive*' -or $Name -like '*one drive*') {
        Write-Log "  Attempting OneDrive removal (special handler)" -Level INFO

        # Stop OneDrive processes
        Get-Process -Name 'OneDrive' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        Get-Process -Name 'OneDriveSetup' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2

        # Find and run OneDrive uninstaller
        $oneDrivePaths = @(
            "$env:SystemRoot\System32\OneDriveSetup.exe",
            "$env:SystemRoot\SysWOW64\OneDriveSetup.exe",
            "$env:LOCALAPPDATA\Microsoft\OneDrive\OneDriveSetup.exe",
            "$env:ProgramFiles\Microsoft OneDrive\OneDriveSetup.exe",
            "${env:ProgramFiles(x86)}\Microsoft OneDrive\OneDriveSetup.exe"
        )

        foreach ($odPath in $oneDrivePaths) {
            if (Test-Path $odPath) {
                try {
                    Start-Process -FilePath $odPath -ArgumentList '/uninstall' -Wait -NoNewWindow -ErrorAction Stop
                    $removed = $true
                    Write-Log "    OneDrive uninstalled via $odPath" -Level SUCCESS
                    break
                } catch {
                    Write-Log "    OneDrive uninstall failed from $odPath" -Level WARNING
                }
            }
        }

        # Clean up OneDrive folders and registry
        $oneDriveFolders = @(
            "$env:LOCALAPPDATA\Microsoft\OneDrive",
            "$env:ProgramData\Microsoft OneDrive",
            "$env:USERPROFILE\OneDrive"
        )
        foreach ($folder in $oneDriveFolders) {
            if (Test-Path $folder) {
                try {
                    Remove-Item -Path $folder -Recurse -Force -ErrorAction SilentlyContinue
                } catch { }
            }
        }

        # Remove OneDrive from Explorer sidebar
        $regPaths = @(
            'HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}',
            'HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}'
        )
        foreach ($regPath in $regPaths) {
            try {
                if (Test-Path $regPath) {
                    Set-ItemProperty -Path $regPath -Name 'System.IsPinnedToNameSpaceTree' -Value 0 -ErrorAction SilentlyContinue
                }
            } catch { }
        }
    }

    return $removed
}

# List of bloatware to remove
$BloatwareList = @(
    # Microsoft Bloatware
    'Microsoft.3DBuilder',
    'Microsoft.549981C3F5F10',      # Cortana
    'Microsoft.Advertising.Xaml',
    'Microsoft.BingFinance',
    'Microsoft.BingNews',
    'Microsoft.BingSports',
    'Microsoft.BingTranslator',
    'Microsoft.BingWeather',
    'Microsoft.GetHelp',
    'Microsoft.Getstarted',
    'Microsoft.Messaging',
    'Microsoft.Microsoft3DViewer',
    'Microsoft.MicrosoftOfficeHub',
    'Microsoft.MicrosoftSolitaireCollection',
    'Microsoft.MixedReality.Portal',
    'Microsoft.NetworkSpeedTest',
    'Microsoft.News',
    'Microsoft.Office.Lens',
    'Microsoft.Office.OneNote',
    'Microsoft.Office.Sway',
    'Microsoft.OneConnect',
    'Microsoft.People',
    'Microsoft.Print3D',
    'Microsoft.SkypeApp',
    'Microsoft.StorePurchaseApp',
    'Microsoft.Wallet',
    'Microsoft.Whiteboard',
    'Microsoft.WindowsAlarms',
    'Microsoft.WindowsCommunicationsApps',  # Mail & Calendar
    'Microsoft.WindowsFeedbackHub',
    'Microsoft.WindowsMaps',
    'Microsoft.WindowsSoundRecorder',
    'Microsoft.YourPhone',
    'Microsoft.ZuneMusic',
    'Microsoft.ZuneVideo',
    'MicrosoftTeams',
    'Microsoft.Todos',
    'Microsoft.PowerAutomateDesktop',
    'Microsoft.GamingApp',
    'Microsoft.MicrosoftStickyNotes',
    'Clipchamp.Clipchamp',

    # Xbox Apps
    'Microsoft.Xbox.TCUI',
    'Microsoft.XboxApp',
    'Microsoft.XboxGameOverlay',
    'Microsoft.XboxGamingOverlay',
    'Microsoft.XboxIdentityProvider',
    'Microsoft.XboxSpeechToTextOverlay',

    # Third-party Bloatware
    'king.com.CandyCrushSaga',
    'king.com.CandyCrushSodaSaga',
    'king.com.BubbleWitch3Saga',
    'king.com.CandyCrushFriends',
    'FACEBOOK.FACEBOOK',
    'Flipboard.Flipboard',
    'Twitter.Twitter',
    'SpotifyAB.SpotifyMusic',
    'Disney.37853FC22B2CE',         # Disney+
    'BytedancePte.Ltd.TikTok',
    'AmazonVideo.PrimeVideo',
    '22364Disney.ESPNBetaPWA',

    # OneDrive (handled specially)
    'OneDrive'
)

$removedCount = 0
$failedCount = 0

foreach ($bloat in $BloatwareList) {
    Write-Log "Processing: $bloat" -Level INFO
    $result = Remove-Bloatware -Name $bloat
    if ($result) {
        $removedCount++
    }
}

Write-Log "Bloatware removal complete: $removedCount items processed" -Level SUCCESS

# =========================
# Helper: Copy with progress
# =========================
function Copy-FolderWithProgress {
    param($Source, $Destination, $InstallType)
    
    Write-Log "Starting copy for $InstallType..."
    $Files = Get-ChildItem -Path $Source -File -Recurse
    $TotalFiles = $Files.Count
    $i = 0
    $failed = 0
    
    foreach ($File in $Files) {
        $i++
        $Progress = [int](($i / $TotalFiles) * 100)
        $TargetFile = Join-Path $Destination $File.FullName.Substring($Source.Length)
        $TargetDir = Split-Path $TargetFile -Parent
        
        if (-not (Test-Path $TargetDir)) { New-Item -Path $TargetDir -ItemType Directory -Force | Out-Null }
        
        try {
            Copy-Item $File.FullName $TargetFile -Force
        } catch {
            Write-Log "Failed to copy $($File.Name)" -Level ERROR
            $failed++
        }
        Write-Progress -Activity "Copying $InstallType" -Status "$i / $TotalFiles" -PercentComplete $Progress
    }

    Write-Progress -Activity "Copying $InstallType" -Completed

    if ($failed -eq 0) {
        Write-Log "Copied $TotalFiles files." -Level SUCCESS
    } else {
        Write-Log "$failed files failed." -Level WARNING
    }
}

# =========================
# 6) Driver installation - OPTIMIZED
# =========================
Write-Log "DRIVER INSTALLATION" -Level SECTION

function Find-DriverSourceRoot {
    foreach ($d in Get-CimInstance Win32_LogicalDisk -Filter "DriveType=2") {
        $path = Join-Path $d.DeviceID "ImageDrivers\Computer"
        if (Test-Path $path) { 
            Write-Log "Driver root: $($d.DeviceID)"
            return $d.DeviceID 
        }
    }
    return $null
}

function Install-DriversForPresentDevices {
    param(
        [string]$DriverFolderPath,
        [string]$PnPUtilExe
    )

    # Exit codes reference:
    # 0    = Success
    # 259  = No more data / already installed
    # 3010 = Success, reboot required
    # -536870353 (0xE000020F) = Cannot install inbox/protected driver
    $stats = @{
        Installed     = 0
        Updated       = 0
        Failed        = 0
        Skipped       = 0
        RebootNeeded  = $false
    }

    # Windows inbox drivers that cannot be replaced via pnputil
    # These are protected system drivers and will fail with exit code -536870353
    $InboxDriversToSkip = @(
        'bth.inf',           # Microsoft Bluetooth Enumerator
        'bthleenum.inf',     # Microsoft Bluetooth LE Enumerator
        'bthpan.inf',        # Bluetooth Device (Personal Area Network)
        'tdibth.inf',        # Bluetooth Device (RFCOMM Protocol TDI)
        'monitor.inf',       # Generic Monitor
        'tpm.inf',           # Trusted Platform Module
        'disk.inf',          # Disk Drive
        'volume.inf',        # Volume
        'keyboard.inf',      # Standard keyboards
        'msmouse.inf',       # Microsoft Mouse
        'usbhub.inf',        # Generic USB Hub
        'usbport.inf',       # USB Host Controller
        'usbstor.inf',       # USB Mass Storage
        'cdrom.inf',         # CD-ROM Drive
        'machine.inf',       # Computer System
        'cpu.inf',           # Processor
        'acpi.inf',          # ACPI components
        'pci.inf',           # PCI Bus
        'hdaudbus.inf',      # Microsoft UAA Bus Driver for High Definition Audio
        'wdma_usb.inf',      # USB Audio Device
        'ks.inf',            # Kernel Streaming
        'kscaptur.inf',      # WDM Streaming Capture Devices
        'msports.inf',       # Communications Port
        'mssmbios.inf',      # Microsoft System Management BIOS Driver
        'swenum.inf',        # Software Device Enumerator
        'umbus.inf'          # UMBus Enumerator
    )
    
    # Get all relevant devices in one query
    $devices = Get-PnpDevice -ErrorAction SilentlyContinue | Where-Object {
        $_.InstanceId -notmatch '^(ROOT\\|HTREE\\|SW\\)' -and
        $_.Class -notin @('System', 'Computer', 'Volume', 'DiskDrive', 'CDROM', 'Processor')
    }

    # Build hardware ID lookup for all devices at once
    # Store both full hardware IDs and shortened versions for flexible matching
    $deviceLookup = @{}
    $deviceHwIdList = @()  # Store all device hardware IDs for prefix matching

    foreach ($device in $devices) {
        try {
            $hwIds = (Get-PnpDeviceProperty -InstanceId $device.InstanceId -KeyName 'DEVPKEY_Device_HardwareIds' -ErrorAction SilentlyContinue).Data
            if ($hwIds) {
                foreach ($hwId in $hwIds) {
                    $key = $hwId.ToUpper()
                    if (-not $deviceLookup.ContainsKey($key)) {
                        $deviceLookup[$key] = @()
                    }
                    $deviceLookup[$key] += $device
                    $deviceHwIdList += @{ HwId = $key; Device = $device }

                    # Also store shortened PCI/USB hardware IDs (VEN+DEV / VID+PID only)
                    # This enables matching when INF has generic ID and device has specific one
                    if ($key -match '^(PCI\\VEN_[0-9A-F]{4}&DEV_[0-9A-F]{4})') {
                        $shortKey = $Matches[1]
                        if (-not $deviceLookup.ContainsKey($shortKey)) {
                            $deviceLookup[$shortKey] = @()
                        }
                        if ($deviceLookup[$shortKey] -notcontains $device) {
                            $deviceLookup[$shortKey] += $device
                        }
                    }
                    elseif ($key -match '^(USB\\VID_[0-9A-F]{4}&PID_[0-9A-F]{4})') {
                        $shortKey = $Matches[1]
                        if (-not $deviceLookup.ContainsKey($shortKey)) {
                            $deviceLookup[$shortKey] = @()
                        }
                        if ($deviceLookup[$shortKey] -notcontains $device) {
                            $deviceLookup[$shortKey] += $device
                        }
                    }
                }
            }
        } catch {
            # Silently skip devices we can't query
        }
    }
    
    Write-Log "Found $($devices.Count) devices, scanning driver folder..."
    
    # Process INF files - only install if matching device exists
    $infFiles = Get-ChildItem -Path $DriverFolderPath -Filter "*.inf" -Recurse -ErrorAction SilentlyContinue
    $processedInfNames = @{}  # Track by filename (not full path) to avoid duplicates

    foreach ($inf in $infFiles) {
        $infNameLower = $inf.Name.ToLower()

        # Skip Windows inbox drivers that cannot be installed via pnputil
        if ($InboxDriversToSkip -contains $infNameLower) {
            Write-Log "Skipping inbox driver: $($inf.Name)" -Level INFO
            $stats.Skipped++
            continue
        }

        # Skip if we've already processed an INF with this filename
        if ($processedInfNames.ContainsKey($infNameLower)) {
            continue
        }

        $content = Get-Content -Path $inf.FullName -Raw -ErrorAction SilentlyContinue
        if (-not $content) { continue }

        # Expanded regex to cover more hardware ID types:
        # PCI, USB, ACPI, HDAUDIO, HID, DISPLAY, MONITOR, BTH, BTHENUM, SWC
        $hwIdPattern = '(PCI\\VEN_[0-9A-Fa-f]{4}&DEV_[0-9A-Fa-f]{4}[^\s,"]*|USB\\VID_[0-9A-Fa-f]{4}&PID_[0-9A-Fa-f]{4}[^\s,"]*|ACPI\\[A-Za-z0-9_]+|HDAUDIO\\[^\s,"]+|HID\\[^\s,"]+|DISPLAY\\[^\s,"]+|MONITOR\\[^\s,"]+|BTH\\[^\s,"]+|BTHENUM\\[^\s,"]+|SWC\\[^\s,"]+)'
        $hwIdMatches = [regex]::Matches($content, $hwIdPattern, 'IgnoreCase')

        $shouldInstall = $false
        $matchedDevice = $null

        foreach ($m in $hwIdMatches) {
            $hwIdUpper = $m.Value.ToUpper()

            # First try exact match
            if ($deviceLookup.ContainsKey($hwIdUpper)) {
                $shouldInstall = $true
                $matchedDevice = $deviceLookup[$hwIdUpper][0]
                break
            }

            # Then try prefix matching - INF hardware ID might be a prefix of device hardware ID
            # e.g., INF has "PCI\VEN_8086&DEV_A0A3" and device has "PCI\VEN_8086&DEV_A0A3&SUBSYS_..."
            foreach ($entry in $deviceHwIdList) {
                if ($entry.HwId.StartsWith($hwIdUpper)) {
                    $shouldInstall = $true
                    $matchedDevice = $entry.Device
                    break
                }
            }
            if ($shouldInstall) { break }
        }

        if ($shouldInstall) {
            # Mark this INF filename as processed to avoid duplicate installs
            $processedInfNames[$infNameLower] = $true

            $deviceName = if ($matchedDevice.FriendlyName) { $matchedDevice.FriendlyName } else { $matchedDevice.InstanceId }
            $isProblem = ($matchedDevice.Status -ne 'OK') -or ($matchedDevice.ConfigManagerErrorCode -ne 0)

            Write-Log "Installing: $($inf.Name) for $deviceName"

            $null = & $PnPUtilExe /add-driver $inf.FullName /install 2>&1

            switch ($LASTEXITCODE) {
                0 {
                    if ($isProblem) {
                        $stats.Installed++
                        Write-Log "  Installed successfully" -Level SUCCESS
                    } else {
                        $stats.Updated++
                        Write-Log "  Updated successfully" -Level SUCCESS
                    }
                }
                259 {
                    # Already installed / no update needed
                    $stats.Skipped++
                    Write-Log "  Already up to date" -Level INFO
                }
                3010 {
                    $stats.RebootNeeded = $true
                    if ($isProblem) {
                        $stats.Installed++
                        Write-Log "  Installed successfully (reboot required)" -Level SUCCESS
                    } else {
                        $stats.Updated++
                        Write-Log "  Updated successfully (reboot required)" -Level SUCCESS
                    }
                }
                default {
                    $stats.Failed++
                    Write-Log "  Failed (exit: $LASTEXITCODE)" -Level WARNING
                }
            }
        }
    }
    
    return $stats
}

$DriverSourceRoot = Find-DriverSourceRoot

if ($DriverSourceRoot) {
    Write-Log "Driver source: $DriverSourceRoot" -Level SUCCESS
    
    $ComputerDriversPath = Join-Path $DriverSourceRoot 'ImageDrivers\Computer'
    $AddonsDriversPath   = Join-Path $DriverSourceRoot 'ImageDrivers\Addons'

    # --- Computer Drivers (only for present devices) ---
    if (Test-Path $ComputerDriversPath) {
        Write-Log "Processing computer drivers: $ComputerDriversPath"
        
        $result = Install-DriversForPresentDevices -DriverFolderPath $ComputerDriversPath -PnPUtilExe $PnPUtilPath
        
        $summaryMsg = "SUMMARY: Installed=$($result.Installed) Updated=$($result.Updated) Skipped=$($result.Skipped) Failed=$($result.Failed)"
        if ($result.RebootNeeded) {
            $summaryMsg += " [REBOOT REQUIRED]"
        }
        Write-Log $summaryMsg -Level INFO
    } else {
        Write-Log "Computer drivers path not found" -Level WARNING
    }

    # --- Addon Drivers (bulk install ALL - no device matching) ---
    if (Test-Path $AddonsDriversPath) {
        Write-Log "Installing ALL addon drivers: $AddonsDriversPath"
        
        $null = & $PnPUtilPath /add-driver (Join-Path $AddonsDriversPath "*.inf") /subdirs /install 2>&1
        
        switch ($LASTEXITCODE) {
            0       { Write-Log "Addon drivers staged successfully" -Level SUCCESS }
            259     { Write-Log "Addon drivers already installed" -Level INFO }
            3010    { Write-Log "Addon drivers staged successfully (reboot required)" -Level SUCCESS }
            default { Write-Log "Addon drivers exit code: $LASTEXITCODE" -Level WARNING }
        }
    }
} else {
    Write-Log "Driver folder not found on removable media" -Level WARNING
}

# =========================
# 7) Install type popup
# =========================
Write-Log "INSTALLATION TYPE SELECTION" -Level SECTION

function Get-InstallTypeFromPopup {
    # FIX #2: Load assemblies FIRST, before creating any UI objects
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    
    $Form = New-Object System.Windows.Forms.Form
    $Form.Text = "Required Setup Selection"
    $Form.Size = New-Object System.Drawing.Size(350, 150)
    $Form.StartPosition = 'CenterScreen'
    $Form.FormBorderStyle = 'FixedDialog'
    $Form.MaximizeBox = $false
    $Form.MinimizeBox = $false
    
    $Label = New-Object System.Windows.Forms.Label
    $Label.Location = New-Object System.Drawing.Point(10, 10)
    $Label.Size = New-Object System.Drawing.Size(320, 20)
    $Label.Text = "Please select the installation type:"
    $Form.Controls.Add($Label)
    
    $script:InstallTypeResult = $null 
    $ButtonConfig = $Global:ButtonMap
    
    for ($i=0; $i -lt $ButtonConfig.Count; $i++) {
        $Config = $ButtonConfig[$i]
        
        $Button = New-Object System.Windows.Forms.Button
        $Button.Text = $Config.Name
        # FIX #2: Create Point objects HERE after assemblies are loaded, using X/Y integers
        $Button.Location = New-Object System.Drawing.Point($Config.X, $Config.Y)
        $Button.Size = New-Object System.Drawing.Size(100, 30)
        $Button.Tag = $i
        
        $Button.Add_Click({
            $Index = [int]$this.Tag
            $TagValue = $Global:ButtonMap[$Index].Tag
            $script:InstallTypeResult = $TagValue
            $Form.Close()
        })
        $Form.Controls.Add($Button)
    }
    
    $Form.Topmost = $true 
    [void]$Form.ShowDialog()
    
    return $script:InstallTypeResult
}

function Find-ResourceFolder {
    $drives = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=2"
    foreach ($d in $drives) {
        $path = Join-Path $d.DeviceID 'ImageResources'
        if (Test-Path $path) { return $path }
    }
    foreach ($L in [char[]](68..90)) {
        $path = "$L`:\ImageResources"
        if (Test-Path $path) { return $path }
    }
    return $null
}

$ResourcesPath = Find-ResourceFolder

if ($ResourcesPath) {
    Write-Log "Resources at: $ResourcesPath" -Level SUCCESS
    
    $InstallType = Get-InstallTypeFromPopup
    
    if ($InstallType) {
        Write-Log "User selected: $InstallType"
        
        $SourceDir = Join-Path $ResourcesPath $InstallType
        $TargetDir = Join-Path "C:\danyel" $InstallType
        
        Write-Log "Source = $SourceDir"
        Write-Log "Target = $TargetDir"
        
        if (Test-Path $SourceDir) {
            Copy-FolderWithProgress $SourceDir $TargetDir $InstallType
            
            try {
                $Shell = New-Object -ComObject WScript.Shell
                $LnkPath = Join-Path $env:PUBLIC "Desktop\$InstallType Resources.lnk"
                $Shortcut = $Shell.CreateShortcut($LnkPath)
                $Shortcut.TargetPath = $TargetDir
                $Shortcut.Save()
                Write-Log "Shortcut created." -Level SUCCESS
            } catch {
                Write-Log "Shortcut failed." -Level ERROR
            }
        } else {
            Write-Log "Source missing!" -Level ERROR
        }
    } else {
        Write-Log "Popup closed with no selection." -Level WARNING
    }
} else {
    Write-Log "'ImageResources' not found." -Level WARNING
}


# =========================
# 8) Wallpaper Setup
# =========================
Write-Log "WALLPAPER CONFIGURATION" -Level SECTION

Add-Type @"
using System;
using System.Runtime.InteropServices;

public class Win32 {
    [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    public static extern bool SystemParametersInfo(
        UInt32 uiAction,
        UInt32 uiParam,
        string pvParam,
        UInt32 fWinIni
    );

    public const UInt32 SPI_SETDESKWALLPAPER = 0x14;
    public const UInt32 SPIF_UPDATEINIFILE   = 0x1;
    public const UInt32 SPIF_SENDCHANGE      = 0x2;
}
"@

function Copy-GlobalWallpaperImage {
    param(
        [string]$ImageFilename,
        [string]$ImageSubPath,
        [string]$ImageDestPath
    )

    Write-Host "Searching removable drives for $ImageFilename..."
    $SourcePath = $null

    # First: real removable drives (DriveType = 2)
    foreach ($Drive in (Get-CimInstance Win32_LogicalDisk -Filter "DriveType=2")) {
        $TestPath = Join-Path $Drive.DeviceID $ImageSubPath
        if (Test-Path $TestPath) {
            $SourcePath = $TestPath
            break
        }
    }

    # Fallback: brute-force D: to Z:
    if (-not $SourcePath) {
        foreach ($L in [char](68..90)) {  # D..Z
            $TestPath = "$L`:\$ImageSubPath"
            if (Test-Path $TestPath) {
                $SourcePath = $TestPath
                break
            }
        }
    }

    if (-not $SourcePath) {
        Write-Error "Wallpaper not found (looked for $ImageSubPath)."
        return $null
    }

    # Copy
    try {
        $DestDir = Split-Path $ImageDestPath
        if (-not (Test-Path $DestDir)) {
            New-Item $DestDir -ItemType Directory | Out-Null
        }
        Copy-Item $SourcePath $ImageDestPath -Force
        Write-Host "Wallpaper copied to $ImageDestPath"
        return $ImageDestPath
    } catch {
        Write-Error "Copy failed: $($_.Exception.Message)"
        return $null
    }
}

function Set-GlobalWallpaper {

    $ImageDestPath = 'C:\danyel\DB_Desktop.jpg'
    $ImageFilename = 'DB_Desktop.jpg'
    $ImageSubPath  = 'ImageResources\' + $ImageFilename
    
    $Style_WallpaperStyle = "6" # 6 = Fit ,  10 = Fill
    $Style_TileWallpaper  = "0"
    $DesktopRegistryPath  = "Control Panel\Desktop"
    
    function Set-UserWallpaperRegistry {
        param(
            [string]$RegistryRootPath,
            [string]$ImagePath,
            [string]$Style,
            [string]$Tile
        )

        $props = @{
            Wallpaper      = $ImagePath
            WallpaperStyle = $Style
            TileWallpaper  = $Tile
        }

        foreach ($name in $props.Keys) {
            try {
                # Create or update as REG_SZ
                New-ItemProperty -Path $RegistryRootPath `
                                 -Name $name `
                                 -Value $props[$name] `
                                 -PropertyType String `
                                 -Force | Out-Null
            } catch {
                Write-Warning "Registry error setting $name at ${RegistryRootPath}: $($_.Exception.Message)"
            }
        }
    }

    # --- search + copy via helper ---
    $FinalImagePath = Copy-GlobalWallpaperImage -ImageFilename $ImageFilename `
                                                -ImageSubPath  $ImageSubPath `
                                                -ImageDestPath $ImageDestPath
    if (-not $FinalImagePath) {
        # helper already logged the error
        return
    }

    # Set HKU\.DEFAULT
    $DefaultPath = "Registry::HKEY_USERS\.DEFAULT\$DesktopRegistryPath"
    Set-UserWallpaperRegistry $DefaultPath $FinalImagePath $Style_WallpaperStyle $Style_TileWallpaper

    # Set all existing profiles
    $PatternSID = 'S-1-5-21-\d+-\d+-\d+-\d+$'
    $Profiles = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*' |
                Where-Object { $_.PSChildName -match $PatternSID }

    foreach ($Profile in $Profiles) {
        $SID = $Profile.PSChildName
        $Path = "Registry::HKEY_USERS\$SID\$DesktopRegistryPath"

        if (Test-Path $Path) {
            Set-UserWallpaperRegistry $Path $FinalImagePath $Style_WallpaperStyle $Style_TileWallpaper
        }
    }

    # === DESKTOP REFRESH ===
    Write-Host "Updating Desktop..."
    try {
        $flags = [Win32]::SPIF_UPDATEINIFILE -bor [Win32]::SPIF_SENDCHANGE
        $ok = [Win32]::SystemParametersInfo([Win32]::SPI_SETDESKWALLPAPER, 0, $FinalImagePath, $flags)
        if ($ok) {
            Write-Host "Desktop updated."
        } else {
            $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-Warning "SystemParametersInfo failed. Error: $err"
        }
    } catch {
        Write-Warning $_
    }
}

Set-GlobalWallpaper


# ================================================================================
# REMOTE SUPPORT SHORTCUT (ALWAYS RUNS AS ADMIN VIA LAUNCHER SCRIPT)
# ================================================================================
Write-Log "Creating 'DanyelBiotech RemoteSupport' launcher and shortcut on Public Desktop..." -Level SECTION

try {
    $targetExe    = 'C:\danyel\danyelbiotechremotesupport.exe'
    $launcherPath = 'C:\danyel\Run_DanyelBiotechRemoteSupport_As_Admin.ps1'

    # Ensure C:\danyel exists
    if (-not (Test-Path 'C:\danyel')) {
        New-Item -Path 'C:\danyel' -ItemType Directory -Force | Out-Null
        Write-Log "Created C:\danyel folder." -Level INFO
    }

    if (-not (Test-Path $targetExe)) {
        Write-Log ("Remote support executable not found at {0}. The launcher/shortcut will still be created, but will fail until the file exists." -f $targetExe) -Level WARNING
    }

    # 1) Create / overwrite the launcher script that runs the EXE as admin
    $launcherContent = @"
# Auto-generated by on-first-login-v2
param()
`$exe = '$targetExe'
if (Test-Path `$exe) {
    Start-Process -FilePath `$exe -Verb RunAs
} else {
    Write-Host "Executable not found: `$exe"
}
"@

    $launcherContent | Set-Content -Path $launcherPath -Encoding UTF8
    Write-Log ("Created/updated launcher script: {0}" -f $launcherPath) -Level SUCCESS

    # 2) Create the Public Desktop shortcut pointing to the launcher via PowerShell
    $publicDesktop = [Environment]::GetFolderPath('CommonDesktopDirectory')
    if (-not $publicDesktop) {
        $publicDesktop = 'C:\Users\Public\Desktop'
    }

    if (-not (Test-Path $publicDesktop)) {
        New-Item -Path $publicDesktop -ItemType Directory -Force | Out-Null
        Write-Log ("Created Public Desktop folder at {0}" -f $publicDesktop) -Level INFO
    }

    $shortcutPath = Join-Path $publicDesktop 'Remote Support.lnk'

    $shell    = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut($shortcutPath)

    # Target = powershell that runs the launcher script
    $shortcut.TargetPath       = 'powershell.exe'
    $shortcut.Arguments        = "-NoProfile -ExecutionPolicy Bypass -File `"$launcherPath`""
    $shortcut.WorkingDirectory = 'C:\danyel'
    $shortcut.WindowStyle      = 1
    $shortcut.IconLocation     = "$targetExe,0"
    $shortcut.Description      = 'DanyelBiotech Remote Support (runs as administrator)'
    $shortcut.Save()

    Write-Log ("Shortcut created at {0}" -f $shortcutPath) -Level SUCCESS
}
catch {
    Write-Log ("Failed to create RemoteSupport launcher/shortcut: {0}" -f $_.Exception.Message) -Level ERROR
}


# =========================
# FINISH
# =========================
Write-Log "SCRIPT COMPLETE" -Level SECTION
Write-Log "System will restart in 10 seconds..." -Level WARNING

Stop-Transcript
#Start-Sleep 10
#Restart-Computer -Force