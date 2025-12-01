# Install-SQLServer2022.ps1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Installs SQL Server 2022 Express with configuration file and applies cumulative update.
.DESCRIPTION
    This script:
    1. Locates SQL Server 2022 installation media (DVD/USB)
    2. Installs SQL Server 2022 Express using ConfigurationFileX64.ini
    3. Applies the cumulative update (KB5050771)
.NOTES
    Expected files on media:
    - SQLEXPR_x64_ENU.exe (SQL Server Express installer)
    - ConfigurationFileX64.ini (Configuration file)
    - SQLServer2022-KB5050771-x64.exe (Cumulative update)
#>

# =========================
# LOGGING CONFIGURATION
# =========================
$LogTimestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$LogFile = "C:\SQLServer2022_Install_$LogTimestamp.txt"

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

Write-Log "SQL SERVER 2022 INSTALLATION" -Level SECTION

# =========================
# CONFIGURATION
# =========================
$SQLServerFolder = "SQL Server 2022"
$InstallerName = "SQLEXPR_x64_ENU.exe"
$ConfigFileName = "ConfigurationFileX64.ini"
$UpdateName = "SQLServer2022-KB5050771-x64.exe"

# Primary installation path (copied by on-first-login-v2.ps1)
$PrimaryInstallPath = "C:\danyel\Cytiva\SQL\SQL Server 2022"

# =========================
# FIND INSTALLATION MEDIA
# =========================
Write-Log "Searching for SQL Server 2022 installation media..." -Level INFO

function Find-SQLServerMedia {
    param(
        [string]$FolderName,
        [string]$InstallerName,
        [string]$PrimaryPath
    )

    # First check the primary local path (C:\danyel\Cytiva\SQL\SQL Server 2022)
    if ($PrimaryPath -and (Test-Path $PrimaryPath)) {
        $installerPath = Join-Path $PrimaryPath $InstallerName
        if (Test-Path $installerPath) {
            return $PrimaryPath
        }
    }

    # Search on CD/DVD drives (DriveType = 5)
    foreach ($drive in (Get-CimInstance Win32_LogicalDisk -Filter "DriveType=5" -ErrorAction SilentlyContinue)) {
        $testPath = Join-Path $drive.DeviceID $FolderName
        $installerPath = Join-Path $testPath $InstallerName
        if (Test-Path $installerPath) {
            return $testPath
        }
        # Also check root of drive
        $installerPath = Join-Path $drive.DeviceID $InstallerName
        if (Test-Path $installerPath) {
            return $drive.DeviceID
        }
    }

    # Search on removable drives (DriveType = 2)
    foreach ($drive in (Get-CimInstance Win32_LogicalDisk -Filter "DriveType=2" -ErrorAction SilentlyContinue)) {
        $testPath = Join-Path $drive.DeviceID $FolderName
        $installerPath = Join-Path $testPath $InstallerName
        if (Test-Path $installerPath) {
            return $testPath
        }
        # Also check root of drive
        $installerPath = Join-Path $drive.DeviceID $InstallerName
        if (Test-Path $installerPath) {
            return $drive.DeviceID
        }
    }

    # Brute force search D: to Z:
    foreach ($letter in [char[]](68..90)) {
        $testPath = "$letter`:\$FolderName"
        $installerPath = Join-Path $testPath $InstallerName
        if (Test-Path $installerPath) {
            return $testPath
        }
        # Also check root of drive
        $installerPath = "$letter`:\$InstallerName"
        if (Test-Path $installerPath) {
            return "$letter`:\"
        }
    }

    return $null
}

$MediaPath = Find-SQLServerMedia -FolderName $SQLServerFolder -InstallerName $InstallerName -PrimaryPath $PrimaryInstallPath

if (-not $MediaPath) {
    Write-Log "SQL Server 2022 installation media not found!" -Level ERROR
    Write-Log "Expected to find '$InstallerName' in a folder named '$SQLServerFolder'" -Level ERROR
    Stop-Transcript
    exit 1
}

Write-Log "Found installation media at: $MediaPath" -Level SUCCESS

# Verify all required files exist
$InstallerPath = Join-Path $MediaPath $InstallerName
$ConfigPath = Join-Path $MediaPath $ConfigFileName
$UpdatePath = Join-Path $MediaPath $UpdateName

$missingFiles = @()
if (-not (Test-Path $InstallerPath)) { $missingFiles += $InstallerName }
if (-not (Test-Path $ConfigPath)) { $missingFiles += $ConfigFileName }
if (-not (Test-Path $UpdatePath)) { $missingFiles += $UpdateName }

if ($missingFiles.Count -gt 0) {
    Write-Log "Missing required files: $($missingFiles -join ', ')" -Level ERROR
    Stop-Transcript
    exit 1
}

Write-Log "All required files found:" -Level SUCCESS
Write-Log "  Installer: $InstallerPath" -Level INFO
Write-Log "  Config: $ConfigPath" -Level INFO
Write-Log "  Update: $UpdatePath" -Level INFO

# =========================
# INSTALL SQL SERVER 2022
# =========================
Write-Log "INSTALLING SQL SERVER 2022 EXPRESS" -Level SECTION

# Read and log key settings from config file
Write-Log "Reading configuration file..." -Level INFO
try {
    $configContent = Get-Content $ConfigPath -ErrorAction Stop
    $instanceName = ($configContent | Where-Object { $_ -match '^INSTANCENAME=' }) -replace 'INSTANCENAME=', ''
    $features = ($configContent | Where-Object { $_ -match '^FEATURES=' }) -replace 'FEATURES=', ''

    if ($instanceName) { Write-Log "  Instance Name: $instanceName" -Level INFO }
    if ($features) { Write-Log "  Features: $features" -Level INFO }
} catch {
    Write-Log "Could not read config file, proceeding with installation anyway" -Level WARNING
}

# ============================================================================
# IMPORTANT: SQLEXPR_x64_ENU.exe has a bug where /ConfigurationFile parameter
# is NOT passed to setup.exe. The workaround is to:
# 1. Extract the installer to a temp folder
# 2. Run setup.exe directly from the extracted folder
# Reference: https://learn.microsoft.com/en-us/answers/questions/1341589/
# ============================================================================

$ExtractPath = "$env:TEMP\SQLServer2022_Extract"

# Clean up any previous extraction
if (Test-Path $ExtractPath) {
    Write-Log "Cleaning up previous extraction folder..." -Level INFO
    Remove-Item -Path $ExtractPath -Recurse -Force -ErrorAction SilentlyContinue
}

# Step 1: Extract the installer silently
Write-Log "Step 1: Extracting SQL Server installer..." -Level INFO
Write-Log "  Extracting to: $ExtractPath" -Level INFO

try {
    $extractProcess = Start-Process -FilePath $InstallerPath `
                                     -ArgumentList "/q", "/x:`"$ExtractPath`"" `
                                     -Wait `
                                     -PassThru `
                                     -NoNewWindow `
                                     -ErrorAction Stop

    if ($extractProcess.ExitCode -ne 0) {
        Write-Log "Extraction failed with exit code: $($extractProcess.ExitCode)" -Level ERROR
        Stop-Transcript
        exit 1
    }
    Write-Log "  Extraction complete" -Level SUCCESS
} catch {
    Write-Log "Failed to extract installer: $($_.Exception.Message)" -Level ERROR
    Stop-Transcript
    exit 1
}

# Verify setup.exe exists
$SetupExePath = Join-Path $ExtractPath "setup.exe"
if (-not (Test-Path $SetupExePath)) {
    Write-Log "setup.exe not found in extraction folder!" -Level ERROR
    Stop-Transcript
    exit 1
}

# Step 2: Run setup.exe with configuration file (fully silent)
Write-Log "Step 2: Running SQL Server setup (silent)..." -Level INFO
Write-Log "This may take 10-20 minutes. Please wait..." -Level INFO

# Build installation arguments for setup.exe
# /Q = Fully quiet (no UI at all)
# /IACCEPTSQLSERVERLICENSETERMS = Accept license
# /CONFIGURATIONFILE = Path to configuration file
$installArgs = @(
    "/Q",
    "/IACCEPTSQLSERVERLICENSETERMS",
    "/CONFIGURATIONFILE=`"$ConfigPath`""
)

Write-Log "  Command: setup.exe $($installArgs -join ' ')" -Level INFO

try {
    $installProcess = Start-Process -FilePath $SetupExePath `
                                     -ArgumentList $installArgs `
                                     -Wait `
                                     -PassThru `
                                     -NoNewWindow `
                                     -ErrorAction Stop

    $exitCode = $installProcess.ExitCode

    switch ($exitCode) {
        0 {
            Write-Log "SQL Server 2022 installed successfully!" -Level SUCCESS
        }
        3010 {
            Write-Log "SQL Server 2022 installed successfully (reboot required)" -Level SUCCESS
        }
        default {
            Write-Log "SQL Server installation completed with exit code: $exitCode" -Level WARNING
            # Check for common error codes
            switch ($exitCode) {
                -2068774911 { Write-Log "  Possible cause: .NET Framework issue" -Level WARNING }
                -2068643838 { Write-Log "  Possible cause: Missing prerequisite" -Level WARNING }
                -2067919934 { Write-Log "  Possible cause: Instance already exists" -Level WARNING }
            }
        }
    }
} catch {
    Write-Log "Failed to start SQL Server installation: $($_.Exception.Message)" -Level ERROR
    Stop-Transcript
    exit 1
}

# Clean up extraction folder
Write-Log "Cleaning up extraction folder..." -Level INFO
Remove-Item -Path $ExtractPath -Recurse -Force -ErrorAction SilentlyContinue

# =========================
# VERIFY INSTALLATION
# =========================
Write-Log "Verifying SQL Server installation..." -Level INFO

Start-Sleep -Seconds 10  # Wait for services to start

# Check if SQL Server service exists
$sqlService = Get-Service -Name "MSSQL`$*" -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $sqlService) {
    $sqlService = Get-Service -Name "MSSQLSERVER" -ErrorAction SilentlyContinue
}

if ($sqlService) {
    Write-Log "SQL Server service found: $($sqlService.Name) - Status: $($sqlService.Status)" -Level SUCCESS
} else {
    Write-Log "SQL Server service not found. Installation may have failed." -Level WARNING
}

# =========================
# APPLY CUMULATIVE UPDATE
# =========================
Write-Log "APPLYING SQL SERVER 2022 CUMULATIVE UPDATE" -Level SECTION

Write-Log "Update file: $UpdateName" -Level INFO
Write-Log "Starting update installation..." -Level INFO
Write-Log "This may take 5-15 minutes. Please wait..." -Level INFO

# Build update arguments
# /quiet - Quiet mode
# /IAcceptSQLServerLicenseTerms - Accept license terms
# /Action=Patch - Apply patch
$updateArgs = @(
    "/quiet",
    "/IAcceptSQLServerLicenseTerms",
    "/Action=Patch"
)

try {
    $updateProcess = Start-Process -FilePath $UpdatePath `
                                    -ArgumentList $updateArgs `
                                    -Wait `
                                    -PassThru `
                                    -NoNewWindow `
                                    -ErrorAction Stop

    $updateExitCode = $updateProcess.ExitCode

    switch ($updateExitCode) {
        0 {
            Write-Log "SQL Server 2022 update applied successfully!" -Level SUCCESS
        }
        3010 {
            Write-Log "SQL Server 2022 update applied successfully (reboot required)" -Level SUCCESS
        }
        default {
            Write-Log "SQL Server update completed with exit code: $updateExitCode" -Level WARNING
        }
    }
} catch {
    Write-Log "Failed to apply SQL Server update: $($_.Exception.Message)" -Level ERROR
}

# =========================
# FINAL VERIFICATION
# =========================
Write-Log "FINAL VERIFICATION" -Level SECTION

# Get SQL Server version info
try {
    $sqlKey = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL16.*\Setup" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($sqlKey) {
        Write-Log "SQL Server Edition: $($sqlKey.Edition)" -Level INFO
        Write-Log "SQL Server Version: $($sqlKey.Version)" -Level INFO
        Write-Log "SQL Server Path: $($sqlKey.SQLPath)" -Level INFO
    }
} catch {
    Write-Log "Could not retrieve SQL Server version info from registry" -Level WARNING
}

# List SQL Server services
Write-Log "SQL Server Services:" -Level INFO
Get-Service -Name "*SQL*" -ErrorAction SilentlyContinue | ForEach-Object {
    Write-Log "  $($_.Name): $($_.Status)" -Level INFO
}

# =========================
# COMPLETION
# =========================
Write-Log "SQL SERVER 2022 INSTALLATION COMPLETE" -Level SECTION

$rebootRequired = ($exitCode -eq 3010) -or ($updateExitCode -eq 3010)
if ($rebootRequired) {
    Write-Log "A system restart is required to complete the installation." -Level WARNING
}

Write-Log "Log file saved to: $LogFile" -Level INFO

Stop-Transcript
