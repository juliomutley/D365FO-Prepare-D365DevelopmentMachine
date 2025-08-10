<# Prepare-D365DevelopmentMachine
 #
 # Preparation:
 # So that the installations do not step on each other: First run windows updates, also
 # wait for antimalware to run scan...otherwise this will take a long time and we do not
 # want an automatic reboot to occur while this script is executing.
 #
 # Execute this script:
 # Set-ExecutionPolicy Bypass -Scope Process -Force; iex ((New-Object System.Net.WebClient).DownloadString('http://192.166.1.15:8000/Prepare-D365DevelopmentMachine.ps1'))
 #
 # Tested on Windows 10 and Windows Server 2016
 # Tested on F&O 7.3 OneBox and F&O 8.1, 10.0.44 OneBox and a 10.0.44 Azure Cloud Hosted Environment (CHE) deployed from LCS
 #
 # Ideas:
 #  Download useful SQL and PowerShell scripts, using Git?
 #>

# Original Script by @batetech shared with permission.
# This script makes the changes described in https://learn.microsoft.com/en-us/troubleshoot/windows-client/installing-updates-features-roles/troubleshoot-windows-update-error-0x80072efe-with-cipher-suite-configuration
# This will also fix issues where PowerShell modules can no longer be installed.
# See also https://github.com/d365collaborative/d365fo.tools/issues/874
# gist at https://gist.github.com/FH-Inway/193a2819c2682e203496ae7d44baecdb

# Requires -RunAsAdministrator
$currentPath = Get-Location
$ErrorActionPreference = 'Stop';
$regPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002';
$ciphers = Get-ItemPropertyValue "$regPath" -Name 'Functions';
Write-host "Values before: $ciphers";
$cipherList = $ciphers.Split(',');
$updateReg = $false;
if ($cipherList -inotcontains 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384')
{
    Write-Host "Adding TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384";
    $ciphers += ',TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384';
    $updateReg = $true;
}
if ($cipherList -inotcontains 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA256')
{
    Write-Host "Adding TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA256";
    $ciphers += ',TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA256';
    $updateReg = $true;
}
if ($updateReg)
{
    Set-ItemProperty "$regPath" -Name 'Functions' -Value "$ciphers";
    $ciphers = Get-ItemPropertyValue "$regPath" -Name 'Functions';
    write-host "Values after: $ciphers";
    Restart-Computer -Force;
}
else
{
    Write-Host 'No updates needed, the required ciphers already exist.';
}


#region Check if required .NET version is installed
$requiredVersion = '4.8'
$dotNetVersion = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' -Recurse |
        Get-ItemProperty -name Version -EA 0 |
        Where-Object { $_.PSChildName -match '^(?!S)\p{L}' } |
        Select-Object -ExpandProperty Version |
        Sort-Object -Descending |
        Select-Object -First 1

if ([string]::IsNullOrEmpty($dotNetVersion) -or [version]$dotNetVersion -lt [version]$requiredVersion)
{
    Write-Host "Error: .NET Framework $requiredVersion or a higher version is not installed on this computer."
    Write-Host "Press any key to exit..."
    $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyUp')
    Exit 1
}
#endregion



#region Installing d365fo.tools

# This is required by Find-Module, by doing it beforehand we remove some warning messages
Set-PSRepository -Name PSGallery -InstallationPolicy Trusted

if (Get-Module -ListAvailable -Name d365fo.tools)
{
    Write-Host "Updating d365fo.tools"
    Update-Module -Name d365fo.tools -Force -SkipPublisherCheck -AllowClobber
}
else
{
    Write-Host "Installing d365fo.tools"
    Write-Host "Documentation: https://github.com/d365collaborative/d365fo.tools"
    Install-Module -Name d365fo.tools -SkipPublisherCheck -AllowClobber -Scope AllUsers
    Import-Module d365fo.tools
}

# Pausing D365FO to optimize CPU and RAM usage
Stop-D365Environment

#endregion



#region Installing additional software using Chocolatey
If (Test-Path -Path "$env:ProgramData\Chocolatey")
{
    choco upgrade chocolatey -y -r
    choco upgrade all --ignore-checksums -y -r
}
Else
{
    Write-Host "Installing Chocolatey"

    Set-ExecutionPolicy Bypass -Scope Process -Force;
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072;
    Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))

    # Determine choco executable location
    # This is needed because the path variable is not updated
    # This part is copied from https://chocolatey.org/install.ps1
    $chocoPath = [Environment]::GetEnvironmentVariable("ChocolateyInstall")
    if ($chocoPath -eq $null -or $chocoPath -eq '')
    {
        $chocoPath = "$env:ALLUSERSPROFILE\Chocolatey"
    }
    if (!(Test-Path ($chocoPath)))
    {
        $chocoPath = "$env:SYSTEMDRIVE\ProgramData\Chocolatey"
    }
    $chocoExePath = Join-Path $chocoPath 'bin\choco.exe'

    $packages = @(
        "googlechrome"
        "notepadplusplus.install"
        "7zip"
        "agentransack"
        "wiztree"
        "smtp4dev"
        "greenshot"
        "nuget.commandline"
    )

    # Install each program
    foreach ($packageToInstall in $packages)
    {
        Write-Host "Installing $packageToInstall" -ForegroundColor Green
        & $chocoExePath "install" $packageToInstall "--ignore-checksums" "-y" "-r"
    }
}
#endregion



# Helper: Safely rearm Windows license if possible
function Invoke-RearmWindowsSafe
{
    try
    {
        # Ensure Software Protection service (sppsvc) exists and is running
        $svc = Get-Service -Name sppsvc -ErrorAction SilentlyContinue
        if ($null -eq $svc)
        {
            Write-Host "Software Protection service (sppsvc) not found. Skipping Windows rearm."
            return
        }
        if ($svc.Status -ne 'Running')
        {
            Write-Host "Starting Software Protection service (sppsvc)..."
            Start-Service -Name sppsvc -ErrorAction Stop
        }

        # Query remaining rearm count
        $sls = Get-CimInstance -ClassName SoftwareLicensingService -ErrorAction Stop
        $remaining = $sls.RemainingWindowsReArmCount
        Write-Host "Remaining Windows rearm count: $remaining"
        if ($remaining -le 0)
        {
            Write-Warning "No remaining Windows rearms. Skipping rearm."
            return
        }

        # Attempt the rearm
        $result = Invoke-CimMethod -InputObject $sls -MethodName ReArmWindows -ErrorAction Stop
        Write-Host "ReArmWindows invoked (ReturnValue=$( $result.ReturnValue )). A reboot may be required."
    }
    catch
    {
        Write-Warning ("Windows rearm failed: {0}" -f $_.Exception.Message)
        Write-Warning "Non-fatal: continuing. Check activation with 'slmgr.vbs /dlv' or rearm manually with 'slmgr.vbs /rearm'."
    }
}

#region Optimizing using d365fo.tools
if (Get-Module -ListAvailable -Name d365fo.tools)
{
    Write-Host "Setting Management Reporter to Disabled to reduce churn and Event Log messages"
    Get-D365Environment -FinancialReporter | Set-Service -StartupType Disabled

    Write-Host "Setting Batch to Disabled to speed up compilation time"
    Get-D365Environment -Batch | Set-Service -StartupType Disabled

    Write-Host "Setting Windows Defender rules to speed up compilation time"
    Add-D365WindowsDefenderRules -Silent

    Write-Host "Rearming Windows license"
    Invoke-RearmWindowsSafe
}
#endregion



#region Local User Policy

# Set the password to never expire
Get-WmiObject Win32_UserAccount -filter "LocalAccount=True" | Where-Object { $_.SID -Like "S-1-5-21-*-500" } | Set-LocalUser -PasswordNeverExpires 1

# Disable changing the password
$registryPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
$name = "DisableChangePassword"
$value = "1"

If (!(Test-Path $registryPath))
{
    New-Item -Path $registryPath -Force | Out-Null
    New-ItemProperty -Path $registryPath -Name $name -Value $value -PropertyType DWORD -Force | Out-Null
}
Else
{
    $passwordChangeRegKey = Get-ItemProperty -Path $registryPath -Name $Name -ErrorAction SilentlyContinue

    If (-Not $passwordChangeRegKey)
    {
        New-ItemProperty -Path $registryPath -Name $name -Value $value -PropertyType DWORD -Force | Out-Null
    }
    Else
    {
        Set-ItemProperty -Path $registryPath -Name $name -Value $value
    }
}

#endregion

#region Privacy
# Disable Windows Telemetry (requires a reboot to take effect)
Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection -Name AllowTelemetry -Type DWord -Value 0
Get-Service DiagTrack, Dmwappushservice | Stop-Service | Set-Service -StartupType Disabled

# SmartScreen Filter for Store Apps: Disable
Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost -Name EnableWebContentEvaluation -Type DWord -Value 0

# Start Menu: Disable Bing Search Results
Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search -Name BingSearchEnabled -Type DWord -Value 0

# WiFi Sense: Shared HotSpot Auto-Connect: Disable
Set-ItemProperty -Path HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots -Name value -Type DWord -Value 0

# Activity Tracking: Disable
@('EnableActivityFeed', 'PublishUserActivities', 'UploadUserActivities') | ForEach-Object { Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\System -Name $_ -Type DWord -Value 0 }

# Start Menu: Disable Cortana
if (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings"))
{
    New-Item -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Type DWord -Value 0
if (!(Test-Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization"))
{
    New-Item -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Type DWord -Value 1
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Type DWord -Value 1
if (!(Test-Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore"))
{
    New-Item -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Type DWord -Value 0
if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"))
{
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Type DWord -Value 0

# Debloat Microsoft Edge
Write-Host "Applying Microsoft Edge debloat settings"
$edgeRegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
if (!(Test-Path $edgeRegPath))
{
    New-Item -Path $edgeRegPath -Force | Out-Null
}

$edgeSettings = @{
    "HideFirstRunExperience" = 1
    "SearchInSidebarEnabled" = 2
    "HubsSidebarEnabled" = 0
    "ReadAloudEnabled" = 0
    "DiagnosticData" = 0
    "PinBrowserEssentialsToolbarButton" = 0
    "EdgeCollectionsEnabled" = 0
    "PersonalizationReportingEnabled" = 0
    "SplitScreenEnabled" = 0
    "ImplicitSignInEnabled" = 0
    "GuidedSwitchEnabled" = 0
    "EdgeDefaultProfileEnabled" = "Default"
    "BrowserSignin" = 0
    "ShowMicrosoftRewards" = 0
    "AutoImportAtFirstRun" = 4
    "EdgeWorkspacesEnabled" = 0
    "EdgeWalletCheckoutEnabled" = 0
    "EdgeWalletEtreeEnabled" = 0
    "BuiltInDnsClientEnabled" = 0
    "AADWebSiteSSOUsingThisProfileEnabled" = 0
    "AccessibilityImageLabelsEnabled" = 0
    "AddressBarMicrosoftSearchInBingProviderEnabled" = 0
    "AllowGamesMenu" = 0
    "AutomaticHttpsDefault" = 2
    "BrowserAddProfileEnabled" = 0
    "BrowserGuestModeEnabled" = 0
    "ComposeInlineEnabled" = 0
    "ConfigureOnPremisesAccountAutoSignIn" = 0
    "ConfigureOnlineTextToSpeech" = 0
    "ConfigureShare" = 0
    "DefaultBrowserSettingsCampaignEnabled" = 0
    "Edge3PSerpTelemetryEnabled" = 0
    "EdgeEDropEnabled" = 0
    "SyncDisabled" = 1
    "WalletDonationEnabled" = 0
    "NonRemovableProfileEnabled" = 0
    "ImportOnEachLaunch" = 0
    "InAppSupportEnabled" = 0
    "LocalBrowserDataShareEnabled" = 0
    "LiveCaptionsAllowed" = 0
    "MSAWebSiteSSOUsingThisProfileAllowed" = 0
    "MicrosoftEdgeInsiderPromotionEnabled" = 0
    "MicrosoftEditorSynonymsEnabled" = 0
    "MicrosoftEditorProofingEnabled" = 0
    "RelatedWebsiteSetsEnabled" = 0
    "PaymentMethodQueryEnabled" = 0
    "PinningWizardAllowed" = 0
    "PromotionalTabsEnabled" = 0
    "QuickSearchShowMiniMenu" = 0
    "QuickViewOfficeFilesEnabled" = 0
    "RemoteDebuggingAllowed" = 0
    "ResolveNavigationErrorsUseWebService" = 0
    "RoamingProfileSupportEnabled" = 0
    "SearchForImageEnabled" = 0
    "SearchFiltersEnabled" = 0
    "SearchSuggestEnabled" = 0
    "SearchbarAllowed" = 0
    "SearchbarIsEnabledOnStartup" = 0
    "SharedLinksEnabled" = 0
    "ShowAcrobatSubscriptionButton" = 0
    "ShowOfficeShortcutInFavoritesBar" = 0
    "ShowRecommendationsEnabled" = 0
    "SpeechRecognitionEnabled" = 0
    "StandaloneHubsSidebarEnabled" = 0
    "TabServicesEnabled" = 0
    "TextPredictionEnabled" = 0
    "UploadFromPhoneEnabled" = 0
    "VisualSearchEnabled" = 0
    "NewTabPageSearchBox" = "redirect"
    "PasswordGeneratorEnabled" = 0
    "PasswordManagerEnabled" = 0
    "PasswordMonitorAllowed" = 0
    "PasswordProtectionWarningTrigger" = 0
    "AlternateErrorPagesEnabled" = 0
    "AskBeforeCloseEnabled" = 0
    "AutofillAddressEnabled" = 0
    "AutofillCreditCardEnabled" = 0
    "AutofillMembershipsEnabled" = 0
    "AADWebSSOAllowed" = 0
    "AIGenThemesEnabled" = 0
    "AccessCodeCastEnabled" = 0
    "AdditionalDnsQueryTypesEnabled" = 0
    "AdsTransparencyEnabled" = 0
    "EdgeAdminCenterEnabled" = 0
    "BingAdsSuppression" = 1
    "ConfigureDoNotTrack" = 1
    "EdgeAssetDeliveryServiceEnabled" = 0
    "EdgeShoppingAssistantEnabled" = 0
    "ExperimentationAndConfigurationServiceControl" = 0
    "NetworkPredictionOptions" = 0
    "UserFeedbackAllowed" = 0
    "WebWidgetAllowed" = 0
    "TyposquattingCheckerEnabled" = 0
    "TrackingPrevention" = 3
    "SigninInterceptionEnabled" = 0
    "SideSearchEnabled" = 0
    "ShowPDFDefaultRecommendationsEnabled" = 0
    "ShowHomeButton" = 0
    "ShoppingListEnabled" = 0
    "SafeBrowsingSurveysEnabled" = 0
    "SafeBrowsingDeepScanningEnabled" = 0
    "SafeBrowsingProxiedRealTimeChecksAllowed" = 0
    "PasswordDismissCompromisedAlertEnabled" = 0
    "MAMEnabled" = 0
    "HighEfficiencyModeEnabled" = 0
    "EdgeManagementEnabled" = 0
    "DesktopSharingHubEnabled" = 0
    "CopilotPageContextEnabled" = 0
    "ProactiveAuthWorkflowEnabled" = 0
    "CopilotPageContext" = 0
    "NewTabPageContentEnabled" = 0
    "NewTabPageAppLauncherEnabled" = 0
    "NewTabPageBingChatEnabled" = 0
    "NewTabPageQuickLinksEnabled" = 0
    "QRCodeGeneratorEnabled" = 0
    "TranslateEnabled" = 0
    "SpotlightExperiencesAndRecommendationsEnabled" = 0
    "ApplicationGuardFavoritesSyncEnabled" = 0
    "ApplicationGuardTrafficIdentificationEnabled" = 0
    "WebToBrowserSignInEnabled" = 0
    "SeamlessWebToBrowserSignInEnabled" = 0
    "EdgeAutofillMlEnabled" = 0
    "GenAILocalFoundationalModelSettings" = 1
    "PersonalizeTopSitesInCustomizeSidebarEnabled" = 0
    "ExtensionsPerformanceDetectorEnabled" = 0
    "PerformanceDetectorEnabled" = 0
    "EdgeEntraCopilotPageContext" = 0
    "MouseGestureEnabled" = 0
    "DisableScreenshots" = 0
    "WebCaptureEnabled" = 0
    "SpellcheckEnabled" = 0
    "AddressBarWorkSearchResultsEnabled" = 0
    "ScarewareBlockerProtectionEnabled" = 0
    "AddressBarTrendingSuggestEnabled" = 0
}

foreach ($key in $edgeSettings.GetEnumerator())
{
    if ($key.Value -is [string])
    {
        Set-ItemProperty -Path $edgeRegPath -Name $key.Name -Value $key.Value -Type String -Force
    }
    else
    {
        Set-ItemProperty -Path $edgeRegPath -Name $key.Name -Value $key.Value -Type DWord -Force
    }
}

#endregion



#region Update power settings
# Set power settings to High Performance
Write-Host "Setting power settings to High Performance"
powercfg.exe /SetActive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
#endregion



#region Updating OS and installed software
# Update Visual Studio 2022
$filepath = "C:\Program Files\Microsoft Visual Studio\2022\Professional"

if (Test-Path $filepath)
{
    Start-Process -Wait `
        -FilePath "C:\Program Files (x86)\Microsoft Visual Studio\Installer\vs_installer.exe" `
        -ArgumentList "update --passive --norestart --installpath `"$filepath`""
}

# Check and install SSMS if not present
function Test-SSMSInstalled
{
    $ssmsPaths = @(
        "C:\Program Files (x86)\Microsoft SQL Server Management Studio 20\Common7\IDE\Ssms.exe"  # SSMS 2022
    )

    foreach ($path in $ssmsPaths)
    {
        if (Test-Path $path)
        {
            $version = (Get-Item $path).VersionInfo.ProductVersion
            Write-Host "SSMS found at $path (Version: $version)"
            return $true
        }
    }

    $registryPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    foreach ($regPath in $registryPaths)
    {
        $ssmsReg = Get-ItemProperty $regPath -ErrorAction SilentlyContinue |
                Where-Object {
                    $_.DisplayName -like "*SQL Server Management Studio*" -and
                            ($_.DisplayVersion -like "19.*" -or $_.DisplayVersion -like "20.*")
                }
        if ($ssmsReg)
        {
            Write-Host "SSMS found in registry: $( $ssmsReg.DisplayName ) (Version: $( $ssmsReg.DisplayVersion ))"
            return $true
        }
    }

    Write-Host "No SSMS 2019 or 2022 installation detected."
    return $false
}

# Set file and folder path for SSMS installer
$folderpath = "C:\Windows\Temp"
$filepath = "$folderpath\SSMS-Setup-ENU.exe"

# Install SSMS only if not already installed
if (-not (Test-SSMSInstalled))
{
    # Download SSMS installer if not present
    if (!(Test-Path $filepath))
    {
        Write-Host "Downloading SQL Server SSMS..."
        try
        {
            $URL = "https://aka.ms/ssmsfullsetup"
            $clnt = New-Object System.Net.WebClient
            $clnt.DownloadFile($URL, $filepath)
            Write-Host "SSMS installer download complete" -ForegroundColor Green
        }
        catch
        {
            Write-Host "Error downloading SSMS installer: $_" -ForegroundColor Red
            Exit 1
        }
    }
    else
    {
        Write-Host "Located the SQL SSMS Installer binaries, moving on to installation..."
    }

    # Start the SSMS installer
    Write-Host "Installing SSMS..."
    try
    {
        $Parms = "/Install /Quiet /Norestart /Logs `"$folderpath\ssms_install_log.txt`" SSMSInstallRoot=`"C:\Program Files (x86)\Microsoft SQL Server Management Studio 20`""
        $process = Start-Process -FilePath $filepath -ArgumentList $Parms -Wait -PassThru
        if ($process.ExitCode -eq 0)
        {
            Write-Host "SSMS installation complete" -ForegroundColor Green
        }
        else
        {
            Write-Host "SSMS installation failed with exit code: $( $process.ExitCode )" -ForegroundColor Red
            Write-Host "Check logs at $folderpath\ssms_install_log.txt for details"
            Exit 1
        }
    }
    catch
    {
        Write-Host "Error during SSMS installation: $_" -ForegroundColor Red
        Exit 1
    }

    # Clean up installer
    Remove-Item $filepath -Force -ErrorAction SilentlyContinue
}
else
{
    Write-Host "SSMS is already installed. Updates will be handled by Windows Update."
}

# SQL Optimization section
#region SQL optimization

If (Test-Path "HKLM:\Software\Microsoft\Microsoft SQL Server\Instance Names\SQL")
{
    if (Get-Module -ListAvailable -Name dbatools)
    {
        Write-Host "Updating dbatools"
        Update-Module -Name dbatools -Force -SkipPublisherCheck -AllowClobber
    }
    else
    {
        Write-Host "Installing dbatools PowerShell module"
        Install-Module -Name dbatools -SkipPublisherCheck -Scope AllUsers
        Import-Module dbatools
    }

    Write-Host "Disabling 'Build metadata cache when AOS starts' to speed up restart times after compile"
    $sql = "UPDATE SystemParameters SET ODataBuildMetadataCacheOnAosStartup = 0"
    Invoke-DbaQuery -SqlInstance "." -Database "AxDB" -Query $sql -QueryTimeout 0

    Set-DbatoolsInsecureConnection -SessionOnly
    Write-Host "Setting max memory to 4GB"
    Set-DbaMaxMemory -SqlInstance . -Max 4096
    Write-Host "Adding trace flags"
    Enable-DbaTraceFlag -SqlInstance . -TraceFlag 174, 834, 1204, 1222, 1224, 2505, 7412
    Write-Host "Restarting service"
    Restart-DbaService -Type Engine -Force
    Write-Host "Setting recovery model"
    Set-DbaDbRecoveryModel -SqlInstance . -RecoveryModel Simple -Database AxDB -Confirm:$false
}
#endregion

#region install VS Addins

# Install Addins (hardened download without IE parser dependency)
# Add-in bootstrap (Waywo + TrudAX + SSD365VSAddIn) — multi-repo, multi-file, idempotent

# --- Settings ---
$addinPath = "C:\Addins"   # target folder for all downloaded add-ins

# Repos and their file lists
$repos = @(
    @{
        Name = "TrudAX"
        Repo = "TrudAX/TRUDUtilsD365"
        Files = @("InstallToVS.exe", "TRUDUtilsD365.dll", "TRUDUtilsD365.pdb")
    },
    @{
        Name = "Waywo"
        Repo = "noakesey/d365fo-entity-schema"
        Files = @("Waywo.DbSchema.AddIn.dll")
        Fallback = "https://github.com/noakesey/d365fo-entity-schema/releases/download/v1.4.0/Waywo.DbSchema.AddIn.dll"
    },
    @{
        Name = "SSD365VSAddIn"
        Repo = "shashisadasivan/SSD365VSAddIn"
        Files = @("Newtonsoft.Json.dll", "SSD365VSAddIn.dll", "Microsoft.VisualStudio.Interop.dll", "envdte80.dll")
    }
)

# --- Prep / Utilities ---
if (!(Test-Path $addinPath))
{
    New-Item -ItemType Directory -Force -Path $addinPath | Out-Null
}

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$ghHeaders = @{ 'User-Agent' = 'D365-PrepScript'; 'Accept' = 'application/vnd.github+json' }

function Invoke-Download
{
    param(
        [Parameter(Mandatory)] [string] $Uri,
        [Parameter(Mandatory)] [string] $OutFile,
        [int] $Retries = 3,
        [int] $TimeoutSec = 180
    )
    for ($i = 1; $i -le $Retries; $i++) {
        try
        {
            Invoke-WebRequest -Uri $Uri -OutFile $OutFile -UseBasicParsing -TimeoutSec $TimeoutSec
            Unblock-File $OutFile
            return
        }
        catch
        {
            if ($i -eq $Retries)
            {
                throw
            }
            Start-Sleep -Seconds ([math]::Pow(2, $i)) # backoff
        }
    }
}

function Get-LatestTag
{
    param([Parameter(Mandatory)][string]$Repo)
    $latestApi = "https://api.github.com/repos/$Repo/releases/latest"
    $releases = "https://api.github.com/repos/$Repo/releases"

    # try /latest first
    try
    {
        $r = Invoke-RestMethod -Uri $latestApi -Headers $ghHeaders -TimeoutSec 60
        if ($r.tag_name)
        {
            return $r.tag_name
        }
    }
    catch
    {
        Write-Host "Latest-tag API failed for $Repo; falling back to releases list..."
    }

    # then fallback to the releases list
    try
    {
        $r = Invoke-RestMethod -Uri $releases -Headers $ghHeaders -TimeoutSec 60
        if ($r -and $r[0] -and $r[0].tag_name)
        {
            return $r[0].tag_name
        }
    }
    catch
    {
        Write-Warning "Could not resolve a release tag for $Repo."
    }
    return $null
}

# --- Download loop ---
foreach ($entry in $repos)
{
    $repo = $entry.Repo
    $name = $entry.Name
    $files = $entry.Files
    $fallback = $entry.Fallback

    Write-Host "Determining latest release for $name ($repo)"
    $tag = Get-LatestTag -Repo $repo
    if (-not $tag -and -not $fallback)
    {
        throw "No tag resolved for $repo and no fallback URL provided."
    }

    foreach ($file in $files)
    {
        $target = Join-Path $addinPath $file
        if (Test-Path $target)
        {
            Write-Host "$name : $file already present at $target"
            continue
        }

        $downloadUrl = $null
        if ($tag)
        {
            $downloadUrl = "https://github.com/$repo/releases/download/$tag/$file"
        }
        elseif ($fallback)
        {
            $downloadUrl = $fallback
        }

        try
        {
            if ($downloadUrl)
            {
                Write-Host "$name : Downloading $file from $downloadUrl"
                Invoke-Download -Uri $downloadUrl -OutFile $target
            }
            else
            {
                throw "No download URL computed."
            }
        }
        catch
        {
            if ($fallback -and $downloadUrl -ne $fallback)
            {
                Write-Host "$name : Primary download failed; attempting fallback $fallback"
                Invoke-Download -Uri $fallback -OutFile $target
            }
            else
            {
                throw
            }
        }
    }

    # Optional: attempt silent post-install (TrudAX only)
    if ($name -eq "TrudAX")
    {
        $installerPath = Join-Path $addinPath "InstallToVS.exe"
        if (Test-Path $installerPath)
        {
            try
            {
                Write-Host "Attempting TrudAX InstallToVS.exe silent run..."
                Start-Process -FilePath $installerPath -ArgumentList "/q" -Wait -ErrorAction SilentlyContinue
            }
            catch
            {
                Write-Host "TrudAX InstallToVS.exe not run (manual run may be required)."
            }
        }
    }
}

# --- Update DynamicsDevConfig.xml once with C:\Addins ---
$documentsFolder = Join-Path $env:USERPROFILE 'Documents'
$xmlFilePath = Join-Path $documentsFolder 'Visual Studio Dynamics 365\DynamicsDevConfig.xml'

if (!(Test-Path $xmlFilePath))
{
    Write-Host "DynamicsDevConfig.xml not found; creating skeleton at $xmlFilePath"
    $null = New-Item -ItemType Directory -Force -Path (Split-Path $xmlFilePath -Parent)
    $xmlContent = @"
<DynamicsDevConfig xmlns:i="http://www.w3.org/2001/XMLSchema-instance" xmlns="http://schemas.datacontract.org/2004/07/Microsoft.Dynamics.Framework.Tools.Development">
  <AddInPaths xmlns:d2p1="http://schemas.microsoft.com/2003/10/Serialization/Arrays">
    <d2p1:string>$addinPath</d2p1:string>
  </AddInPaths>
</DynamicsDevConfig>
"@
    $xmlContent | Out-File -FilePath $xmlFilePath -Encoding UTF8
}
else
{
    try
    {
        [xml]$xml = Get-Content -Path $xmlFilePath
        $already = $false
        foreach ($s in $xml.DynamicsDevConfig.AddInPaths.string)
        {
            if ($s -eq $addinPath)
            {
                $already = $true; break
            }
        }
        if (-not $already)
        {
            $newElement = $xml.CreateElement('d2p1', 'string', 'http://schemas.microsoft.com/2003/10/Serialization/Arrays')
            $newElement.InnerText = $addinPath
            $xml.DynamicsDevConfig.AddInPaths.AppendChild($newElement) | Out-Null
            $xml.Save($xmlFilePath)
            Write-Host "Added $addinPath to DynamicsDevConfig.xml"
        }
        else
        {
            Write-Host "$addinPath already present in DynamicsDevConfig.xml"
        }
    }
    catch
    {
        throw "Failed to update DynamicsDevConfig.xml: $( $_.Exception.Message )"
    }
}

Write-Host "Add-ins downloaded to $addinPath and configuration updated."
#endregion install Addins

# Based on https://gist.github.com/ScottHutchinson/b22339c3d3688da5c9b477281e258400
# Based on http://nuts4.net/post/automated-download-and-installation-of-visual-studio-extensions-via-powershell

function Invoke-VSInstallExtension
{
    param(
        [Parameter(Position = 1)]
        [ValidateSet('2019', '2022')]
        [System.String]$Version,
        [String] $PackageName)

    $ErrorActionPreference = "Stop"

    $baseProtocol = "https:"
    $baseHostName = "marketplace.visualstudio.com"

    $Uri = "$( $baseProtocol )//$( $baseHostName )/items?itemName=$( $PackageName )"
    $VsixLocation = "$( $env:Temp )\$([guid]::NewGuid() ).vsix"

    switch ($Version)
    {
        '2019' {
            $VSInstallDir = "C:\Program Files (x86)\Microsoft Visual Studio\Installer\resources\app\ServiceHub\Services\Microsoft.VisualStudio.Setup.Service"
        }
        '2022' {
            $VSInstallDir = "C:\Program Files\Microsoft Visual Studio\2022\Professional\Common7\IDE\"
        }
    }

    If ((test-path $VSInstallDir))
    {

        Write-Host "Grabbing VSIX extension at $( $Uri )"
        $HTML = Invoke-WebRequest -Uri $Uri -UseBasicParsing -SessionVariable session

        Write-Host "Attempting to download $( $PackageName )..."
        $anchor = $HTML.Links |
                Where-Object { $_.class -eq 'install-button-container' } |
                Select-Object -ExpandProperty href

        if (-Not $anchor)
        {
            Write-Error "Could not find download anchor tag on the Visual Studio Extensions page"
            Exit 1
        }
        Write-Host "Anchor is $( $anchor )"
        $href = "$( $baseProtocol )//$( $baseHostName )$( $anchor )"
        Write-Host "Href is $( $href )"
        Invoke-WebRequest $href -OutFile $VsixLocation -WebSession $session

        if (-Not (Test-Path $VsixLocation))
        {
            Write-Error "Downloaded VSIX file could not be located"
            Exit 1
        }


        Write-Host "************    VSInstallDir is:  $( $VSInstallDir )"
        Write-Host "************    VsixLocation is: $( $VsixLocation )"
        Write-Host "************    Installing: $( $PackageName )..."
        Start-Process -Filepath "$( $VSInstallDir )\VSIXInstaller" -ArgumentList "/q /a $( $VsixLocation )" -Wait

        Write-Host "Cleanup..."
        Remove-Item $VsixLocation -Force -Confirm:$false

        Write-Host "Installation of $( $PackageName ) complete!"
    }
}

Get-Process devenv -ErrorAction Ignore | Stop-Process -ErrorAction Ignore

Invoke-VSInstallExtension -Version 2022 -PackageName 'Zhenkas.LocateInTFS'
Invoke-VSInstallExtension -Version 2022 -PackageName 'cpmcgrath.Codealignment'
Invoke-VSInstallExtension -Version 2022 -PackageName 'EWoodruff.VisualStudioSpellCheckerVS2022andLater'
Invoke-VSInstallExtension -Version 2019 -PackageName 'MadsKristensen.TrailingWhitespaceVisualizer'
Invoke-VSInstallExtension -Version 2022 -PackageName 'MadsKristensen.TrailingWhitespace64'
Invoke-VSInstallExtension -Version 2022 -PackageName 'ViktarKarpach.DebugAttachManager2022'

#endregion install VS Addins

#region run windows update
Install-PackageProvider NuGet -Force -Confirm:$false
Install-Module PSWindowsUpdate -Force -Confirm:$false
Install-WindowsUpdate -MicrosoftUpdate -AcceptAll -AutoReboot -Confirm:$false
#endregion

#region Installing powershell modules
# This is requried by Find-Module, by doing it beforehand we remove some warning messages
Set-PSRepository -Name PSGallery -InstallationPolicy Trusted

# Installing powershell modules
$Module2Service = @('Az', 'dbatools', 'SqlServer')

$Module2Service | ForEach-Object {
    if (Get-Module -ListAvailable -Name $_)
    {
        Write-Host "Updating " + $_
        Update-Module -Name $_ -Force
    }
    else
    {
        Write-Host "Installing " + $_
        Install-Module -Name $_ -SkipPublisherCheck -Scope AllUsers -AllowClobber -Force
        Import-Module $_
    }
}
#endregion

#region Install and run Ola Hallengren's IndexOptimize

Function Execute-Sql
{
    Param(
        [Parameter(Mandatory = $true)][string]$server,
        [Parameter(Mandatory = $true)][string]$database,
        [Parameter(Mandatory = $true)][string]$command
    )
    Process {
        $scon = New-Object System.Data.SqlClient.SqlConnection
        $scon.ConnectionString = "Data Source=$server;Initial Catalog=$database;Integrated Security=true"

        $cmd = New-Object System.Data.SqlClient.SqlCommand
        $cmd.Connection = $scon
        $cmd.CommandTimeout = 0
        $cmd.CommandText = $command

        try
        {
            $scon.Open()
            $cmd.ExecuteNonQuery()
        }
        catch [Exception]
        {
            Write-Warning $_.Exception.Message
        }
        finally
        {
            $scon.Dispose()
            $cmd.Dispose()
        }
    }
}

If (Test-Path "HKLM:\Software\Microsoft\Microsoft SQL Server\Instance Names\SQL")
{

    #Alocating 70% of the total server memory for sql server
    $totalServerMemory = Get-WMIObject -Computername . -class win32_ComputerSystem | Select-Object -Expand TotalPhysicalMemory
    $memoryForSqlServer = ($totalServerMemory * 0.7) / 1024 / 1024

    Set-DbaMaxMemory -SqlInstance . -Max $memoryForSqlServer

    Write-Host "Installing Ola Hallengren's SQL Maintenance scripts"
    Install-DbaMaintenanceSolution -SqlInstance . -Database master

    Write-Host "Installing FirstAidResponder PowerShell module"
    Install-DbaFirstResponderKit -SqlInstance . -Database master

    Invoke-D365InstallSqlPackage
    Invoke-D365InstallAzCopy

    Write-Host "Install latest CU"

    $DownloadPath = "C:\temp\SqlKB"
    $PathExists = Test-Path($DownloadPath)
    if ($PathExists -eq $false)
    {
        mkdir $DownloadPath
    }

    Set-DbatoolsConfig -FullName 'sql.connection.trustcert' -Value $true -Register

    $BuildTargets = Test-DbaBuild -SqlInstance . -MaxBehind 0CU -Update | Where-Object { !$PSItem.Compliant } | Select-Object -ExpandProperty BuildTarget -Unique
    Get-DbaBuildReference -Build $BuildTargets | ForEach-Object { Save-DbaKBUpdate -Path $DownloadPath -Name $PSItem.KBLevel };
    Update-DbaInstance -ComputerName . -Path $DownloadPath -Confirm:$false
    Remove-Item $DownloadPath -Recurse -Force -Confirm:$false

    Write-Host "Adding trace flags"
    Enable-DbaTraceFlag -SqlInstance . -TraceFlag 174, 834, 1204, 1222, 1224, 2505, 7412

    Set-DbaPrivilege -Type LPIM,IFI

    Write-Host "Restarting service"
    Restart-DbaService -Type Engine -Force

    Write-Host "Setting recovery model"
    Set-DbaDbRecoveryModel -SqlInstance . -RecoveryModel Simple -Database AxDB -Confirm:$false

    Write-Host "Setting database options"
    $sql = "ALTER DATABASE [AxDB] SET AUTO_CLOSE OFF"
    Invoke-DbaQuery -Query $sql -SqlInstance "." -database "AxDB" -QueryTimeout 0

    $sql = "ALTER DATABASE [AxDB] SET AUTO_UPDATE_STATISTICS_ASYNC OFF"
    Invoke-DbaQuery -Query $sql -SqlInstance "." -database "AxDB" -QueryTimeout 0

    Write-Host "enabling users"
    $sql = "UPDATE USERINFO SET enable = 1 WHERE id NOT IN ('axrunner', 'Guest')"
    Invoke-DbaQuery -SqlInstance "." -Database "AxDB" -Query $sql -QueryTimeout 0

    Write-Host "Setting Server configurations"
    $sql = "WITH ServerConfigCTE AS ( SELECT top 1 SERVERID, @@servername AS NewServerID FROM SYSSERVERCONFIG ) UPDATE ServerConfigCTE SET SERVERID = 'Batch:' + NewServerID"
    Invoke-DbaQuery -SqlInstance "." -Database "AxDB" -Query $sql -QueryTimeout 0
    $sql = "delete SYSSERVERCONFIG where SERVERID <> 'Batch:' + @@servername"
    Invoke-DbaQuery -SqlInstance "." -Database "AxDB" -Query $sql -QueryTimeout 0

    Write-Host "Setting batchservergroup options"
    $sql = "delete batchservergroup where SERVERID <> 'Batch:$server'

    insert into batchservergroup(GROUPID, SERVERID, RECID, RECVERSION, CREATEDDATETIME, CREATEDBY)
    select GROUP_, 'Batch:@@SERVERNAME, 5900000000 + cast(CRYPT_GEN_RANDOM(4) as bigint), 1, GETUTCDATE(), '-admin-' from batchgroup
        where not EXISTS (select recid from batchservergroup where batchservergroup.GROUPID = batchgroup.GROUP_)"
    Invoke-DbaQuery -SqlInstance "." -Database "AxDB" -Query $sql -QueryTimeout 0
    Write-Host "purging disposable data"

    $DiposableTables = @(
        "batchjobhistory"
        ,"BatchConstraintsHistory"
        ,"batchhistory"
        ,"DMFDEFINITIONGROUPEXECUTION"
        ,"DMFDEFINITIONGROUPEXECUTIONHISTORY"
        ,"DMFEXECUTION"
        ,"DMFSTAGINGEXECUTIONERRORS"
        ,"DMFSTAGINGLOG"
        ,"DMFSTAGINGLOGDETAILS"
        ,"DMFSTAGINGVALIDATIONLOG"
        ,"eventcud"
        ,"EVENTCUDLINES"
        ,"formRunConfiguration"
        ,"INVENTSUMLOGTTS"
        ,"MP.PeggingIdMapping"
        ,"REQPO"
        ,"REQTRANS"
        ,"REQTRANSCOV"
        ,"RETAILLOG"
        ,"SALESPARMLINE"
        ,"SALESPARMSUBLINE"
        ,"SALESPARMSUBTABLE"
        ,"SALESPARMTABLE"
        ,"SALESPARMUPDATE"
        ,"SUNTAFRELEASEFAILURES"
        ,"SUNTAFRELEASELOGLINEDETAILS"
        ,"SUNTAFRELEASELOGTABLE"
        ,"SUNTAFRELEASELOGTRANS"
        ,"sysdatabaselog"
        ,"syslastvalue"
        ,"sysuserlog"
    )

    $DiposableTables | ForEach-Object {
        Write-Host "purging $_"
        $sql = "truncate table $_"
        Invoke-DbaQuery -Query $sql -SqlInstance "." -database "AxDB" -QueryTimeout 0
    }

    Write-Host "purging disposable batch job data"
    $sql = "delete batchjob where status in (3, 4, 8)
    delete batch where not exists (select recid from batchjob where batch.BATCHJOBID = BATCHJOB.recid)"
    Invoke-DbaQuery -Query $sql -SqlInstance "." -database "AxDB" -QueryTimeout 0

    Write-Host "purging staging tables data"
    $sql = "EXEC sp_msforeachtable
    @command1 ='truncate table ?'
    ,@whereand = ' And Object_id In (Select Object_id From sys.objects
    Where name like ''%staging'')'"

    Invoke-DbaQuery -Query $sql -SqlInstance "." -database "AxDB" -QueryTimeout 0

    Write-Host "purging disposable report data"
    $sql = "EXEC sp_msforeachtable
    @command1 ='truncate table ?'
    ,@whereand = ' And Object_id In (Select Object_id From sys.objects
    Where name like ''%tmp'')'"
    Invoke-DbaQuery -Query $sql -SqlInstance "." -database "AxDB" -QueryTimeout 0

    Write-Host "dropping temp tables"
    $sql = "EXEC sp_msforeachtable
    @command1 ='drop table ?'
    ,@whereand = ' And Object_id In (Select Object_id FROM SYS.OBJECTS AS O WITH (NOLOCK), SYS.SCHEMAS AS S WITH (NOLOCK) WHERE S.NAME = ''DBO'' AND S.SCHEMA_ID = O.SCHEMA_ID AND O.TYPE = ''U'' AND O.NAME LIKE ''T[0-9]%'')' "
    Invoke-DbaQuery -Query $sql -SqlInstance "." -database "AxDB" -QueryTimeout 0

    Write-Host "dropping DMF temp tables"
    $sql = "EXEC sp_msforeachtable
    @command1 ='drop table ?'
    ,@whereand = ' And Object_id In (Select Object_id FROM SYS.OBJECTS AS O WITH (NOLOCK), SYS.SCHEMAS AS S WITH (NOLOCK) WHERE S.NAME = ''DBO'' AND S.SCHEMA_ID = O.SCHEMA_ID AND O.TYPE = ''U'' AND O.NAME LIKE ''DMF[_][0-9a-zA-Z]%'')' "
    Invoke-DbaQuery -Query $sql -SqlInstance "." -database "AxDB" -QueryTimeout 0

    Write-Host "purging disposable large tables data"
    $LargeTables | ForEach-Object {
        $sql = "delete $_ where $_.CREATEDDATETIME < dateadd(""MM"", -2, getdate())"
        Invoke-DbaQuery -Query $sql -SqlInstance "." -database "AxDB" -QueryTimeout 0
    }

    $sql = "DELETE [REFERENCES] FROM [REFERENCES]
    JOIN Names ON (Names.Id = [REFERENCES].SourceId OR Names.Id = [REFERENCES].TargetId)
    JOIN Modules ON Names.ModuleId = Modules.Id
    WHERE Module LIKE '%Test%' AND Module <> 'TestEssentials'"

    Invoke-DbaQuery -Query $sql -SqlInstance "." -database "DYNAMICSXREFDB" -QueryTimeout 0

    Write-Host "Reclaiming freed database space"
    Invoke-DbaDbShrink -SqlInstance . -Database "AxDb", "DYNAMICSXREFDB" -FileType Data

    Write-Host "Running Ola Hallengren's IndexOptimize tool"
    # http://calafell.me/defragment-indexes-on-d365-finance-operations-virtual-machine/
    $sql = "EXECUTE master.dbo.IndexOptimize
        @Databases = 'ALL_DATABASES',
        @FragmentationLow = NULL,
        @FragmentationMedium = 'INDEX_REBUILD_OFFLINE',
        @FragmentationHigh = 'INDEX_REBUILD_OFFLINE',
        @FragmentationLevel1 = 5,
        @FragmentationLevel2 = 25,
        @LogToTable = 'N',
        @MaxDOP = 0,
        @Online = 'N',
        @UpdateStatistics = 'ALL',
        @OnlyModifiedStatistics = 'Y'"

    Execute-Sql -server "." -database "master" -command $sql

    Write-Host "Reclaiming database log space"
    Invoke-DbaDbShrink -SqlInstance . -Database "AxDb", "DYNAMICSXREFDB" -FileType Log -ShrinkMethod TruncateOnly

    $memoryForSqlServer = ($totalServerMemory * 0.15) / 1024 / 1024
    Set-DbaMaxMemory -SqlInstance . -Max $memoryForSqlServer
}
Else
{
    Write-Verbose "SQL not installed.  Skipped Ola Hallengren's index optimization"
}

#endregion



#region Update PowerShell Help, power settings

Write-Host "Updating PowerShell help"
$what = ""
Update-Help  -Force -Ea 0 -Ev what
If ($what)
{
    Write-Warning "Minor error when updating PowerShell help"
    Write-Host $what.Exception
}
#endregion



#region Configure Windows Updates when Windows 10

if ((Get-WmiObject Win32_OperatingSystem).Caption -Like "*Windows 10*")
{

    #Write-Host "Changing Windows Updates to -Notify to schedule restart-"
    #Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings -Name UxOption -Type DWord -Value 1

    Write-Host "Disabling P2P Update downlods outside of local network"
    Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config -Name DODownloadMode -Type DWord -Value 1
    Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization -Name SystemSettingsDownloadMode -Type DWord -Value 3
}

#endregion

