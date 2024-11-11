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
 # Tested on F&O 7.3 OneBox and F&O 8.1 OneBox and a 10.0.11 Azure Cloud Hosted Environment (CHE) deployed from LCS
 #
 # Ideas:
 #  Download useful SQL and PowerShell scripts, using Git?
 #>

#region Update visual studio
Get-Process devenv | Stop-Process -ErrorAction Ignore
dotnet nuget add source "https://api.nuget.org/v3/index.json" --name "nuget.org"
dotnet tool update -g dotnet-vs
$env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User") 
vs update --all
#endregion

#region install VS Addins
#region install TrudAX VS Addin
#$repo = "juliomutley/TRUDUtilsD365" # VS2019
$repo = "TrudAX/TRUDUtilsD365" # VS 2022
$releases = "https://api.github.com/repos/$repo/releases"
$path = "C:\Temp\Addin"

If (!(test-path $path)) {
    New-Item -ItemType Directory -Force -Path $path
}
Set-Location $path

Write-Host Determining latest release
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$tag = (Invoke-WebRequest -Uri $releases -UseBasicParsing | ConvertFrom-Json)[0].tag_name

$files = @("InstallToVS.exe", "TRUDUtilsD365.dll", "TRUDUtilsD365.pdb")

Write-Host Downloading files
foreach ($file in $files) {
    $download = "https://github.com/$repo/releases/download/$tag/$file"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest $download -Out $file
    Unblock-File $file
}
Start-Process "InstallToVS.exe" -Verb runAs

#endregion install TrudAX VS Addin

# Based on https://gist.github.com/ScottHutchinson/b22339c3d3688da5c9b477281e258400
# Based on http://nuts4.net/post/automated-download-and-installation-of-visual-studio-extensions-via-powershell

function Invoke-VSInstallExtension {
    param(
        [Parameter(Position=1)]
        [ValidateSet('2019','2022')]
        [System.String]$Version,  
    [String] $PackageName)
 
    $ErrorActionPreference = "Stop"
 
    $baseProtocol = "https:"
    $baseHostName = "marketplace.visualstudio.com"
 
    $Uri = "$($baseProtocol)//$($baseHostName)/items?itemName=$($PackageName)"
    $VsixLocation = "$($env:Temp)\$([guid]::NewGuid()).vsix"

    switch ($Version) {
        '2019' {
            $VSInstallDir = "C:\Program Files (x86)\Microsoft Visual Studio\Installer\resources\app\ServiceHub\Services\Microsoft.VisualStudio.Setup.Service"
        }
        '2022' {
            $VSInstallDir = "C:\Program Files\Microsoft Visual Studio\2022\Professional\Common7\IDE\"
        }
    }

    If ((test-path $VSInstallDir)) {

        Write-Host "Grabbing VSIX extension at $($Uri)"
        $HTML = Invoke-WebRequest -Uri $Uri -UseBasicParsing -SessionVariable session
    
        Write-Host "Attempting to download $($PackageName)..."
        $anchor = $HTML.Links |
        Where-Object { $_.class -eq 'install-button-container' } |
        Select-Object -ExpandProperty href

        if (-Not $anchor) {
            Write-Error "Could not find download anchor tag on the Visual Studio Extensions page"
            Exit 1
        }
        Write-Host "Anchor is $($anchor)"
        $href = "$($baseProtocol)//$($baseHostName)$($anchor)"
        Write-Host "Href is $($href)"
        Invoke-WebRequest $href -OutFile $VsixLocation -WebSession $session
    
        if (-Not (Test-Path $VsixLocation)) {
            Write-Error "Downloaded VSIX file could not be located"
            Exit 1
        }


        Write-Host "************    VSInstallDir is:  $($VSInstallDir)"
        Write-Host "************    VsixLocation is: $($VsixLocation)"
        Write-Host "************    Installing: $($PackageName)..."
        Start-Process -Filepath "$($VSInstallDir)\VSIXInstaller" -ArgumentList "/q /a $($VsixLocation)" -Wait

        Write-Host "Cleanup..."
        Remove-Item $VsixLocation -Force -Confirm:$false
    
        Write-Host "Installation of $($PackageName) complete!"
    }
}

Get-Process devenv -ErrorAction Ignore | Stop-Process -ErrorAction Ignore

Invoke-VSInstallExtension -Version 2019 -PackageName 'AlexPendleton.LocateinTFS2017'
Invoke-VSInstallExtension -Version 2022 -PackageName 'Zhenkas.LocateInTFS'
Invoke-VSInstallExtension -Version 2019 -PackageName 'cpmcgrath.Codealignment-2019'
Invoke-VSInstallExtension -Version 2022 -PackageName 'cpmcgrath.Codealignment'
Invoke-VSInstallExtension -Version 2019 -PackageName 'EWoodruff.VisualStudioSpellCheckerVS2017andLater'
Invoke-VSInstallExtension -Version 2022 -PackageName 'EWoodruff.VisualStudioSpellCheckerVS2022andLater'
Invoke-VSInstallExtension -Version 2019 -PackageName 'MadsKristensen.OpeninVisualStudioCode'
Invoke-VSInstallExtension -Version 2022 -PackageName 'MadsKristensen.OpeninVisualStudioCode'
Invoke-VSInstallExtension -Version 2019 -PackageName 'MadsKristensen.TrailingWhitespaceVisualizer'
Invoke-VSInstallExtension -Version 2022 -PackageName 'MadsKristensen.TrailingWhitespace64'
Invoke-VSInstallExtension -Version 2019 -PackageName 'ViktarKarpach.DebugAttachManager'
Invoke-VSInstallExtension -Version 2022 -PackageName 'ViktarKarpach.DebugAttachManager2022'

Write-Host "Installing TrudUtils"

$currentPath = Get-Location
#$repo = "juliomutley/TRUDUtilsD365" # VS2019
$repo = "TrudAX/TRUDUtilsD365" # VS 2022


$releases = "https://api.github.com/repos/$repo/releases"
$path = "C:\Temp\Addin"

If (!(test-path $path)) {
    New-Item -ItemType Directory -Force -Path $path
}
else {
    Get-ChildItem $path -Recurse | Remove-Item -Force -Confirm:$false
}

Set-Location $path

Write-Host Determining latest release
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$tag = (Invoke-WebRequest -Uri $releases -UseBasicParsing | ConvertFrom-Json)[0].tag_name

$files = @("InstallToVS.exe", "TRUDUtilsD365.dll", "TRUDUtilsD365.pdb")

Write-Host Downloading files
foreach ($file in $files) {
    $download = "https://github.com/$repo/releases/download/$tag/$file"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest $download -Out $file
    Unblock-File $file
}

# Accessing the Documents folder using environment variables
$documentsFolder = Join-Path $env:USERPROFILE 'Documents'

$xmlFilePath = "$documentsFolder\Visual Studio Dynamics 365\DynamicsDevConfig.xml"
$valueToCheck = "C:\Temp\Addin"

# Load the XML file
[xml]$xml = Get-Content -Path $xmlFilePath

# Check if the value exists
if (-not ($xml.DynamicsDevConfig.AddInPaths.string -contains $valueToCheck)) {
    # Value doesn't exist, add it
    $newElement = $xml.CreateElement("d2p1", "string", "http://schemas.microsoft.com/2003/10/Serialization/Arrays")
    $newElement.InnerText = $valueToCheck
    $xml.DynamicsDevConfig.AddInPaths.AppendChild($newElement)

    # Save the modified XML back to a file
    $xml.Save($xmlFilePath)
    Write-Host "Element added successfully."
}

Set-Location $currentPath

Write-Host "Installing Default Tools and Internal Dev tools"

$VSInstallDir = "C:\Program Files (x86)\Microsoft Visual Studio\Installer\resources\app\ServiceHub\Services\Microsoft.VisualStudio.Setup.Service"

Get-ChildItem "K:\DeployablePackages" -Include "*.vsix" -Exclude "*.17.0.vsix" -Recurse | ForEach-Object {
    Write-Host "installing: $_"
    Split-Path -Path $VSInstallDir -Leaf -Resolve
    Start-Process -Filepath "$($VSInstallDir)\VSIXInstaller" -ArgumentList "/q /a $_" -Wait
}

$VSInstallDir = "C:\Program Files\Microsoft Visual Studio\2022\Professional\Common7\IDE\"

Get-ChildItem "K:\DeployablePackages" -Include "*.17.0.vsix" -Recurse | ForEach-Object {
    Write-Host "installing: $_"
    Split-Path -Path $VSInstallDir -Leaf -Resolve
    Start-Process -Filepath "$($VSInstallDir)\VSIXInstaller" -ArgumentList "/q /a $_" -Wait
}
#endregion install VS Addins

#region run windows update
Install-PackageProvider NuGet -Force -Confirm:$false
Install-Module PSWindowsUpdate -Force -Confirm:$false
Install-WindowsUpdate -MicrosoftUpdate -AcceptAll -AutoReboot -Confirm:$false
#endregion

#region Update SSMS
# Set file and folder path for SSMS installer .exe
$folderpath = "c:\temp\SSMS_KB"
$PathExists = Test-Path($folderpath)
if ($PathExists -eq $false) {
    mkdir $folderpath
}
$filepath = "$folderpath\SSMS-Setup-ENU.exe"

#If SSMS not present, download
if (!(Test-Path $filepath)) {
    write-host "Downloading SQL Server SSMS..."
    $URL = "https://aka.ms/ssmsfullsetup"
    $clnt = New-Object System.Net.WebClient
    $clnt.DownloadFile($url, $filepath)
    Write-Host "SSMS installer download complete" -ForegroundColor Green

}
else {

    write-host "Located the SQL SSMS Installer binaries, moving on to install..."
}

# start the SSMS installer
write-host "Beginning SSMS install..." -nonewline
$Parms = " /Install /Quiet /Norestart /Logs log.txt"
$Prms = $Parms.Split(" ")
& "$filepath" $Prms | Out-Null

Remove-Item $folderpath -Recurse -Force -Confirm:$false
Write-Host "SSMS installation complete" -ForegroundColor Green
#endregion

#region Installing powershell modules
# This is requried by Find-Module, by doing it beforehand we remove some warning messages
Set-PSRepository -Name PSGallery -InstallationPolicy Trusted

# Installing powershell modules
$Module2Service = $('Az'
    ,'dbatools'
    ,'d365fo.tools'
    , 'SqlServer')

$Module2Service | ForEach-Object {
    if (Get-Module -ListAvailable -Name $_) {
        Write-Host "Updating " + $_
        Update-Module -Name $_ -Force
    } 
    else {
        Write-Host "Installing " + $_
        Install-Module -Name $_ -SkipPublisherCheck -Scope AllUsers -AllowClobber -Force
        Import-Module $_
    }
}
#endregion

Install-D365SupportingSoftware -Name "7zip", "adobereader", "azure-data-studio", "dotnetcore", "fiddler", "git.install", "notepadplusplus.install", "postman", "sysinternals", "vscode", "powertoys"

$env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User") 

#region vscode extensions
$vsCodeExtensions = @(
    "adamwalzer.string-converter"
    ,"DotJoshJohnson.xml"
    ,"IBM.output-colorizer"
    ,"mechatroner.rainbow-csv"
    ,"ms-vscode.PowerShell"
    ,"piotrgredowski.poor-mans-t-sql-formatter-pg"
    ,"streetsidesoftware.code-spell-checker"
    ,"ZainChen.json"
)

$vsCodeExtensions | ForEach-Object {
    code --install-extension $_
}
#endregion

Write-Host "Setting web browser homepage to the local environment"
Get-D365Url | Set-D365StartPage

$registryPath = 'HKLM:\Software\Policies\Microsoft\Edge' 
$regpath = 'HKLM:\Software\Policies\Microsoft\Edge\RestoreOnStartupURLs' 
$value = 0x00000004 
$URL = (Get-D365Url).Url

if(!(Test-Path $registryPath)) 
{ 
    New-Item -Path $registryPath -Force | Out-Null 
    New-ItemProperty -Path $registryPath -Name RestoreOnStartup -Value $value -PropertyType DWORD -Force | Out-Null
} 
ELSE 
{
    New-ItemProperty -Path $registryPath -Name RestoreOnStartup -Value $value -PropertyType DWORD -Force | Out-Null
} 

Set-Location $registrypath 
New-Item -Name RestoreOnStartupURLs -Force 
Set-Itemproperty -Path $regpath -Name 1 -Value $URL

Write-Host "The homepage has been set as: $URL" 

Write-Host "Setting Management Reporter to manual startup to reduce churn and Event Log messages"
Get-D365Environment -FinancialReporter | Set-Service -StartupType Manual

Write-Host "Setting Windows Defender rules to speed up compilation time"
Add-D365WindowsDefenderRules -Silent

#region Local User Policy

# Set the password to never expire
Get-WmiObject Win32_UserAccount -filter "LocalAccount=True" | Where-Object { $_.SID -Like "S-1-5-21-*-500" } | Set-LocalUser -PasswordNeverExpires 1

# Disable changing the password
$registryPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
$name = "DisableChangePassword"
$value = "1"

If (!(Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
    New-ItemProperty -Path $registryPath -Name $name -Value $value -PropertyType DWORD -Force | Out-Null
}
Else {
    $passwordChangeRegKey = Get-ItemProperty -Path $registryPath -Name $Name -ErrorAction SilentlyContinue

    If (-Not $passwordChangeRegKey) {
        New-ItemProperty -Path $registryPath -Name $name -Value $value -PropertyType DWORD -Force | Out-Null
    }
    Else {
        Set-ItemProperty -Path $registryPath -Name $name -Value $value
    }
}

#endregion

#region Privacy

# Disable Windows Telemetry (requires a reboot to take effect)
Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection -Name AllowTelemetry -Type DWord -Value 0
Get-Service DiagTrack, Dmwappushservice | Stop-Service | Set-Service -StartupType Disabled

# Start Menu: Disable Bing Search Results
Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search -Name BingSearchEnabled -Type DWord -Value 0


# Start Menu: Disable Cortana
If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings")) {
    New-Item -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Type DWord -Value 0
If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization")) {
    New-Item -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Type DWord -Value 1
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Type DWord -Value 1
If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore")) {
    New-Item -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Type DWord -Value 0
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Type DWord -Value 0

#endregion


#region Install and run Ola Hallengren's IndexOptimize

Function Execute-Sql {
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

        try {
            $scon.Open()
            $cmd.ExecuteNonQuery()
        }
        catch [Exception] {
            Write-Warning $_.Exception.Message
        }
        finally {
            $scon.Dispose()
            $cmd.Dispose()
        }
    }
}

If (Test-Path "HKLM:\Software\Microsoft\Microsoft SQL Server\Instance Names\SQL") {

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
    if ($PathExists -eq $false) {
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

    Write-Host "Setting batchservergroup options"
    $sql = "delete batchservergroup where SERVERID <> 'Batch:'+@@servername

    insert into batchservergroup(GROUPID, SERVERID, RECID, RECVERSION, CREATEDDATETIME, CREATEDBY)
    select GROUP_, 'Batch:'+@@servername, 5900000000 + cast(CRYPT_GEN_RANDOM(4) as bigint), 1, GETUTCDATE(), '-admin-' from batchgroup
        where not EXISTS (select recid from batchservergroup where batchservergroup.GROUPID = batchgroup.GROUP_)"
    Invoke-DbaQuery -Query $sql -SqlInstance "." -database "AxDB" -QueryTimeout 0

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

    Write-Host "dropping oledb error tmp tables"
    $sql = "EXEC sp_msforeachtable 
    @command1 ='drop table ?'
    ,@whereand = ' And Object_id In (Select Object_id FROM SYS.OBJECTS AS O WITH (NOLOCK), SYS.SCHEMAS AS S WITH (NOLOCK) WHERE S.NAME = ''DBO'' AND S.SCHEMA_ID = O.SCHEMA_ID AND O.TYPE = ''U'' AND O.NAME LIKE ''DMF_OLEDB_Error_%'')' "
    Invoke-DbaQuery -Query $sql -SqlInstance "." -database "AxDB" -QueryTimeout 0

    $sql = "EXEC sp_msforeachtable 
    @command1 ='drop table ?'
    ,@whereand = ' And Object_id In (Select Object_id FROM SYS.OBJECTS AS O WITH (NOLOCK), SYS.SCHEMAS AS S WITH (NOLOCK) WHERE S.NAME = ''DBO'' AND S.SCHEMA_ID = O.SCHEMA_ID AND O.TYPE = ''U'' AND O.NAME LIKE ''DMF_FLAT_Error_%'')' "
    Invoke-DbaQuery -Query $sql -SqlInstance "." -database "AxDB" -QueryTimeout 0

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
        @FragmentationMedium = 'INDEX_REORGANIZE,INDEX_REBUILD_ONLINE,INDEX_REBUILD_OFFLINE',
        @FragmentationHigh = 'INDEX_REBUILD_ONLINE,INDEX_REBUILD_OFFLINE',
        @FragmentationLevel1 = 5,
        @FragmentationLevel2 = 25,
        @LogToTable = 'N',
        @MaxDOP = 0,
        @Sort_in_TempDB = 'Y',
        @Online = 'N',
        @UpdateStatistics = 'ALL',
        @OnlyModifiedStatistics = 'Y'"

    Execute-Sql -server "." -database "master" -command $sql

    Write-Host "Reclaiming database log space"
    Invoke-DbaDbShrink -SqlInstance . -Database "AxDb", "DYNAMICSXREFDB" -FileType Log -ShrinkMethod TruncateOnly

    $memoryForSqlServer = ($totalServerMemory * 0.15) / 1024 / 1024
    Set-DbaMaxMemory -SqlInstance . -Max $memoryForSqlServer
}
Else {
    Write-Verbose "SQL not installed.  Skipped Ola Hallengren's index optimization"
}

#endregion


#region Update PowerShell Help, power settings

Write-Host "Updating PowerShell help"
$what = ""
Update-Help  -Force -Ea 0 -Ev what
If ($what) {
    Write-Warning "Minor error when updating PowerShell help"
    Write-Host $what.Exception
}

# Set power settings to High Performance
Write-Host "Setting power settings to High Performance"
powercfg.exe /SetActive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
#endregion


#region Configure Windows Updates when Windows 10

if ((Get-WmiObject Win32_OperatingSystem).Caption -Like "*Windows 10*") {

    #Write-Host "Changing Windows Updates to -Notify to schedule restart-"
    #Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings -Name UxOption -Type DWord -Value 1

    Write-Host "Disabling P2P Update downlods outside of local network"
    Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config -Name DODownloadMode -Type DWord -Value 1
    Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization -Name SystemSettingsDownloadMode -Type DWord -Value 3
}

#endregion
