param(
    [Parameter(Mandatory)]
    [String] $ConfigurationDataFile
) 
#Begin Function Region

function Create-Variables {
    param ()
    #Set Variables from Config File
Get-Content $ConfigurationDataFile
$config=Import-PowerShellDataFile -Path $ConfigurationDataFile 

Write-Host -ForegroundColor Green -Object $WelcomeMessage

Login-AzAccount

Select-AzSubscription -Subscription $config.AzureSubID
$ServerList = $config.Node01, $config.Node02

#Set AD Domain Cred
$AzDJoin = Get-AzKeyVaultSecret -VaultName 'KV' -Name "DomainJoinerSecret"
$ADcred = [pscredential]::new("contoso\djoiner",$AZDJoin.SecretValue)
#$ADpassword = ConvertTo-SecureString "" -AsPlainText -Force
#$ADCred = New-Object System.Management.Automation.PSCredential ("contoso\djoiner", $ADpassword)

#Set Cred for AAD tenant and subscription
$AADAccount = "azstackadmin@contoso.onmicrosoft.com"
$AADAdmin=Get-AzKeyVaultSecret -VaultName 'KV' -Name "AADAdmin"
$AADCred = [pscredential]::new("azstackadmin@contoso.onmicrosoft.com",$AADAdmin.SecretValue)
$Arcsecretact=Get-AzKeyVaultSecret -VaultName "KV" -Name "AzureArc-for-HCI"
$ARCSecret=$arcsecretact.SecretValue
}


function ConfigureWorkstation {
    param ()
    Write-Host -ForegroundColor Green -Object "Configuring Managment Workstation"

    #Set WinRM for remote management of nodes
    winrm quickconfig
    Enable-WSManCredSSP -Role Client -DelegateComputer * -Force
    New-Item hklm:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\AllowFreshCredentialsWhenNTLMOnly
    New-ItemProperty hklm:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\AllowFreshCredentialsWhenNTLMOnly -Name 1 -Value "wsman/*" -Force 

    Write-Host -ForegroundColor Green -Object "Installing Required Features on Management Workstation"

    If ((get-computerinfo).windowsinstallationtype -eq "client"){
        Enable-WindowsOptionalFeature -FeatureName "Microsoft-Hyper-V-Management-PowerShell"  -Online 
        }
        
        else {
        #Install some PS modules if not already installed
        Install-WindowsFeature -Name RSAT-Clustering,RSAT-Clustering-Mgmt,RSAT-Clustering-PowerShell,RSAT-Hyper-V-Tools;
        Install-Module AZ.ConnectedMachine -force
        }


}

function Configure-Nodes {
    param ()
    Write-Host -ForegroundColor Green "Configuring Nodes"

#Add features, add PS modules, rename, join domain, reboot
Invoke-Command -ComputerName $ServerList -Credential $ADCred -ScriptBlock {
    Install-WindowsFeature -Name "BitLocker", "Data-Center-Bridging", "Failover-Clustering", "FS-FileServer", "FS-Data-Deduplication", "Hyper-V", "Hyper-V-PowerShell", "RSAT-AD-Powershell", "RSAT-Clustering-Powershell","FS-Data-Deduplication", "Storage-Replica", "NetworkATC", "System-Insights" -IncludeAllSubFeature -IncludeManagementTools
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
    Install-Module -Name Az.StackHCI -Force -All
    Enable-WSManCredSSP -Role Server -Force
    New-NetFirewallRule -DisplayName “ICMPv4” -Direction Inbound -Action Allow -Protocol icmpv4 -Enabled True
    Enable-NetFirewallRule -DisplayGroup “Remote Desktop”
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" –Value 0
    Set-TimeZone -Name "Central Standard Time" 
}
     
Restart-Computer -ComputerName $ServerList -Protocol WSMan -Wait -For PowerShell -Force

#Pause for a bit - let changes apply before moving on...
Start-Sleep 180
    
}

function Configure-Node01 {
    param ()
    Write-Host -ForegroundColor Green -Object "Configure Node 01"

Invoke-Command -ComputerName $config.Node01 -Credential $ADCred -ScriptBlock {

# Configure IP and subnet mask, no default gateway for Storage interfaces
    #MGMT
    New-NetIPAddress -InterfaceAlias "LOM2 Port3" -IPAddress $using:config.node01_MgmtIP -PrefixLength 24 -DefaultGateway $using:config.GWIP  | Set-DnsClientServerAddress -ServerAddresses $using:config.DNSIP
    #Storage 
    New-NetIPAddress -InterfaceAlias "LOM1 Port1" -IPAddress 172.16.0.1 -PrefixLength 24
    New-NetIPAddress -InterfaceAlias "LOM1 Port2" -IPAddress 172.16.1.1 -PrefixLength 24
    Get-NetAdapter -Name Ethernet | Disable-NetAdapter -Confirm:$false
}
}

function Configure-Node02 {
    param ()
    Write-Host -ForegroundColor Green -Object "Configure Node02"

Invoke-Command -ComputerName $config.Node02 -Credential $ADCred -ScriptBlock {
    # Configure IP and subnet mask, no default gateway for Storage interfaces
    #MGMT
    New-NetIPAddress -InterfaceAlias "LOM2 Port3" -IPAddress $using:config.node02_MgmtIP -PrefixLength 24 -DefaultGateway $using:config.GWIP| Set-DnsClientServerAddress -ServerAddresses $using:config.DNSIP
    #Storage 
    New-NetIPAddress -InterfaceAlias "LOM1 Port1" -IPAddress 172.16.0.2 -PrefixLength 24
    New-NetIPAddress -InterfaceAlias "LOM1 Port2" -IPAddress 172.16.1.2 -PrefixLength 24
    Get-NetAdapter -Name Ethernet | Disable-NetAdapter -Confirm:$false
}
}

function Prepare-Storage {
    param ()
    Write-Host -ForegroundColor Green -Object "Prepare Storage"

#Clear Storage
Invoke-Command ($ServerList) {
    Update-StorageProviderCache
    Get-StoragePool | ? IsPrimordial -eq $false | Set-StoragePool -IsReadOnly:$false -ErrorAction SilentlyContinue
    Get-StoragePool | ? IsPrimordial -eq $false | Get-VirtualDisk | Remove-VirtualDisk -Confirm:$false -ErrorAction SilentlyContinue
    Get-StoragePool | ? IsPrimordial -eq $false | Remove-StoragePool -Confirm:$false -ErrorAction SilentlyContinue
    Get-PhysicalDisk | Reset-PhysicalDisk -ErrorAction SilentlyContinue
    Get-Disk | ? Number -ne $null | ? IsBoot -ne $true | ? IsSystem -ne $true | ? PartitionStyle -ne RAW | % {
        $_ | Set-Disk -isoffline:$false
        $_ | Set-Disk -isreadonly:$false
        $_ | Clear-Disk -RemoveData -RemoveOEM -Confirm:$false
        $_ | Set-Disk -isreadonly:$true
        $_ | Set-Disk -isoffline:$true
    }
    Get-Disk | Where Number -Ne $Null | Where IsBoot -Ne $True | Where IsSystem -Ne $True | Where PartitionStyle -Eq RAW | Group -NoElement -Property FriendlyName
} | Sort -Property PsComputerName, Count
}

function Create-Cluster {
    param ()
    Write-Host -ForegroundColor Green -Object "Creating the Cluster"

#Create the Cluster
#Test-Cluster –Node $config.Node01, $config.Node02 –Include "Storage Spaces Direct", "Inventory", "Network", "System Configuration"
New-Cluster -Name $config.ClusterName -Node $config.Node01, $config.Node02 -StaticAddress $config.ClusterIP -NoStorage 

#Pause for a bit then clear DNS cache.
Start-Sleep 30
Clear-DnsClientCache

# Update the cluster network names that were created by default.  First, look at what's there
Get-ClusterNetwork -Cluster $config.ClusterName  | ft Name, Role, Address

# Change the cluster network names so they are consistent with the individual nodes
(Get-ClusterNetwork -Cluster $config.ClusterName  | where-object address -like "172.16.0.0").Name = "Storage1"
(Get-ClusterNetwork -Cluster $config.ClusterName  | where-object address -like "172.16.1.0").Name = "Storage2"
#(Get-ClusterNetwork -Cluster $config.ClusterName  | where-object address -like "").Name = "OOB"
(Get-ClusterNetwork -Cluster $config.ClusterName  | where-object address -like $config.MGMTSubnet).Name = "MGMT"

# Check to make sure the cluster network names were changed correctly
Get-ClusterNetwork -Cluster $config.ClusterName | ft Name, Role, Address
}

function Set-LiveMigration {
    parama()
    Write-Host -ForegroundColor Green -Object "Set Cluster Live Migration Settings"

#Set Cluster Live Migration Settings 
Enable-VMMigration -ComputerName $ServerList
Add-VMMigrationNetwork -computername $ServerList -Subnet 172.16.0.0/24 -Priority 1 
Add-VMMigrationNetwork -computername $ServerList -Subnet 172.16.1.0/24 -Priority 2 
Set-VMHost -ComputerName $ServerList -MaximumStorageMigrations 2 -MaximumVirtualMachineMigrations 2 -VirtualMachineMigrationPerformanceOption SMB -UseAnyNetworkForMigration $false 

}

function Deploy-S2D {
    param ()
    Write-Host -ForegroundColor Green -Object "Enable Storage Spaces Direct"

#Enable S2D
Enable-ClusterStorageSpacesDirect  -CimSession $config.ClusterName -PoolFriendlyName $config.StoragePoolName -Confirm:0 

}

function Enable-CAU {
parama()
#############Enable CAU and update to latest 21H2 bits...###############
#First we must add the AD cluster object to the Cluster Objects AD Group
$ADClusterObj = $config.ClusterName + "$"
Add-ADGroupMember -Identity ClusterObjects -Members $ADClusterObj
#Now we can add the CAU role...
Add-CauClusterRole -ClusterName $config.ClusterName -MaxFailedNodes 0 -RequireAllNodesOnline -EnableFirewallRules -Force -CauPluginName Microsoft.WindowsUpdatePlugin -MaxRetriesPerNode 3 -CauPluginArguments @{ 'IncludeRecommendedUpdates' = 'False' } -StartDate "3/2/2017 3:00:00 AM" -DaysOfWeek 4 -WeeksOfMonth @(3) -verbose


#Enable KSR on ALl and Future CAU 
Get-Cluster -Name $config.ClusterName | Set-ClusterParameter -Name CauEnableSoftReboot -Value 1 -Create

#Now we can force an update...
Invoke-CauRun -ClusterName $config.ClusterName -CauPluginName "Microsoft.WindowsUpdatePlugin" -MaxFailedNodes 1 -MaxRetriesPerNode 3 -RequireAllNodesOnline -Force


}

function Confirm-FunctionLevels {
    param ()
    #Update Cluster Function Level

$cfl=Get-Cluster -Name $config.ClusterName 
if ($cfl.ClusterFunctionalLevel -lt "12") {
write-host -ForegroundColor yellow -Object "Cluster Functional Level needs to be upgraded"  

Update-ClusterFunctionalLevel -Cluster $config.ClusterName -Verbose -Force
}

else {
write-host -ForegroundColor Green -Object "Cluster Functional Level is good"

}

#storage Pool Level check and upgrade

$spl=Get-StoragePool -CimSession $config.ClusterName -FriendlyName $config.StoragePoolName
 
if ($spl.version -ne "Windows Server 2022") {
write-host -ForegroundColor yellow -Object "Storage Pool Level needs to be upgraded"

Update-StoragePool -FriendlyName $config.StoragePoolName -Confirm:0 -CimSession $config.Node01
}
else {
write-host -ForegroundColor Green -Object "Storage Pool level is set to Windows Server 2022"
}
    
}

function Create-CSV {
    param ()
    write-host -ForegroundColor Green -Object "Creating Cluster Shared Volume"

#Create S2D Tier and Volumes
New-StorageTier -StoragePoolFriendlyName $config.StoragePoolName -FriendlyName 2WayNestedMirror -ResiliencySettingName Mirror -MediaType SSD -NumberOfDataCopies 4 -CimSession $config.ClusterName ;

New-Volume -StoragePoolFriendlyName $config.StoragePoolName -FriendlyName Volume01 -StorageTierFriendlyNames 2WayNestedMirror -StorageTierSizes $config.CSVSize -CimSession $config.ClusterName 
 

}

function Create-CloudWitness{
    param()
    write-host -ForegroundColor Green -Object "Set Cloud Witness"

#Set Cloud Witness
Set-ClusterQuorum -Cluster $config.ClusterName -Credential $AADCred -CloudWitness -AccountName $CWStorageAccount  -AccessKey $CWStoageKey


}

function Set-NetIntents {
    param()
    write-host -ForegroundColor Green -Object "Setting NetworkATC Configuration"

Invoke-Command -ComputerName $config.Node01 -Credential $ADcred -Authentication Credssp {

#North-South Net-Intents
Add-NetIntent -ClusterName $using:config.ClusterName -AdapterName "LOM2 Port3", "LOM2 Port4" -Name HCI -Compute -Management  

#Storage NetIntent
Add-NetIntent -ClusterName $using:config.ClusterName -AdapterName "LOM1 Port1", "LOM1 Port2"  -Name SMB -Storage
}

start-sleep 30 

Start-ClusterResource -Cluster $config.ClusterName -Name "Cluster IP Address"

write-host -ForegroundColor Green -Object "Testing to ensure Cluster IP is online" 

$tnc_clip=Test-NetConnection $config.ClusterIP
if ($tnc_clip.pingsucceded -eq "true") {
    write-host -ForegroundColor Green -Object "Cluster in online, NetworkATC was successful"
}

elseif ($tnc_clip.pingsucceded -eq "false") {
    Start-ClusterResource -Cluster $config.ClusterName -Name Cluster IP Address
   Start-Sleep 15
}
 
 $tnc_clip2=Test-NetConnection $config.ClusterIP

if ( $tnc_clip2.pingsucceded -eq "true") {

write-host -ForegroundColor Green -Object "Cluster in online, NetworkATC was successful"
}

else {

Write-Host -ForegroundColor Red -Object "Please ensure Cluster Resources are online and Network configration is correct on nodes";

    Start-Sleep 180
}
}

function register-hcicluster {
param()
write-host -ForegroundColor Green -Object "Register the Cluster to Azure Subscription"

#Register Cluster with Azure

#Register Cluster with Azure
Invoke-Command -ComputerName $config.Node01 {
    Connect-AzAccount -Credential $using:AADCred
    $armtoken = Get-AzAccessToken
    $graphtoken = Get-AzAccessToken -ResourceTypeName AadGraph
    Register-AzStackHCI -SubscriptionId $using:config.AzureSubID -ComputerName $using:config.Node01 -AccountId $using:AADAccount -ArmAccessToken $armtoken.Token -GraphAccessToken $graphtoken.Token -EnableAzureArcServer -Credential $using:ADCred -Region "East US" -ResourceName $using:config.ClusterName
    }

}

function Deploy-AKS {
    param ()


}

#End Function Region

#Begin Main Region

<#---------------------------------------------------------------------------------------------------------------#>

# Main execution begins here

$orginalErrorAction = $ErrorActionPreference
$ErrorActionPreference = "Inquire"

$logFile = ('.\ExecutionTranscript.log')
Start-Transcript -Path $logFile -Append

try 
{
    Initialize-Variables
    $progressLog = Get-Content -Path '.\progress.log'

    $currentStepName = 'Init'
    $currentStepIndex = 0

    do 
    {
        if ($progressLog[$currentStepIndex].Contains("Pending"))
        {
            $currentStepName = ($progressLog[$currentStepIndex].Split())[0]
            Invoke-Expression -Command $currentStepName
        }
        $currentStepIndex++
        $progressLog = Get-Content -Path '.\progress.log' -Force
    }
    until ( $progressLog[$currentStepIndex] -eq "Done" )

}
finally 
{
    Stop-Transcript
    $ErrorActionPreference = $orginalErrorAction
}





