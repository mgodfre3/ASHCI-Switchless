<#
.SYNOPSIS 
    Deploys and configures a 2 node Lenovo SE350 Azure Stack HCI Cluster for a Proof of Concept.
.EXAMPLE
    .\Deploy_AZSHCI.ps1 -ConfigurationFile .\deploy_config.psd1

.NOTES
    Prerequisites:
    *This script should be run from a Jump Workstation, with network communication to the ASHCI Physical Nodes that will be configured"
     
    * You will be asked to login to your Azure Subscription, as this will allow credentials from Azure Key Vault to be utilized.
    
    *The AD Group "Fabric Admins" needs to be made local admin on the Hosts.  
    
    *You must provide the Configuraiton variables in the attached Config file and supply it as a paramter.

    *You will need to configure AD and Service Principal Secrets in an Azure Key Vault in the same subscription. 
#>

param(
    [Parameter(Mandatory)]
    [String] $ConfigurationDataFile
) 

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

###############################################################################################################################

Write-Host -ForegroundColor Green -Object "Configuring Managment Workstation"

#Set WinRM for remote management of nodes
winrm quickconfig
Enable-WSManCredSSP -Role Client -DelegateComputer * -Force
#New-Item hklm:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\AllowFreshCredentialsWhenNTLMOnly
#New-ItemProperty hklm:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\AllowFreshCredentialsWhenNTLMOnly -Name 1 -Value "wsman/*" -Force

###############################################################################################################################
Write-Host -ForegroundColor Green -Object "Installing Required Features on Management Workstation"

#Install some PS modules if not already installed
Install-WindowsFeature -Name RSAT-Clustering,RSAT-Clustering-Mgmt,RSAT-Clustering-PowerShell,RSAT-Hyper-V-Tools;
Install-Module AZ.ConnectedMachine -force

##########################################Configure Nodes####################################################################

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

###############################################################################################################################

##################################################Configure Node01#############################################################
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

############################################################Configure Node02#############################################################
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

#########################################################################################################################################

#########################################################Configure HCI Cluster##########################################################

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

#########################################################################################################################################
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

#########################################################################################################################################
Write-Host -ForegroundColor Green -Object "Set Cluster Live Migration Settings"

#Set Cluster Live Migration Settings 
Enable-VMMigration -ComputerName $ServerList
Add-VMMigrationNetwork -computername $ServerList -Subnet 172.16.0.0/24 -Priority 1 
Add-VMMigrationNetwork -computername $ServerList -Subnet 172.16.1.0/24 -Priority 2 
Set-VMHost -ComputerName $ServerList -MaximumStorageMigrations 2 -MaximumVirtualMachineMigrations 2 -VirtualMachineMigrationPerformanceOption SMB -UseAnyNetworkForMigration $false 

#########################################################################################################################################
Write-Host -ForegroundColor Green -Object "Enable Storage Spaces Direct"

#Enable S2D
Enable-ClusterStorageSpacesDirect  -CimSession $config.ClusterName -PoolFriendlyName $config.StoragePoolName -Confirm:0 

#########################################################################################################################################

#############Configure for 21H2 Preview Channel###############
Invoke-Command ($ServerList) {
    Set-WSManQuickConfig -Force
    Enable-PSRemoting
    Set-NetFirewallRule -Group "@firewallapi.dll,-36751" -Profile Domain -Enabled true
    Set-PreviewChannel
}

Restart-Computer -ComputerName $ServerList -Protocol WSMan -Wait -For PowerShell -Force
#Pause for a bit - let changes apply before moving on...
Start-Sleep 180

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

##########################################################################################################

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

#########################################################################################################################################
write-host -ForegroundColor Green -Object "Creating Cluster Shared Volume"

#Create S2D Tier and Volumes
New-StorageTier -StoragePoolFriendlyName $config.StoragePoolName -FriendlyName 2WayNestedMirror -ResiliencySettingName Mirror -MediaType SSD -NumberOfDataCopies 4 -CimSession $config.ClusterName ;

New-Volume -StoragePoolFriendlyName $config.StoragePoolName -FriendlyName Volume01 -StorageTierFriendlyNames 2WayNestedMirror -StorageTierSizes $config.CSVSize -CimSession $config.ClusterName 
 


#########################################################################################################################################
write-host -ForegroundColor Green -Object "Set Cloud Witness"

#Set Cloud Witness
Set-ClusterQuorum -Cluster $config.ClusterName -Credential $AADCred -CloudWitness -AccountName hciwitness  -AccessKey "lj7LGQrmkyDoMH2AnHXQjp8EI+gWMPsKDYmMBv1mL7Ldo0cwz+aYIoDA8fO3hJoSyY/fUksiOWlZ/8Heme1XGw=="

#########################################################################################################################################

############################################################Set Net-Intent########################################################
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

#########################################################################################################################################

write-host -ForegroundColor Green -Object "Register the Cluster to Azure Subscription"

#Register Cluster with Azure

#Register Cluster with Azure
Invoke-Command -ComputerName $config.Node01 {
    Connect-AzAccount -Credential $using:AADCred
    $armtoken = Get-AzAccessToken
    $graphtoken = Get-AzAccessToken -ResourceTypeName AadGraph
    Register-AzStackHCI -SubscriptionId $using:config.AzureSubID -ComputerName $using:config.Node01 -AccountId $using:AADAccount -ArmAccessToken $armtoken.Token -GraphAccessToken $graphtoken.Token -EnableAzureArcServer -Credential $using:ADCred -Region "East US" -ResourceName $using:config.ClusterName
    }

<#
Old, just keeping for archive reasons
Invoke-Command -ComputerName $config.Node01 -Credential $ADcred -Authentication Credssp -ScriptBlock {
    Connect-AzAccount -Credential $using:AADCred
    Select-AzSubscription -Subscription $using:config.AzureSubID
    $armtoken = Get-AzAccessToken
    $graphtoken = Get-AzAccessToken -ResourceTypeName AadGraph
    $tenantid=(Get-AzTenant).TenantId
    $resourcegroupname=New-AzResourceGroup -Name $using:config.ClusterName -Location 'East US' 
    Register-AzStackHCI -SubscriptionId $using:config.AzureSubID -ComputerName $using:config.Node01 -AccountId $using:AADAccount -ArmAccessToken $armtoken.Token'
     -GraphAccessToken $graphtoken.Token -EnableAzureArcServer -Credential $using:ADCred -Region $resourcegroupname.Location -ResourceName $using:config.clustername'
     -TenantId $tenantid -ResourceGroupName $resourcegroupname.ResourceGroupName
  }
  #>  


<#  Seems that registration does now work with also installing Arc on the hosts as it should so commenting all of the below out for now #
############################################################################################################################################
function InstallArcAgent{

# Add the service principal application ID and secret here
$servicePrincipalClientId="3e69bf6c-0679-41d8-ba2f-342130b6f003"

#obtain SPN Secret
$AzureArcReg = Get-AzKeyVaultSecret -VaultName 'KV' -Name "AzureARCReg"
$ssptr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($AzureArcReg.SecretValue)
$servicePrincipalSecret = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($ssptr)

Invoke-Command -ComputerName $ServerList -ScriptBlock{

# Download the package
function download() {$ProgressPreference="SilentlyContinue"; Invoke-WebRequest -Uri https://aka.ms/AzureConnectedMachineAgent -OutFile AzureConnectedMachineAgent.msi}
download


# Install the package
$exitCode = (Start-Process -FilePath msiexec.exe -ArgumentList @("/i", "AzureConnectedMachineAgent.msi" ,"/l*v", "installationlog.txt", "/qn") -Wait -Passthru).ExitCode
if($exitCode -ne 0) {
    $message=(net helpmsg $exitCode)
    throw "Installation failed: $message See installationlog.txt for additional details."
}

# Run connect command
& "$env:ProgramW6432\AzureConnectedMachineAgent\azcmagent.exe" connect --service-principal-id "$using:servicePrincipalClientId" --service-principal-secret "$using:servicePrincipalSecret" --resource-group "$using:config.clustername" --tenant-id "ebc762d5-57e5-4ed1-9b32-a9524c3396b6" --location "eastus" --subscription-id "0c6c3a0d-0866-4e68-939d-ef81ca6f802e" --cloud "AzureCloud" --tags "City='Nashville'" --correlation-id "c2de33f9-2186-4754-a8bc-33dedd20104a"

if($LastExitCode -eq 0){Write-Host -ForegroundColor yellow "To view your onboarded server(s), navigate to https://portal.azure.com/#blade/HubsExtension/BrowseResource/resourceType/Microsoft.HybridCompute%2Fmachines"}

}

}

######################################################################################################################################################################

write-host -ForegroundColor Green -Object "Register the Azure ARC Agent on each node"

$rg=Get-AzResourceGroup | where ResourceGroupName -Like $config.ClusterName

#Node01 ARC Agent Check

$arm_machine_node01=ForEach ($r in $rg.resourcegroupname) {Get-AzConnectedMachine -Name $config.Node01 -ResourceGroupName $r}


if ($arm_machine_node01.Status -eq "Connected") { 
Write-host -ForegroundColor Green -Object "$config.node01 is connected to ARC...Horray!"
} 
else {
InstallARCAgent
}

#Node02 ARC Agent Check

$rg_node2=Get-AzResourceGroup | where ResourceGroupName -Like $config.ClusterName

$arm_machine_node02=ForEach ($r in $rg.resourcegroupname) {Get-AzConnectedMachine -Name $using:config.Node02 -ResourceGroupName $r}


if ($arm_machine_node02.Status -eq "Connected") { 
Write-host -ForegroundColor Green -Object "$config.node02 is connected to ARC...Horray!"
}
else {
InstallARCAgent
}
#>
##################################Install AKS-HCI#####################################################################


#Install latest versions of Nuget and PowershellGet
If ($config.AKSInstall -eq $true) {
    
    Enable-WSManCredSSP -Role Client -DelegateComputer $ServerList -Force

    Invoke-Command -ComputerName $ServerList -Authentication Credssp -Credential $ADCred -ScriptBlock {
        Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted
        Install-PackageProvider -Name NuGet -Force 
        Install-Module -Name PowershellGet -Force -Confirm:$false
        }
        
    #Install necessary AZ modules plus AksHCI module and initialize akshci on each node
    Invoke-Command -ComputerName $ServerList -Authentication Credssp -Credential $ADCred -ScriptBlock {
        Install-Module -Name Az.Accounts -Repository PSGallery -RequiredVersion 2.2.4 -Force
        Install-Module -Name Az.Resources -Repository PSGallery -RequiredVersion 3.2.0 -Force
        Install-Module -Name AzureAD -Repository PSGallery -RequiredVersion 2.0.2.128 -Force
        Install-Module -Name AksHci -Repository PSGallery -Force -AcceptLicense
        Import-Module Az.Accounts
        Import-Module Az.Resources
        Import-Module AzureAD
        Import-Module AksHci
        Initialize-akshcinode
        }
    
    #Install AksHci - only need to perform the following on one of the nodes
    Invoke-Command -ComputerName $config.Node01 -Authentication Credssp -Credential $ADCred -ScriptBlock {
        $vnet = New-AksHciNetworkSetting -name $using:config.AKSvnetname -vSwitchName $using:config.AKSvSwitchName -k8sNodeIpPoolStart $using:config.AKSNodeStartIP -k8sNodeIpPoolEnd $using:config.AKSNodeEndIP -vipPoolStart $using:config.AKSVIPStartIP -vipPoolEnd $using:config.AKSVIPEndIP -ipAddressPrefix $using:config.AKSIPPrefix -gateway $using:config.AKSGWIP -dnsServers $using:config.AKSDNSIP1,$using:config.AKSDNSIP2 -vlanID 460
        Set-AksHciConfig -imageDir $using:config.AKSImagedir -workingDir $using:config.AKSWorkingdir -cloudConfigLocation $using:config.AKSCloudConfigdir -vnet $vnet -cloudservicecidr $using:config.AKSCloudSvcidr 
        Connect-AzAccount -Credential $using:AADCred
        $armtoken = Get-AzAccessToken
        $graphtoken = Get-AzAccessToken -ResourceTypeName AadGraph
        Set-AksHciRegistration -subscriptionId $using:config.AzureSubID -resourceGroupName $using:config.AKSResourceGroupName -AccountId $using:AADAccount -ArmAccessToken $armtoken.Token -GraphAccessToken $graphtoken.Token
        Write-Host -ForegroundColor Green -Object "Installing AKS on HCI Cluster"
        Install-AksHci 
    }
}
##########################################################################################################################

write-host -ForegroundColor Green -Object "Cluster is Deployed; Enjoy!"

#Appendix

$WelcomeMessage="Welcome to the Azure Stack HCI 2 Node Deployment script, this script will deploy out a fully functional 2 Node Azure Stack HCI Cluster, in a Switchless configuraiton. The first step in this deployment is to ask for you to sign into your Azure Subscription."