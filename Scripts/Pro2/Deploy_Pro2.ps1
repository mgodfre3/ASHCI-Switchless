param(
    [Parameter(Mandatory)]
    [String] $ConfigurationDataFile
) 

$WelcomeMessage="Welcome to the Azure Stack HCI 2 Node Deployment script, this script will deploy out a fully functional 2 Node Azure Stack HCI Cluster, in a Switchless configuraiton. The first step in this deployment is to ask for you to sign into your Azure Subscription."
#Begin Function Region

Function Update-Progress 
{
    $progressLog[$currentStepIndex] = "$currentStepName = Completed"
    $progressLog | Out-File -FilePath '.\progress.log' -Encoding utf8 -Force
    Write-Host "============================================" -ForegroundColor Yellow
    Write-Host "Completed Step:"(($progressLog[$currentStepIndex]).Split())[0] -ForegroundColor DarkGreen
    Write-Host "Next Step:"(($progressLog[$currentStepIndex+1]).Split())[0] -ForegroundColor DarkGreen

}
        
function LoadVariables {
   
    #Set Variables from Config File

$config=Import-PowerShellDataFile -Path $ConfigurationDataFile 
Write-Host -ForegroundColor Green -Object $WelcomeMessage
return $config 
}







function ConfigureWorkstation {
    param ()
    Write-Host -ForegroundColor Green -Object "Configuring Managment Workstation"

    #Set WinRM for remote management of nodes
    #winrm quickconfig
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

function ConfigureNodes {
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

function ConfigureNode01 {
    param ()
    Write-Host -ForegroundColor Green -Object "Configure Node 01"

Invoke-Command -ComputerName $config.Node01 -Credential $ADCred -ScriptBlock {

# Configure IP and subnet mask, no default gateway for Storage interfaces
   
    #Rename Net Adapters
    $m1=Get-NetAdapter -InterfaceDescription "Intel(R) Ethernet Connection X722 for 10GBASE-T"
    $m2=Get-NetAdapter -InterfaceDescription "Intel(R) Ethernet Connection X722 for 10GBASE-T #2"
    $m1 | Rename-NetAdapter -NewName "MGMT1"
    $m2 | Rename-NetAdapter -NewName "MGMT2"
    $s1=Get-NetAdapter -InterfaceDescription "Mellanox ConnectX-6 Dx Adapter"
    $s2=Get-NetAdapter -InterfaceDescription "Mellanox ConnectX-6 Dx Adapter #2"
    $s1 | Rename-NetAdapter -NewName "SMB1"
    $s2 | Rename-NetAdapter -NewName "SMB2"
    
    #MGMT
    New-NetIPAddress -InterfaceAlias "MGMT" -IPAddress $using:config.node01_MgmtIP -PrefixLength 24 -DefaultGateway $using:config.GWIP  | Set-DnsClientServerAddress -ServerAddresses $using:config.DNSIP
    
    #Storage 
    
    New-NetIPAddress -InterfaceAlias "SMB1" -IPAddress 172.16.0.1 -PrefixLength 24
    New-NetIPAddress -InterfaceAlias "SMB2" -IPAddress 172.16.1.1 -PrefixLength 24
    #Get-NetAdapter "-Name Ethernet *"| Disable-NetAdapter -Confirm:$false
}
}

function ConfigureNode02 {
    param ()
    Write-Host -ForegroundColor Green -Object "Configure Node02"

Invoke-Command -ComputerName $config.Node02 -Credential $ADCred -ScriptBlock {
    # Configure IP and subnet mask, no default gateway for Storage interfaces
    
    #Rename Net Adapters
    $m1=Get-NetAdapter -InterfaceDescription "Intel(R) Ethernet Connection X722 for 10GBASE-T"
    $m2=Get-NetAdapter -InterfaceDescription "Intel(R) Ethernet Connection X722 for 10GBASE-T #2"
    $m1 | Rename-NetAdapter -NewName "MGMT1"
    $m2 | Rename-NetAdapter -NewName "MGMT2"
    $s1=Get-NetAdapter -InterfaceDescription "Mellanox ConnectX-6 Dx Adapter"
    $s2=Get-NetAdapter -InterfaceDescription "Mellanox ConnectX-6 Dx Adapter #2"
    $s1 | Rename-NetAdapter -NewName "SMB1"
    $s2 | Rename-NetAdapter -NewName "SMB2"
    
    
    #MGMT
    New-NetIPAddress -InterfaceAlias "MGMT" -IPAddress $using:config.node02_MgmtIP -PrefixLength 24 -DefaultGateway $using:config.GWIP| Set-DnsClientServerAddress -ServerAddresses $using:config.DNSIP
    
    #Storage 
    New-NetIPAddress -InterfaceAlias "SMB1" -IPAddress 172.16.0.2 -PrefixLength 24
    New-NetIPAddress -InterfaceAlias "SMB2" -IPAddress 172.16.1.2 -PrefixLength 24
    #Get-NetAdapter -Name "Ethernet *" | Disable-NetAdapter -Confirm:$false
}
}

function PrepareStorage {
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

function CreateCluster {
    param ()
    Write-Host -ForegroundColor Green -Object "Creating the Cluster"

#Create the Cluster
Invoke-Command -ComputerName $config.node01 -Credential $adcred -Authentication Credssp -ScriptBlock {
#Test-Cluster –Node $using:config.Node01, $using:config.Node02 –Include "Storage Spaces Direct", "Inventory", "Network", "System Configuration"
#New-Cluster -Name $using:config.ClusterName -Node $using:config.Node01, $using:config.Node02 -StaticAddress $using:config.ClusterIP -NoStorage -AdministrativeAccessPoint ActiveDirectoryAndDns 

#Pause for a bit then clear DNS cache.
Start-Sleep 30
Clear-DnsClientCache

# Update the cluster network names that were created by default.  First, look at what's there
Get-ClusterNetwork -Cluster $using:config.ClusterName  | ft Name, Role, Address

# Change the cluster network names so they are consistent with the individual nodes
(Get-ClusterNetwork -Cluster $using:config.ClusterName  | where-object address -like "172.16.0.0").Name = "Storage1"
(Get-ClusterNetwork -Cluster $using:config.ClusterName  | where-object address -like "172.16.1.0").Name = "Storage2"
#(Get-ClusterNetwork -Cluster $using:config.ClusterName  | where-object address -like "").Name = "OOB"
(Get-ClusterNetwork -Cluster $using:config.ClusterName  | where-object address -like $using:config.MGMTSubnet).Name = "MGMT"

# Check to make sure the cluster network names were changed correctly
Get-ClusterNetwork -Cluster $config.ClusterName | ft Name, Role, Address
}

}

function SetLiveMigration {
    param()
    Write-Host -ForegroundColor Green -Object "Set Cluster Live Migration Settings"

#Set Cluster Live Migration Settings 
Enable-VMMigration -ComputerName $ServerList
Add-VMMigrationNetwork -computername $ServerList -Subnet 172.16.0.0/24 -Priority 1 
Add-VMMigrationNetwork -computername $ServerList -Subnet 172.16.1.0/24 -Priority 2 
Set-VMHost -ComputerName $ServerList -MaximumStorageMigrations 2 -MaximumVirtualMachineMigrations 2 -VirtualMachineMigrationPerformanceOption SMB -UseAnyNetworkForMigration $false 

}

function DeployS2D {
    param ()
    Write-Host -ForegroundColor Green -Object "Enable Storage Spaces Direct"

#Enable S2D
Enable-ClusterStorageSpacesDirect  -CimSession $config.ClusterName -PoolFriendlyName $config.StoragePoolName -Confirm:0 

}

function EnableCAU {
param()
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

function ConfirmFunctionLevels {
    param ()
    #Update Cluster Function Level

$cfl=Get-Cluster -Name $config.ClusterName 
if ($cfl.ClusterFunctionalLevel -lt "11") {
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

function CreateCSV {
    param ()
    write-host -ForegroundColor Green -Object "Creating Cluster Shared Volume"

#Create S2D Tier and Volumes
New-StorageTier -StoragePoolFriendlyName $config.StoragePoolName -FriendlyName 2WayNestedMirror -ResiliencySettingName Mirror -MediaType SSD -NumberOfDataCopies 4 -CimSession $config.ClusterName ;

New-Volume -StoragePoolFriendlyName $config.StoragePoolName -FriendlyName Volume01 -StorageTierFriendlyNames 2WayNestedMirror -StorageTierSizes $config.CSVSize -CimSession $config.ClusterName 
 

}

function CreateCloudWitness{
    param()
    write-host -ForegroundColor Green -Object "Set Cloud Witness"

#Set Cloud Witness

Set-ClusterQuorum -Cluster $config.ClusterName -CloudWitness -AccountName $config.CloudWitnessShare  -AccessKey $Config.CloudWitnessKey

}

function SetNetIntents {
    param()
    write-host -ForegroundColor Green -Object "Setting NetworkATC Configuration"

Invoke-Command -ComputerName $ServerList -Credential $ADcred -Authentication Credssp {

#North-South Net-Intents
New-VMSwitch -Name "HCI" -AllowManagementOS $true -EnableEmbeddedTeaming $true -MinimumBandwidthMode Weight -NetAdapterName "MGMT1", "MGMT2"
 
}

Invoke-Command -ComputerName $config.Node01 -Credential $ADcred -Authentication Credssp {
#Storage NetIntent
Add-NetIntent -ClusterName $using:config.ClusterName -AdapterName "SMB1", "SMB2"  -Name SMB -Storage
}

<#
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
#>
}

function registerhcicluster {
param()
write-host -ForegroundColor Green -Object "Register the Cluster to Azure Subscription"

#Register Cluster with Azure

#Register Cluster with Azure
Invoke-Command -ComputerName $config.Node01 -Credential $ADcred -Authentication Credssp {
    Connect-AzAccount -Credential $using:AADCred
    $armtoken = Get-AzAccessToken
    $graphtoken = Get-AzAccessToken -ResourceTypeName AadGraph
    Register-AzStackHCI -SubscriptionId $using:config.AzureSubID -ComputerName $using:config.Node01 -AccountId $using:AADAccount -ArmAccessToken $armtoken.Token -GraphAccessToken $graphtoken.Token -EnableAzureArcServer -Credential $using:ADCred -Region "East US" -ResourceName $using:config.ClusterName
    }

}


function DeployAKS {
    param ()

$azureAppCred = (New-Object System.Management.Automation.PSCredential $config.AzureSPNAPPId, (ConvertTo-SecureString -String $config.AzureSPNSecret -AsPlainText -Force))
Connect-AzAccount -ServicePrincipal -Subscription $config.AzureSubID -Tenant $config.AzureTenantID -Credential $azureAppCred
$context = Get-AzContext # Azure credential
$armtoken = Get-AzAccessToken
$graphtoken = Get-AzAccessToken -ResourceTypeName AadGraph

#AzResourceGroup

$rg=Get-AzResourceGroup -Name $config.AKSResourceGroupName
if ($rq -eq $null)
{
New-AzResourceGroup -Name $config.AKSResourceGroupName -Location "west central us" 
    }
else {write-host "$config.AKSResourceGroupName exists"
}


# Install latest versions of Nuget and PowershellGet
Write-Host "Install latest versions of Nuget and PowershellGet"
Invoke-Command -ComputerName $ServerList -Credential $adcred -ScriptBlock {
    Enable-PSRemoting -Force
    Install-PackageProvider -Name NuGet -Force 
    Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted
    Install-Module -Name PowershellGet -Force
}

# Install necessary AZ modules and initialize akshci on each node
Write-Host "Install necessary AZ modules plus AksHCI module and initialize akshci on each node" 

Invoke-Command -ComputerName $ServerList  -Credential $adcred -ScriptBlock {
    Write-Host "Installing Required Modules" -ForegroundColor Green -BackgroundColor Black
    
    $ModuleNames="Az.Resources","Az.Accounts", "AzureAD", "AKSHCI"
    foreach ($ModuleName in $ModuleNames){
        if (!(Get-InstalledModule -Name $ModuleName -ErrorAction Ignore)){
            Install-Module -Name $ModuleName -Force -AcceptLicense 
        }
    }
    Import-Module Az.Accounts
    Import-Module Az.Resources
    Import-Module AzureAD
    Import-Module AksHci
    Initialize-akshcinode
}


Write-Host "Prepping AKS Install"

Invoke-Command -ComputerName $config.Node01 -Credential $adcred -Authentication Credssp -ScriptBlock  {
    

    $vnet = New-AksHciNetworkSetting -name $using:config.AKSvnetname -vSwitchName $using:config.AKSvSwitchName -k8sNodeIpPoolStart $using:config.AKSNodeStartIP -k8sNodeIpPoolEnd $using:config.AKSNodeEndIP -vipPoolStart $using:config.AKSVIPStartIP -vipPoolEnd $using:config.AKSVIPEndIP -ipAddressPrefix $using:config.AKSIPPrefix -gateway $using:config.AKSGWIP -dnsServers $using:config.AKSDNSIP         

    Set-AksHciConfig -imageDir $using:config.AKSImagedir -workingDir $using:config.AKSWorkingdir -cloudConfigLocation $using:config.AKSCloudConfigdir -vnet $vnet -cloudservicecidr $using:config.AKSCloudSvcidr

    $azurecred = Connect-AzAccount -ServicePrincipal -Subscription $using:context.Subscription.Id -Tenant $using:context.Subscription.TenantId -Credential $using:azureAppCred
    
    Set-AksHciRegistration -subscriptionId $azurecred.Context.Subscription.Id -resourceGroupName $using:config.AKSResourceGroupName -Tenant $azurecred.Context.Tenant.Id -Credential $using:azureAppCred

    Write-Host "Ready to Install AKS on HCI Cluster"

    Install-AksHci

}

}

Function InstallArcRB {
param ()

$azureAppCred = (New-Object System.Management.Automation.PSCredential $config.AzureSPNAPPId, (ConvertTo-SecureString -String $config.AzureSPNSecret -AsPlainText -Force))
Connect-AzAccount -ServicePrincipal -Subscription $config.AzureSubID -Tenant $config.AzureTenantID -Credential $azureAppCred
$context = Get-AzContext # Azure credential
$armtoken = Get-AzAccessToken
$graphtoken = Get-AzAccessToken -ResourceTypeName AadGraph


#Install AZ Resource Bridge
Write-Host "Now Preparing to Install Azure Arc Resource Bridge" -ForegroundColor Black -BackgroundColor Green 

#Install Required Modules 
Invoke-Command -ComputerName $ServerList -Credential $ADcred -ScriptBlock {
Install-PackageProvider -Name NuGet -Force 
Install-Module -Name PowershellGet -Force -Confirm:$false -SkipPublisherCheck
}
#Must Restart Powershell Session for Next Commands
Invoke-Command -ComputerName $ServerList -Credential $ADcred -ScriptBlock {
#Install-Module -Name Moc -Repository PSGallery -AcceptLicense -Force
#Initialize-MocNode
Install-Module -Name ArcHci -Force -Confirm:$false -SkipPublisherCheck -AcceptLicense
}


#Install AZ CLI
Invoke-Command -ComputerName $ServerList -Credential $ADcred -ScriptBlock {
$ProgressPreference = 'SilentlyContinue'; 
Invoke-WebRequest -Uri https://aka.ms/installazurecliwindows -OutFile .\AzureCLI.msi; 
Start-Process msiexec.exe -Wait -ArgumentList '/I AzureCLI.msi /quiet'; rm .\AzureCLI.msi
}


#Install Required Extensions
Invoke-Command -ComputerName $config.Node01 -Credential $ADcred -ScriptBlock {
az extension remove --name arcappliance
az extension remove --name connectedk8s
az extension remove --name k8s-configuration
az extension remove --name k8s-extension
az extension remove --name customlocation
az extension remove --name azurestackhci
az extension add --upgrade --name arcappliance
az extension add --upgrade --name connectedk8s
az extension add --upgrade --name k8s-configuration
az extension add --upgrade --name k8s-extension
az extension add --upgrade --name customlocation
az extension add --upgrade --name azurestackhci
}

Invoke-Command -ComputerName $config.Node01 -Credential $ADcred -Authentication Credssp -ScriptBlock {

$csv_path= "C:\clusterstorage\Volume01"
$resource_name= ((Get-AzureStackHci).AzureResourceName) + "-arcbridge"

mkdir $csv_path\ResourceBridge


az login --service-principal -u $using:config.AzureSPNAPPId -p $using:config.AzureSPNSecret --tenant $using:config.AzureTenantID

New-ArcHciConfigFiles -subscriptionId $using:config.AzureSubID -location $using:config.Location -resourceGroup $using:config.resbridgeresource_group -resourceName $resource_name -workDirectory $csv_path\ResourceBridge -controlPlaneIP $using:config.resbridgecpip  -k8snodeippoolstart $using:config.resbridgeip -k8snodeippoolend $using:config.resbridgeip -gateway $using:Config.AKSGWIP -dnsservers $using:config[0].AKSDNSIP -ipaddressprefix $using:config.AKSIPPrefix   
 
az arcappliance validate hci --config-file $csv_path\ResourceBridge\hci-appliance.yaml

#start-sleep 60 

az arcappliance prepare hci --config-file $csv_path\ResourceBridge\hci-appliance.yaml

#Start-Sleep 60
New-Item -Path $csv_path\ResourceBridge -ItemType Directory -Name ".\kube"
New-Item -Path $csv_path\ResourceBridge\.kube -ItemType Directory -Name "config"
az arcappliance deploy hci --config-file  $csv_path\ResourceBridge\hci-appliance.yaml --outfile $csv_path\ResourceBridge\.kube\config

#Start-Sleep 60

#az arcappliance create hci --config-file $csv_path\ResourceBridge\hci-appliance.yaml --kubeconfig C:\Users\mgodfre3\.kube\config
}


Invoke-Command -ComputerName $config.Node01 -Credential $ADcred -Authentication Credssp -ScriptBlock {
az login --service-principal -u $using:config.AzureSPNAPPId -p $using:config.AzureSPNSecret --tenant $using:config.AzureTenantID
$csv_path= "C:\clusterstorage\Volume01"
az arcappliance create hci --config-file $csv_path\ResourceBridge\hci-appliance.yaml --kubeconfig C:\Users\mgodfre3\.kube\config

}
}


#End Function Region

#Begin Main Region

<#---------------------------------------------------------------------------------------------------------------#>


$config=LoadVariables
$ServerList = $config.Node01, $config.Node02

#Retrieve Credentials
$azlogin = Connect-AzAccount -Subscription $config.azuresubid 
Select-AzSubscription -Subscription $config.AzureSubID
#Set AD Domain Cred
$AzDJoin = Get-AzKeyVaultSecret -VaultName $config.KeyVault -Name "SecretName"
$ADcred = [pscredential]::new("domain\djoin",$AZDJoin.SecretValue)
#$ADpassword = ConvertTo-SecureString "" -AsPlainText -Force
#$ADCred = New-Object System.Management.Automation.PSCredential ("contoso\djoiner", $ADpassword)

#Set Cred for AAD tenant and subscription
$AADAccount = "username@domain.com"
$AADAdmin=Get-AzKeyVaultSecret -VaultName $config.KeyVault -Name "azurestackadmin"
$AADCred = [pscredential]::new("username@domain.com",$AADAdmin.SecretValue)
$Arcsecretact=Get-AzKeyVaultSecret -VaultName $config.KeyVault -Name "SecretName"
$ARCSecret=$arcsecretact.SecretValue

ConfigureWorkstation
ConfigureNodes
ConfigureNode01
ConfigureNode02
PrepareStorage
CreateCluster
SetLiveMigration
DeployS2D
EnableCAU
ConfirmFunctionLevels
CreateCSV
CreateCloudWitness
SetNetintents

registerhcicluster
DeployAKS


    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
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





























# Main execution begins here







write-host -ForegroundColor Green -Object "Cluster is Deployed; Enjoy!"

#Appendix

