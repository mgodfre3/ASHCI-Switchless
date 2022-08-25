

@{


# This is the PowerShell datafile used to provide configuration information for the Azure Stack HCI Cluster Deployment.

# Version 1.0.0

#Node Parameters
Node01 = "ashci1" #Set Short Name for Node01
Node02 = "ashci2" #Set Short Name for Node02

node01_MgmtIP="192.168.0.110" #Set MGMT IP address for Node01
node02_MgmtIP="192.168.0.111" #Set MGMT IP address for Node02

MGMTSubnet="192.168.0.0" #Please provide MGMT Subnet
GWIP = "192.168.0.1" #Set Default Gateway IP for MGMT Network

ADDomain = "contoso.local" #Please provide domain FQDN
DNSIP = "172.16.100.20" #Set DNS IP(s) for DNS servers i.e. Domain Controllers



#Cluster Parameters
ClusterName = "ashcicl" #Set Short name of Cluster. This account can be Prestaged in Active Directory, just make sure it is "Disabled."
ClusterIP = "192.168.0.115" #Provide Cluster IP Address

#Storage Spaces Direct Paramters
StoragePoolName= "ASHCICL Storage Pool 1" #Provide Desired Friendly name of Storage Pool

CSVFriendlyname="Volume01-Thin" #Provide First Cluster Shared Volume Friendly Name, this will be created as a Nested-2-Way Mirror Volume by default.
CSVSize=5GB #Size in GB of First Cluster Shared Volume, Remember Nested-2 Way Mirror is a Storage Efficency of 25%, so 1 TB uses 4 TB of the Storage Pool.

#CLoud Witness 
CWStorageAct="" #Provide Name of Cloud Witness Storage Accounts
CWStorageKey="" #Provide Storage Acocunt Key
#######################################################################################
    #AKS-HCI parameters
    AKSEnable="false"
    AKSvnetname = "vnet1"
    AKSvSwitchName = "ConvergedSwitch(hci)"
    AKSNodeStartIP = "192.168.0.150"
    AKSNodeEndIP = "192.168.0.175"
    AKSVIPStartIP = "192.168.0.176"
    AKSVIPEndIP = "192.168.0.200"
    AKSIPPrefix = "192.168.0.0/24"
    AKSGWIP = "192.168.0.1"
    AKSDNSIP = "172.16.100.20"
    AKSImagedir = "c:\clusterstorage\Volume01\Images"
    AKSWorkingdir = "c:\clusterstorage\Volume01\Workdir"
    AKSCloudConfigdir = "c:\clusterstorage\Volume01\Config"
    AKSCloudSvcidr = "192.168.0.112/24"
    AKSResourceGroupName = "ashcicl-rg"
    

#########################SET ALL  Azure VARIABLES########################### 

AzureSubID = "SubID" #Please Provide Subscription ID Number for Azure Subscription


}


