################################
# Run from DC or Management VM #
################################

#region  Config
  
    #Input Server Names
        $Servers="AzSHCI1","AzSHCI2","AzSHCI","AzSHCI4"
        #alternatively you can just do $Servers="AzSHCI1","AzSHCI2","AzSHCI","AzSHCI4". The result is the same

        #NetworkAdapter Names
       
    #Cluster Name
        $ClusterName="AzSHCI-Cluster"

    #Cluster-Aware-Updating role name
        $CAURoleName="AzSHCI-Cl-CAU"

    #Cluster IP
        $ClusterIP="10.0.0.111" #If blank (you can write just $ClusterIP="", DHCP will be used). If $DistributedManagementPoint is true, then IP is not used

    #Distributed Cluster ManagementPoint? (Cluster Name in DNS will have IP of every node - like SOFS). If $ClusterIP is set, then $clusterIP will be ignored).
        $DistributedManagementPoint=$true

    #Witness type
        $WitnessType="Cloud"#orFileShare
        #if cloud then configure following (use your own, these are just examples)
        <#
        $CloudWitnessStorageAccountName="MyStorageAccountName"
        $CloudWitnessStorageKey="qi8QB/VSHHiA9lSvz1kEIEt0JxIucPL3l99nRHhkp+n1Lpabu4Ydi7Ih192A4VW42vccIgUnrXxxxxxxxxxxxx=="
        $CloudWitnessEndpoint="core.windows.net“
        #>

    #Disable CSV Balancer
        $DisableCSVBalancer=$False

    #Perform Windows update? (for more info visit WU Scenario https://github.com/microsoft/WSLab/tree/dev/Scenarios/Windows%20Update)
        $WindowsUpdate="Recommended" #Can be "All","Recommended" or "None"

    ## Networking ##
        $vSwitchName="vSwitch"
        #Provide Network Adapter Names
        $eth0="Management Physical 1"
        $eth1="Managment Physical 2"
        $SMB1="SMB1"
        $SMB2="SMB2"
        $smb_prefix="24"
        
        $NumberOfStorageNets=2

        #IF Stornet is 1
        $StorNet="192.168.10.10"
        $StorVLAN=10

        #IF Stornets are 2 (in larger clusters it worth keep storage traffic local to each TOR switch)
        $StorNet1="192.168.10.10"
        $StorNet2="192.168.20.10"
        $StorVLAN1=10
        $StorVLAN2=20

        $SRIOV=$true #Deploy SR-IOV enabled switch (best practice is to enable if possible)

       

    #start IP for storage network
        $IP=10

    #Real hardware?
        $RealHW=$true #will configure VMQ not to use CPU 0 if $True, configures power plan
        $DellHW=$False #include Dell recommendation to increase HW timeout to 10s becayse of their Hitachi HDDs. May be already obsolete.

    #IncreaseHW Timeout for virtual environments to 30s? This is because of running in lab https://docs.microsoft.com/en-us/windows-server/storage/storage-spaces/storage-spaces-direct-in-vm
        $VirtualEnvironment=$false

    #Configure dcb? (more info at http://aka.ms/ConvergedRDMA)
        $DCB=$False #$true for ROCE, $false for iWARP

    #iWARP?
        $iWARP=$true

    #DisableNetBIOS on all vNICs? $True/$False It's optional. Works well with both settings default/disabled
        $DisableNetBIOS=$False

    #SMB Bandwith Limits for Live Migration? https://techcommunity.microsoft.com/t5/Failover-Clustering/Optimizing-Hyper-V-Live-Migrations-on-an-Hyperconverged/ba-p/396609
        $SMBBandwidthLimits=$true

    #Jumbo Frames? Might be necessary to increase for iWARP. If not default, make sure all switches are configured end-to-end and (for example 9216). Also if non-default is set, you might run into various issues such as https://blog.workinghardinit.work/2019/09/05/fixing-slow-roce-rdma-performance-with-winof-2-to-winof/.
    #if 1514 is set, setting JumboFrames is skipped. All NICs are configured (vNICs + pNICs)
        $JumboSize=9014 #9014, 4088 or 1514 (default)

    #Additional Features
        $Bitlocker=$true #Install "Bitlocker" and "RSAT-Feature-Tools-BitLocker" on nodes?
        $StorageReplica=$true #Install "Storage-Replica" and "RSAT-Storage-Replica" on nodes?
        $Deduplication=$true #install "FS-Data-Deduplication" on nodes?
        $SystemInsights=$true #install "System-Insights" on nodes?

    #Enable Meltdown mitigation? https://support.microsoft.com/en-us/help/4072698/windows-server-guidance-to-protect-against-the-speculative-execution
    #CVE-2017-5754 cannot be used to attack across a hardware virtualized boundary. It can only be used to read memory in kernel mode from user mode. It is not a strict requirement to set this registry value on the host if no untrusted code is running and no untrusted users are able to logon to the host.
        $MeltdownMitigationEnable=$false

    #Enable Microarchitectural Data Sampling Mitigation? https://support.microsoft.com/en-us/help/4072698/windows-server-speculative-execution-side-channel-vulnerabilities-prot
        $MicroarchitecturalDataSamplingMitigation=$false

    #Enable speculative store bypass mitigation? https://support.microsoft.com/en-us/help/4073119/protect-against-speculative-execution-side-channel-vulnerabilities-in , https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/ADV180012
        $SpeculativeStoreBypassMitigation=$false

    #Configure PCID to expose to VMS prior version 8.0 https://docs.microsoft.com/en-us/virtualization/hyper-v-on-windows/CVE-2017-5715-and-hyper-v-vms
        $ConfigurePCIDMinVersion=$true

    #Configure Processor Machine Check Error vulnerability mitigation https://support.microsoft.com/en-us/help/4530989/guidance-for-protecting-against-intel-processor-machine-check-error-vu
        $ConfigureProcessorMachineCheckErrorMitigation=$true

    #Configure Core scheduler on Windows Server 2016? https://docs.microsoft.com/en-us/windows-server/virtualization/hyper-v/manage/manage-hyper-v-scheduler-types#configuring-the-hypervisor-scheduler-type-on-windows-server-2016-hyper-v
        $CoreScheduler=$True

    #Memory dump type (Active or Kernel) https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/varieties-of-kernel-mode-dump-files
        $MemoryDump="Active"

    #real VMs? If true, script will create real VMs on mirror disks from vhd you will provide during the deployment. The most convenient is to provide NanoServer
        $realVMs=$false
        $NumberOfRealVMs=2 #number of VMs on each mirror disk


#region install features for management (Client needs RSAT, Server/Server Core have different features)
    $WindowsInstallationType=Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\' -Name InstallationType
    $CurrentBuildNumber=Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\' -Name CurrentBuildNumber
    if ($WindowsInstallationType -eq "Server"){
        Install-WindowsFeature -Name RSAT-Clustering,RSAT-Clustering-Mgmt,RSAT-Clustering-PowerShell,RSAT-Hyper-V-Tools,RSAT-Feature-Tools-BitLocker-BdeAducExt,RSAT-Storage-Replica
    }elseif ($WindowsInstallationType -eq "Server Core"){
        Install-WindowsFeature -Name RSAT-Clustering,RSAT-Clustering-PowerShell,RSAT-Hyper-V-Tools,RSAT-Storage-Replica
    }elseif (($WindowsInstallationType -eq "Client") -and ($CurrentBuildNumber -lt 17763)){
        #Validate RSAT Installed
            if (!((Get-HotFix).hotfixid -contains "KB2693643") ){
                Write-Host "Please install RSAT, Exitting in 5s"
                Start-Sleep 5
                Exit
            }
    }elseif (($WindowsInstallationType -eq "Client") -and ($CurrentBuildNumber -ge 17763)){
        #Install RSAT tools
            $Capabilities="Rsat.ServerManager.Tools~~~~0.0.1.0","Rsat.FailoverCluster.Management.Tools~~~~0.0.1.0","Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0"
            foreach ($Capability in $Capabilities){
                Add-WindowsCapability -Name $Capability -Online
            }
    }
    if ($WindowsInstallationType -eq "Client"){
        #Install Hyper-V Management features
            if ((Get-WindowsOptionalFeature -online -FeatureName Microsoft-Hyper-V-Management-PowerShell).state -ne "Enabled"){
                #Install all features and then remove all except Management (fails when installing just management)
                Enable-WindowsOptionalFeature -online -FeatureName Microsoft-Hyper-V-All -NoRestart
                Disable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -NoRestart
                $Q=Read-Host -Prompt "Restart is needed. Do you want to restart now? Y/N"
                If ($Q -eq "Y"){
                    Write-Host "Restarting Computer"
                    Start-Sleep 3
                    Restart-Computer
                }else{
                    Write-Host "You did not type Y, please restart Computer. Exitting"
                    Start-Sleep 3
                    Exit
                }
            }elseif((Get-command -Module Hyper-V) -eq $null){
                $Q=Read-Host -Prompt "Restart is needed to load Hyper-V Management. Do you want to restart now? Y/N"
                If ($Q -eq "Y"){
                    Write-Host "Restarting Computer"
                    Start-Sleep 3
                    Restart-Computer
                }else{
                    Write-Host "You did not type Y, please restart Computer. Exitting"
                    Start-Sleep 3
                    Exit
                }
            }
    }
#endregion

#region Update all servers (for more info visit WU Scenario https://github.com/microsoft/WSLab/tree/dev/Scenarios/Windows%20Update)
    if ($WindowsUpdate -eq "Recommended"){
        Invoke-Command -ComputerName $servers -ScriptBlock {
            #Grab updates
            $SearchCriteria = "IsInstalled=0"
            #$SearchCriteria = "IsInstalled=0 and DeploymentAction='OptionalInstallation'" #does not work, not sure why
            $ScanResult=Invoke-CimMethod -Namespace "root/Microsoft/Windows/WindowsUpdate" -ClassName "MSFT_WUOperations" -MethodName ScanForUpdates -Arguments @{SearchCriteria=$SearchCriteria}
            #apply updates (if not empty)
            if ($ScanResult.Updates){
                Invoke-CimMethod -Namespace "root/Microsoft/Windows/WindowsUpdate" -ClassName "MSFT_WUOperations" -MethodName InstallUpdates -Arguments @{Updates=$ScanResult.Updates}
            }
        }
    }elseif ($WindowsUpdate -eq "All"){
        # Update servers with all updates (including preview)
        Invoke-Command -ComputerName $servers -ScriptBlock {
            New-PSSessionConfigurationFile -RunAsVirtualAccount -Path $env:TEMP\VirtualAccount.pssc
            Register-PSSessionConfiguration -Name 'VirtualAccount' -Path $env:TEMP\VirtualAccount.pssc -Force
        } -ErrorAction Ignore
        # Run Windows Update via ComObject.
        Invoke-Command -ComputerName $servers -ConfigurationName 'VirtualAccount' {
            $Searcher = New-Object -ComObject Microsoft.Update.Searcher
            $SearchCriteriaAllUpdates = "IsInstalled=0 and DeploymentAction='Installation' or
                                    IsInstalled=0 and DeploymentAction='OptionalInstallation' or
                                    IsPresent=1 and DeploymentAction='Uninstallation' or
                                    IsInstalled=1 and DeploymentAction='Installation' and RebootRequired=1 or
                                    IsInstalled=0 and DeploymentAction='Uninstallation' and RebootRequired=1"
            $SearchResult = $Searcher.Search($SearchCriteriaAllUpdates).Updates
            $Session = New-Object -ComObject Microsoft.Update.Session
            $Downloader = $Session.CreateUpdateDownloader()
            $Downloader.Updates = $SearchResult
            $Downloader.Download()
            $Installer = New-Object -ComObject Microsoft.Update.Installer
            $Installer.Updates = $SearchResult
            $Result = $Installer.Install()
            $Result
        }
        #remove temporary PSsession config
        Invoke-Command -ComputerName $servers -ScriptBlock {
            Unregister-PSSessionConfiguration -Name 'VirtualAccount'
            Remove-Item -Path $env:TEMP\VirtualAccount.pssc
        }
    }
#endregion

#region Configure basic settings on servers
    #Tune HW timeout to 10 seconds (6 seconds is default) in Dell servers (may be obsolete as it applies to Dell 730xd with Hitachi HDDs)
        if ($DellHW){
            Invoke-Command -ComputerName $servers -ScriptBlock {Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\spaceport\Parameters -Name HwTimeout -Value 0x00002710}
        }

    #IncreaseHW Timeout for virtual environments to 30s
        if ($VirtualEnvironment){
            Invoke-Command -ComputerName $servers -ScriptBlock {Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\spaceport\Parameters -Name HwTimeout -Value 0x00007530}
        }

    #configure memory dump
        if ($MemoryDump -eq "Kernel"){
        #Configure Kernel memory dump
            Invoke-Command -ComputerName $servers -ScriptBlock {
                Set-ItemProperty -Path HKLM:\System\CurrentControlSet\Control\CrashControl -Name CrashDumpEnabled -value 2
            }
        }
        if ($MemoryDump -eq "Active"){
            #Configure Active memory dump
            Invoke-Command -ComputerName $servers -ScriptBlock {
                Set-ItemProperty -Path HKLM:\System\CurrentControlSet\Control\CrashControl -Name CrashDumpEnabled -value 1
                Set-ItemProperty -Path HKLM:\System\CurrentControlSet\Control\CrashControl -Name FilterPages -value 1
            }
        }

    #enable meltdown mitigation
        if ($MeltdownMitigationEnable){
            Invoke-Command -ComputerName $servers -ScriptBlock {
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name FeatureSettingsOverride -value 0
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name FeatureSettingsOverrideMask -value 3
            }
        }

    #enable Speculative Store Bypass mitigation
        if ($SpeculativeStoreBypassMitigation){
            Invoke-Command -ComputerName $servers -ScriptBlock {
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name FeatureSettingsOverride -value 8
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name FeatureSettingsOverrideMask -value 3
            }
        }

    #enable Microarchitectural Data Sampling mitigation
        if ($MicroarchitecturalDataSamplingMitigation){
            Invoke-Command -ComputerName $servers -ScriptBlock {
                #Detect HT
                $processor=Get-WmiObject win32_processor | Select-Object -First 1
                if ($processor.NumberOfCores -eq $processor.NumberOfLogicalProcessors/2){
                    $HT=$True
                }
                if ($HT -eq $True){
                    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name FeatureSettingsOverride -value 72
                }else{
                    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name FeatureSettingsOverride -value 8264
                }
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name FeatureSettingsOverrideMask -value 3
            }
        }

    #Configure MinVmVersionForCpuBasedMitigations (only needed if you are running VM versions prior 8.0)
        if ($ConfigurePCIDMinVersion){
            Invoke-Command -ComputerName $servers -ScriptBlock {
                if (-not (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization")){
                    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name Virtualization -Force
                }
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization" -Name MinVmVersionForCpuBasedMitigations -value "1.0"
            }
        }

    #Configure Processor Machine Check Error vulnerability mitigation https://support.microsoft.com/en-us/help/4530989/guidance-for-protecting-against-intel-processor-machine-check-error-vu
        if ($ConfigureProcessorMachineCheckErrorMitigation -eq $true){
            Invoke-Command -ComputerName $servers -ScriptBlock {
                if (-not (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization")){
                    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name Virtualization -Force
                }
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization" -Name IfuErrataMitigations  -value 1
            }
        }

    #Enable core scheduler
    if ($CoreScheduler){
        $RevisionNumber=Invoke-Command -ComputerName $servers[0] -ScriptBlock {
            Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\' -Name UBR
        }
        $CurrentBuildNumber=Invoke-Command -ComputerName $servers[0] -ScriptBlock {
            Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\' -Name CurrentBuildNumber
        }
        if ($CurrentBuildNumber -eq 14393 -and $RevisionNumber -ge 2395){
            Invoke-Command -ComputerName $Servers {
                bcdedit /set hypervisorschedulertype Core
            }
        }
    }

    #enable high performance power plan
    if ($RealHW){
        #set high performance
            Invoke-Command -ComputerName $servers -ScriptBlock {powercfg /SetActive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c}
        #check settings
            Invoke-Command -ComputerName $servers -ScriptBlock {powercfg /list}
    }

    #install roles and features
        #install Hyper-V using DISM if Install-WindowsFeature fails (if nested virtualization is not enabled install-windowsfeature fails)
        Invoke-Command -ComputerName $servers -ScriptBlock {
            $Result=Install-WindowsFeature -Name "Hyper-V" -ErrorAction SilentlyContinue
            if ($result.ExitCode -eq "failed"){
                Enable-WindowsOptionalFeature -FeatureName Microsoft-Hyper-V -Online -NoRestart 
            }
        }

        #define features
        $features="Failover-Clustering","Hyper-V-PowerShell"
        if ($Bitlocker){$Features+="Bitlocker","RSAT-Feature-Tools-BitLocker"}
        if ($StorageReplica){$Features+="Storage-Replica","RSAT-Storage-Replica"}
        if ($Deduplication){$features+="FS-Data-Deduplication"}
        if ($SystemInsights){$features+="System-Insights","RSAT-System-Insights"}

        #install features
        Invoke-Command -ComputerName $servers -ScriptBlock {Install-WindowsFeature -Name $using:features} 
        #restart and wait for computers
        Restart-Computer $servers -Protocol WSMan -Wait -For PowerShell
        Start-Sleep 20 #Failsafe as Hyper-V needs 2 reboots and sometimes it happens, that during the first reboot the restart-computer evaluates the machine is up

#endregion

#region configure Networking (best practices are covered in this guide http://aka.ms/ConvergedRDMA ). For more information about networking you can look at this scenario: https://github.com/microsoft/WSLab/tree/master/Scenarios/S2D%20and%20Networks%20deep%20dive
    #Create Virtual Switches and Virtual Adapters
        if ($SRIOV){
            Invoke-Command -ComputerName $servers -ScriptBlock {New-VMSwitch -Name $using:vSwitchName -EnableEmbeddedTeaming $TRUE -EnableIov $true -NetAdapterName (Get-NetIPAddress | where name -like "$eth0" ).InterfaceAlias;
            Add-VMSwitchTeamMember -VMSwitch $using:vSwitchName -NetAdapterName ($using:eth1).Name}
        }else{
            Invoke-Command -ComputerName $servers -ScriptBlock {New-VMSwitch -Name $using:vSwitchName -EnableEmbeddedTeaming $TRUE -NetAdapterName (Get-NetIPAddress | where name -like "$eth0" ).InterfaceAlias;
                Add-VMSwitchTeamMember -VMSwitch $using:vSwitchName -NetAdapterName ($using:eth1).Name}
        }

        $Servers | ForEach-Object {
            #Configure vNICs
            Rename-VMNetworkAdapter -ManagementOS -Name $vSwitchName -NewName Management -ComputerName $_
           
            #configure IP Addresses
            New-NetIPAddress -InterfaceAlias $using:smb1.interfacealias -IPAddress ($StorNet1+$IP.ToString()) -Prefixlength 24 $IP++
            New-NetIPAddress -InterfaceAlias $using:smb2.interfacealias -IPAddress ($StorNet2+$IP.ToString()) -Prefixlength 24 $IP++

        }

        Start-Sleep 5
        Clear-DnsClientCache

     

        #Restart each host vNIC adapter so that the Vlan is active.
            Restart-NetAdapter "SMB01" -CimSession $Servers 
            Restart-NetAdapter "SMB02" -CimSession $Servers

        #Enable RDMA on the host vNIC adapters
            Enable-NetAdapterRDMA "SMB01","SMB02" -CimSession $Servers

        #Configure Jumbo Frames
            if ($JumboSize -ne 1514){
                Set-NetAdapterAdvancedProperty -CimSession $Servers  -DisplayName "Jumbo Packet" -RegistryValue $JumboSize
            }

        #Disable NetBIOS on all vNICs https://msdn.microsoft.com/en-us/library/aa393601(v=vs.85).aspx
            if ($DisableNetBIOS){
                $vNICs = Get-NetAdapter -CimSession $Servers | Where-Object Name -like vEthernet*
                foreach ($vNIC in $vNICs){
                    Write-Host "Disabling NetBIOS on $($vNIC.Name) on computer $($vNIC.PSComputerName)"
                    $output=Get-WmiObject -class win32_networkadapterconfiguration -ComputerName $vNIC.PSComputerName | Where-Object Description -eq $vNIC.InterfaceDescription | Invoke-WmiMethod -Name settcpipNetBIOS -ArgumentList 2
                    if ($output.Returnvalue -eq 0){
                        Write-Host "`t Success" -ForegroundColor Green
                    }else{
                        Write-Host "`t Failure"
                    }
                }
            }

        #Disable RSC (receive segment coalescing) on Physical NICs connected to vSwitch (RSC in the vSwitch (2019+ only) conflicts with NIC vendors implementation of RSC if they did it in software (miniport, not OS) rather than firmware. In Validate-DCB it's only for MLX4 drivers (Mellanox CX 3)
            Invoke-Command -ComputerName $servers -ScriptBlock {
                $physicaladapters=(get-vmswitch $using:vSwitchName).NetAdapterInterfaceDescriptions
                foreach ($physicaladapter in $physicaladapters){
                    $adapter=Get-NetAdapter -InterfaceDescription $physicaladapter
                    if ($adapter.DriverName -like "*mlx4*"){
                        $adapter | Set-NetAdapterAdvancedProperty -RegistryKeyword '*RscIPv4' -RegistryValue 0
                        $adapter | Set-NetAdapterAdvancedProperty -RegistryKeyword '*RscIPv6' -RegistryValue 0
                    }
                }
            }

    #Verify Networking
        #verify mapping
            Get-VMNetworkAdapterTeamMapping -CimSession $servers -ManagementOS | Format-Table ComputerName,NetAdapterName,ParentAdapter 
        #Verify that the VlanID is set
            Get-VMNetworkAdapterVlan -ManagementOS -CimSession $servers |Sort-Object -Property Computername | Format-Table ComputerName,AccessVlanID,ParentAdapter -AutoSize -GroupBy ComputerName
        #verify RDMA
            Get-NetAdapterRdma -CimSession $servers | Sort-Object -Property Systemname | Format-Table systemname,interfacedescription,name,enabled -AutoSize -GroupBy Systemname
        #verify ip config 
            Get-NetIPAddress -CimSession $servers -InterfaceAlias vEthernet* -AddressFamily IPv4 | Sort-Object -Property PSComputername | Format-Table pscomputername,interfacealias,ipaddress -AutoSize -GroupBy pscomputername
        #verify JumboFrames
            Get-NetAdapterAdvancedProperty -CimSession $servers -DisplayName "Jumbo Packet"

    #configure DCB if requested
        if ($DCB -eq $True){
            #Install DCB
                if (!$NanoServer){
                    foreach ($server in $servers) {Install-WindowsFeature -Name "Data-Center-Bridging" -ComputerName $server} 
                }
            ##Configure QoS
                New-NetQosPolicy "SMB"       -NetDirectPortMatchCondition 445 -PriorityValue8021Action 3 -CimSession $servers
                New-NetQosPolicy "ClusterHB" -Cluster                         -PriorityValue8021Action 7 -CimSession $servers
                New-NetQosPolicy "Default"   -Default                         -PriorityValue8021Action 0 -CimSession $servers

            #Turn on Flow Control for SMB
                Invoke-Command -ComputerName $servers -ScriptBlock {Enable-NetQosFlowControl -Priority 3}

            #Disable flow control for other traffic than 3 (pause frames should go only from prio 3)
                Invoke-Command -ComputerName $servers -ScriptBlock {Disable-NetQosFlowControl -Priority 0,1,2,4,5,6,7}

            #Disable Data Center bridging exchange (disable accept data center bridging (DCB) configurations from a remote device via the DCBX protocol, which is specified in the IEEE data center bridging (DCB) standard.)
                Invoke-Command -ComputerName $servers -ScriptBlock {Set-NetQosDcbxSetting -willing $false -confirm:$false}

            #Configure IeeePriorityTag
                #IeePriorityTag needs to be On if you want tag your nonRDMA traffic for QoS. Can be off if you use adapters that pass vSwitch (both SR-IOV and RDMA bypasses vSwitch)
                Invoke-Command -ComputerName $servers -ScriptBlock {Set-VMNetworkAdapter -ManagementOS -Name "SMB*" -IeeePriorityTag on}

            #validate flow control setting
                Invoke-Command -ComputerName $servers -ScriptBlock { Get-NetQosFlowControl} | Sort-Object  -Property PSComputername | Format-Table PSComputerName,Priority,Enabled -GroupBy PSComputerName

            #Validate DCBX setting
                Invoke-Command -ComputerName $servers -ScriptBlock {Get-NetQosDcbxSetting} | Sort-Object PSComputerName | Format-Table Willing,PSComputerName

            #Apply policy to the target adapters.  The target adapters are adapters connected to vSwitch
                Invoke-Command -ComputerName $servers -ScriptBlock {Enable-NetAdapterQos -InterfaceDescription (Get-VMSwitch).NetAdapterInterfaceDescriptions}

            #validate policy
                Invoke-Command -ComputerName $servers -ScriptBlock {Get-NetAdapterQos | Where-Object enabled -eq true} | Sort-Object PSComputerName

            #Create a Traffic class and give SMB Direct 60% of the bandwidth minimum. The name of the class will be "SMB".
            #This value needs to match physical switch configuration. Value might vary based on your needs.
            #If connected directly (in 2 node configuration) skip this step.
                Invoke-Command -ComputerName $servers -ScriptBlock {New-NetQosTrafficClass "SMB"       -Priority 3 -BandwidthPercentage 60 -Algorithm ETS}
                Invoke-Command -ComputerName $servers -ScriptBlock {New-NetQosTrafficClass "ClusterHB" -Priority 7 -BandwidthPercentage 1 -Algorithm ETS}
        }

    #enable iWARP firewall rule if requested
        if ($iWARP -eq $True){
            Enable-NetFirewallRule -Name "FPSSMBD-iWARP-In-TCP" -CimSession $servers
        }

#endregion

#region Create cluster and configure basic settings
    Test-Cluster -Node $servers -Include "Storage Spaces Direct","Inventory","Network","System Configuration","Hyper-V Configuration"
    If ($DistributedManagementPoint){
        New-Cluster -Name $ClusterName -Node $servers -ManagementPointNetworkType "Distributed"
    }else{
        if ($ClusterIP){
            New-Cluster -Name $ClusterName -Node $servers -StaticAddress $ClusterIP
        }else{
            New-Cluster -Name $ClusterName -Node $servers
        }
    }
    Start-Sleep 5
    Clear-DnsClientCache

    #Configure CSV Cache (value is in MB) - disable if SCM or VM is used. For VM it's just for labs - to save some RAM.
        if (Get-PhysicalDisk -cimsession $servers[0] | Where-Object bustype -eq SCM){
            #disable CSV cache if SCM storage is used
            (Get-Cluster $ClusterName).BlockCacheSize = 0
        }elseif ((Invoke-Command -ComputerName $servers[0] -ScriptBlock {(get-wmiobject win32_computersystem).Model}) -eq "Virtual Machine"){
            #disable CSV cache for virtual environments
            (Get-Cluster $ClusterName).BlockCacheSize = 0
        }

    #ConfigureWitness
    if ($WitnessType -eq "FileShare"){
        ##Configure Witness on DC
        #Create new directory
            $WitnessName=$Clustername+"Witness"
            Invoke-Command -ComputerName DC -ScriptBlock {new-item -Path c:\Shares -Name $using:WitnessName -ItemType Directory}
            $accounts=@()
            $accounts+="corp\$ClusterName$"
            $accounts+="corp\Domain Admins"
            New-SmbShare -Name $WitnessName -Path "c:\Shares\$WitnessName" -FullAccess $accounts -CimSession DC
        #Set NTFS permissions 
            Invoke-Command -ComputerName DC -ScriptBlock {(Get-SmbShare $using:WitnessName).PresetPathAcl | Set-Acl}
        #Set Quorum
            Set-ClusterQuorum -Cluster $ClusterName -FileShareWitness "\\DC\$WitnessName"
    }elseif($WitnessType -eq $Cloud){
        Set-ClusterQuorum -Cluster $ClusterName -CloudWitness -AccountName $CloudWitnessStorageAccountName -AccessKey $CloudWitnessStorageKey -Endpoint $CloudWitnessEndpoint 
    }

    #Disable CSV Balancer
        if ($DisableCSVBalancer){
            (Get-Cluster $ClusterName).CsvBalancer = 0
        }

#endregion

#region Configure Cluster Networks
    #rename networks
        if ($NumberOfStorageNets -eq 1){
            (Get-ClusterNetwork -Cluster $clustername | Where-Object Address -eq $StorNet"0").Name="SMB"
        }else{
            (Get-ClusterNetwork -Cluster $clustername | Where-Object Address -eq $StorNet1"0").Name="SMB01"
            (Get-ClusterNetwork -Cluster $clustername | Where-Object Address -eq $StorNet2"0").Name="SMB02"
        }
        (Get-ClusterNetwork -Cluster $clustername | Where-Object Address -like $AdaptersIPPrefix).Name="Management"

    #configure Live Migration 
        Get-ClusterResourceType -Cluster $clustername -Name "Virtual Machine" | Set-ClusterParameter -Name MigrationExcludeNetworks -Value ([String]::Join(";",(Get-ClusterNetwork -Cluster $clustername | Where-Object {$_.Name -eq "Management"}).ID))
        Set-VMHost -VirtualMachineMigrationPerformanceOption SMB -cimsession $servers

    #Configure SMB Bandwidth Limits for Live Migration https://techcommunity.microsoft.com/t5/Failover-Clustering/Optimizing-Hyper-V-Live-Migrations-on-an-Hyperconverged/ba-p/396609
        if ($SMBBandwidthLimits){
            #install feature
            Invoke-Command -ComputerName $servers -ScriptBlock {Install-WindowsFeature -Name "FS-SMBBW"}
            #Calculate 40% of capacity of NICs in vSwitch (considering 2 NICs, if 1 fails, it will not consume all bandwith, therefore 40%)
            $Adapters=(Get-VMSwitch -CimSession $Servers[0]).NetAdapterInterfaceDescriptions
            $BytesPerSecond=((Get-NetAdapter -CimSession $Servers[0] -InterfaceDescription $adapters).TransmitLinkSpeed | Measure-Object -Sum).Sum/8
            Set-SmbBandwidthLimit -Category LiveMigration -BytesPerSecond ($BytesPerSecond*0.4) -CimSession $Servers
        }

#endregion

#region configure Cluster-Aware-Updating
    if (!$NanoServer){
        #Install required features on nodes.
            $ClusterNodes=(Get-ClusterNode -Cluster $ClusterName).Name
            foreach ($ClusterNode in $ClusterNodes){
                Install-WindowsFeature -Name RSAT-Clustering-PowerShell -ComputerName $ClusterNode
            }
        #add role
            Add-CauClusterRole -ClusterName $ClusterName -MaxFailedNodes 0 -RequireAllNodesOnline -EnableFirewallRules -VirtualComputerObjectName $CAURoleName -Force -CauPluginName Microsoft.WindowsUpdatePlugin -MaxRetriesPerNode 3 -CauPluginArguments @{ 'IncludeRecommendedUpdates' = 'False' } -StartDate "3/2/2017 3:00:00 AM" -DaysOfWeek 4 -WeeksOfMonth @(3) -verbose
    }
#endregion
<#
#region Create Fault Domains (just an example) https://docs.microsoft.com/en-us/windows-server/failover-clustering/fault-domains

#just some examples for Rack/Chassis fault domains.
    if ($numberofnodes -eq 4){
        $xml =  @"
<Topology>
    <Site Name="SEA" Location="Contoso HQ, 123 Example St, Room 4010, Seattle">
        <Rack Name="Rack01" Location="Contoso HQ, Room 4010, Aisle A, Rack 01">
                <Node Name="$($ServersNamePrefix)1"/>
                <Node Name="$($ServersNamePrefix)2"/>
                <Node Name="$($ServersNamePrefix)3"/>
                <Node Name="$($ServersNamePrefix)4"/>
        </Rack>
    </Site>
</Topology>
"@
    
        Set-ClusterFaultDomainXML -XML $xml -CimSession $ClusterName
    }
    
    if ($numberofnodes -eq 8){
        $xml =  @"
<Topology>
    <Site Name="SEA" Location="Contoso HQ, 123 Example St, Room 4010, Seattle">
        <Rack Name="Rack01" Location="Contoso HQ, Room 4010, Aisle A, Rack 01">
            <Node Name="$($ServersNamePrefix)1"/>
            <Node Name="$($ServersNamePrefix)2"/>
        </Rack>
        <Rack Name="Rack02" Location="Contoso HQ, Room 4010, Aisle A, Rack 02">
            <Node Name="$($ServersNamePrefix)3"/>
            <Node Name="$($ServersNamePrefix)4"/>
        </Rack>
        <Rack Name="Rack03" Location="Contoso HQ, Room 4010, Aisle A, Rack 03">
            <Node Name="$($ServersNamePrefix)5"/>
            <Node Name="$($ServersNamePrefix)6"/>
        </Rack>
        <Rack Name="Rack04" Location="Contoso HQ, Room 4010, Aisle A, Rack 04">
            <Node Name="$($ServersNamePrefix)7"/>
            <Node Name="$($ServersNamePrefix)8"/>
        </Rack>
    </Site>
</Topology>
"@
    
        Set-ClusterFaultDomainXML -XML $xml -CimSession $ClusterName
    }

    if ($numberofnodes -eq 16){
        $xml =  @"
<Topology>
    <Site Name="SEA" Location="Contoso HQ, 123 Example St, Room 4010, Seattle">
        <Rack Name="Rack01" Location="Contoso HQ, Room 4010, Aisle A, Rack 01">
            <Chassis Name="Chassis01" Location="Rack Unit 1 (Upper)" >
                <Node Name="$($ServersNamePrefix)1"/>
                <Node Name="$($ServersNamePrefix)2"/>
                <Node Name="$($ServersNamePrefix)3"/>
                <Node Name="$($ServersNamePrefix)4"/>
            </Chassis>
            <Chassis Name="Chassis02" Location="Rack Unit 1 (Upper)" >
                <Node Name="$($ServersNamePrefix)5"/>
                <Node Name="$($ServersNamePrefix)6"/>
                <Node Name="$($ServersNamePrefix)7"/>
                <Node Name="$($ServersNamePrefix)8"/>
            </Chassis>
            <Chassis Name="Chassis03" Location="Rack Unit 1 (Lower)" >
                <Node Name="$($ServersNamePrefix)9"/>
                <Node Name="$($ServersNamePrefix)10"/>
                <Node Name="$($ServersNamePrefix)11"/>
                <Node Name="$($ServersNamePrefix)12"/>
            </Chassis>
            <Chassis Name="Chassis04" Location="Rack Unit 1 (Lower)" >
                <Node Name="$($ServersNamePrefix)13"/>
                <Node Name="$($ServersNamePrefix)14"/>
                <Node Name="$($ServersNamePrefix)15"/>
                <Node Name="$($ServersNamePrefix)16"/>
            </Chassis>
        </Rack>
    </Site>
</Topology>
"@
        Set-ClusterFaultDomainXML -XML $xml -CimSession $ClusterName
    }
    
    #show fault domain configuration
        Get-ClusterFaultDomainxml -CimSession $ClusterName
    <# Alternate way
    if ($numberofnodes -eq 4){
        New-ClusterFaultDomain -Name "Rack01"    -FaultDomainType Rack    -Location "Contoso HQ, Room 4010, Aisle A, Rack 01"           -CimSession $ClusterName
        New-ClusterFaultDomain -Name "SEA"       -FaultDomainType Site    -Location "Contoso HQ, 123 Example St, Room 4010, Seattle"    -CimSession $ClusterName
    
        1..4 | ForEach-Object {Set-ClusterFaultDomain -Name "$($ServersNamePrefix)$_"  -Parent "Rack01" -CimSession $ClusterName}
        Set-ClusterFaultDomain -Name "Rack01" -Parent "SEA"    -CimSession $ClusterName
    
    }
    
    if ($numberofnodes -eq 8){
        New-ClusterFaultDomain -Name "Rack01"    -FaultDomainType Rack    -Location "Contoso HQ, Room 4010, Aisle A, Rack 01"           -CimSession $ClusterName
        New-ClusterFaultDomain -Name "Rack02"    -FaultDomainType Rack    -Location "Contoso HQ, Room 4010, Aisle A, Rack 02"           -CimSession $ClusterName
        New-ClusterFaultDomain -Name "Rack03"    -FaultDomainType Rack    -Location "Contoso HQ, Room 4010, Aisle A, Rack 03"           -CimSession $ClusterName
        New-ClusterFaultDomain -Name "Rack04"    -FaultDomainType Rack    -Location "Contoso HQ, Room 4010, Aisle A, Rack 04"           -CimSession $ClusterName
        New-ClusterFaultDomain -Name "SEA"       -FaultDomainType Site    -Location "Contoso HQ, 123 Example St, Room 4010, Seattle"    -CimSession $ClusterName
    
        1..2 |ForEach-Object {Set-ClusterFaultDomain -Name "$($ServersNamePrefix)$_" -Parent "Rack01"    -CimSession $ClusterName}
        3..4 |ForEach-Object {Set-ClusterFaultDomain -Name "$($ServersNamePrefix)$_" -Parent "Rack02"    -CimSession $ClusterName}
        5..6 |ForEach-Object {Set-ClusterFaultDomain -Name "$($ServersNamePrefix)$_" -Parent "Rack03"    -CimSession $ClusterName}
        7..8 |ForEach-Object {Set-ClusterFaultDomain -Name "$($ServersNamePrefix)$_" -Parent "Rack04"    -CimSession $ClusterName}
        1..4 |ForEach-Object {Set-ClusterFaultDomain -Name "Rack0$_" -Parent "SEA"    -CimSession $ClusterName}
    }
    
    if ($numberofnodes -eq 16){
        New-ClusterFaultDomain -Name "Chassis01" -FaultDomainType Chassis -Location "Rack Unit 1 (Upper)"                               -CimSession $ClusterName
        New-ClusterFaultDomain -Name "Chassis02" -FaultDomainType Chassis -Location "Rack Unit 1 (Upper)"                               -CimSession $ClusterName
        New-ClusterFaultDomain -Name "Chassis03" -FaultDomainType Chassis -Location "Rack Unit 1 (Lower)"                               -CimSession $ClusterName 
        New-ClusterFaultDomain -Name "Chassis04" -FaultDomainType Chassis -Location "Rack Unit 1 (Lower)"                               -CimSession $ClusterName
        New-ClusterFaultDomain -Name "Rack01"    -FaultDomainType Rack    -Location "Contoso HQ, Room 4010, Aisle A, Rack 01"           -CimSession $ClusterName
        New-ClusterFaultDomain -Name "SEA"       -FaultDomainType Site    -Location "Contoso HQ, 123 Example St, Room 4010, Seattle"    -CimSession $ClusterName
    
        1..4   |ForEach-Object {Set-ClusterFaultDomain -Name "$($ServersNamePrefix)$_" -Parent "Chassis01" -CimSession $ClusterName}
        5..8   |ForEach-Object {Set-ClusterFaultDomain -Name "$($ServersNamePrefix)$_" -Parent "Chassis02" -CimSession $ClusterName}
        9..12  |ForEach-Object {Set-ClusterFaultDomain -Name "$($ServersNamePrefix)$_" -Parent "Chassis03" -CimSession $ClusterName}
        13..16 |ForEach-Object {Set-ClusterFaultDomain -Name "$($ServersNamePrefix)$_" -Parent "Chassis04" -CimSession $ClusterName}
    
        1..4   |ForEach-Object {Set-ClusterFaultDomain -Name "Chassis0$_" -Parent "Rack01"    -CimSession $ClusterName}
        
        1..1 |ForEach-Object {Set-ClusterFaultDomain -Name "Rack0$_" -Parent "SEA"    -CimSession $ClusterName}
    
    }
    #>

#endregion

#region Enable Cluster S2D and check Pool and Tiers

    #Enable-ClusterS2D
        Enable-ClusterS2D -CimSession $ClusterName -confirm:0 -Verbose

    #display pool
        Get-StoragePool "S2D on $ClusterName" -CimSession $ClusterName

    #Display disks
        Get-StoragePool "S2D on $ClusterName" -CimSession $ClusterName | Get-PhysicalDisk -CimSession $ClusterName

    #Get Storage Tiers
        Get-StorageTier -CimSession $ClusterName
    
    <#alternate way
        #register storage provider 
            Get-StorageProvider | Register-StorageSubsystem -ComputerName $ClusterName

        #display pool
            Get-StoragePool "S2D on $ClusterName"

        #Display disks
            Get-StoragePool "S2D on $ClusterName" | Get-PhysicalDisk

        #display tiers
            Get-StorageTier

        #unregister StorageSubsystem
            $ss=Get-StorageSubSystem -FriendlyName *$ClusterName
            Unregister-StorageSubsystem -ProviderName "Windows Storage Management Provider" -StorageSubSystemUniqueId $ss.UniqueId
    #>

#endregion

#region Register Azure Stack HCI to Azure
    #download Azure module
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
    if (!(Get-InstalledModule -Name Az.StackHCI -ErrorAction Ignore)){
        Install-Module -Name Az.StackHCI -Force
    }

    #login to azure
    #download Azure module
    if (!(Get-InstalledModule -Name az.accounts -ErrorAction Ignore)){
        Install-Module -Name Az.Accounts -Force
    }
    Login-AzAccount -UseDeviceAuthentication

    #select context if more available
    $context=Get-AzContext -ListAvailable
    if (($context).count -gt 1){
        $context | Out-GridView -OutputMode Single | Set-AzContext
    }

    #select subscription
    $subscriptions=Get-AzSubscription
    if (($subscriptions).count -gt 1){
        $subscriptions | Out-GridView -OutputMode Single | Select-AzSubscription
    }

    $subscriptionID=(Get-AzSubscription).ID

    #register Azure Stack HCI
    Register-AzStackHCI -SubscriptionID $subscriptionID -ComputerName $ClusterName -UseDeviceAuthentication
    <# without device authentication if running on server with Internet Explorer
    #add some trusted sites (to be able to authenticate with Register-AzStackHCI)
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\EscDomains\live.com\login" /v https /t REG_DWORD /d 2
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\EscDomains\microsoftonline.com\login" /v https /t REG_DWORD /d 2
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\EscDomains\msauth.net\aadcdn" /v https /t REG_DWORD /d 2
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\EscDomains\msauth.net\logincdn" /v https /t REG_DWORD /d 2
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\EscDomains\msftauth.net\aadcdn" /v https /t REG_DWORD /d 2
    #and register
    Register-AzStackHCI -SubscriptionID $subscriptionID -ComputerName $ClusterName
    #>
    #or with location picker
    <#
    #grab location
    if (!(Get-InstalledModule -Name Az.Resources -ErrorAction Ignore)){
        Install-Module -Name Az.Resources -Force
    }
    $Location=Get-AzLocation | Where-Object Providers -Contains "Microsoft.AzureStackHCI" | Out-GridView -OutputMode Single
    Register-AzStackHCI -SubscriptionID $subscriptionID -Region $location.location -ComputerName $ClusterName -UseDeviceAuthentication
    #>

    #Install Azure Stack HCI RSAT Tools to all nodes
    $Servers=(Get-ClusterNode -Cluster $ClusterName).Name
    Invoke-Command -ComputerName $Servers -ScriptBlock {
        Install-WindowsFeature -Name RSAT-Azure-Stack-HCI
    }

    #Validate registration (query on just one node is needed)
    Invoke-Command -ComputerName $ClusterName -ScriptBlock {
        Get-AzureStackHCI
    }

    #Cleanup if needed
    <#
    UnRegister-AzStackHCI -ComputerName $ClusterName -Confirm:0 -UseDeviceAuthentication
    Get-AzResourceGroup -Name "$ClusterName-rg" | Remove-AzResourceGroup -Force
    #>
#endregion