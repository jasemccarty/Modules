<#==========================================================================
Module: VSANSC2N
Created on: 2/14/2018
Created by: Jase McCarty
Github: http://www.github.com/jasemccarty
Twitter: @jasemccarty
Website: http://www.jasemccarty.com
===========================================================================

.DESCRIPTION
This module combines a few sample Stretched Cluster & 2 Node scripts

.Notes

#>
Function runGuestOpInESXiVM() {
	param(
		$vm_moref,
		$guest_username, 
		$guest_password,
		$guest_command_path,
		$guest_command_args
	)
	
	# Get Session information
	$session = $global:DefaultVIServer

	# Guest Ops Managers
	$guestOpMgr = Get-View $session.ExtensionData.Content.GuestOperationsManager
	$authMgr = Get-View $guestOpMgr.AuthManager
	$procMgr = Get-View $guestOpMgr.processManager
	
	# Create Auth Session Object
	$auth = New-Object VMware.Vim.NamePasswordAuthentication
	$auth.username = $guest_username
	$auth.password = $guest_password
	$auth.InteractiveSession = $false
	
	# Program Spec
	$progSpec = New-Object VMware.Vim.GuestProgramSpec
	# Full path to the command to run inside the guest
	$progSpec.programPath = "$guest_command_path"
	$progSpec.workingDirectory = "/tmp"
	# Arguments to the command path, must include "++goup=host/vim/tmp" as part of the arguments
	$progSpec.arguments = "++group=host/vim/tmp $guest_command_args"
	
	# Issue guest op command
	$cmd_pid = $procMgr.StartProgramInGuest($vm_moref,$auth,$progSpec)
}

Function Set-VsanStretchedClusterWitness {
	<#
    .SYNOPSIS
       This function will set an existing vSAN Witness Appliance as a Witness for a 2 Node or Stretched vSAN Cluster
    .DESCRIPTION
       Use this function to set the vSAN Witness Host for a 2 Node or Stretched vSAN Cluster.

    .PARAMETER ClusterName
       Specifies the name of the Cluster you want to set the vSAN Witness Host for.
    .PARAMETER NewWitness
       Specifies the name of the new vSAN Witness Host want to use.

    .EXAMPLE
       PS C:\> Set-VsanStretchedClusterWitness -ClusterName <Cluster Name> -NewWitness <New Witness>

    .NOTES
       Author                                    : Jase McCarty
       Version                                   : 0.1
       ==========Tested Against Environment==========
       VMware vSphere Hypervisor(ESXi) Version   : 6.5
       VMware vCenter Server Version             : 6.5
       PowerCLI Version                          : PowerCLI 6.5.4
       PowerShell Version                        : 3.0
    #>

	# Set our Parameters
    [CmdletBinding()]Param(
    [Parameter(Mandatory=$True)][string]$ClusterName,
    [Parameter(Mandatory = $true)][String]$NewWitness
    )

    # Check to see the cluster exists
    Try {
	    # Check to make sure the New Witness Host has already been added to vCenter
	    $Cluster = Get-Cluster -Name $ClusterName -ErrorAction Stop
    }
	    Catch [VMware.VimAutomation.Sdk.Types.V1.ErrorHandling.VimException.VimException]
    {
	    Write-Host "The cluster, $ClusterName, was not found.               " -foregroundcolor red -backgroundcolor white
	    Write-Host "Please enter a valid cluster name and rerun this script."  -foregroundcolor black -backgroundcolor white
	    Exit
    }		

    # Check to make sure we are dealing with a vSAN cluster
	If($Cluster.VsanEnabled){
		
		# Determine whether this is a 2 Node or Stretched Cluster
		$HostCount = $Cluster | Select-Object @{n="count";e={($_ | Get-VMHost).Count}}
		Switch($HostCount.count){
			"2" {$SCTYPE = "2 Node"}
			default {$SCTYPE = "Stretched"}
		}
			
		# Let's go grab the vSAN Cluster's Configuration
		$VsanConfig = Get-VsanClusterConfiguration -Cluster $Cluster

		# If we're dealing with a Stretched Cluster architecture, then we can proceed
		If($VsanConfig.StretchedClusterEnabled) {

			# We'll need to get the Preferred Fault Domain, and be sure to set it as Preferred when setting up the new Witness
			$PFD = $VsanConfig.PreferredFaultDomain

			# We'll need to see what the name of the current witness is.
			$CWH = $VsanConfig.WitnessHost
			
			
				# If the Old & New Witness are named the same, no need to perform a replacement
				If ($NewWitness -ne $CWH.Name) {
				
					# Check to make sure the New Witness Host has already been added to vCenter
					Try {
					
						# Get the Witness Host
						$NewWitnessHost = Get-VMHost -Name $NewWitness -ErrorAction Stop

						# See if it is the VMware vSAN Witness Appliance
						$IsVsanWitnessAppliance = Get-AdvancedSetting -Entity $NewWitnessHost -Name Misc.vsanWitnessVirtualAppliance
						

						# If it is the VMware vSAN Witness Appliance, then proceed
						If ($IsVsanWitnessAppliance.Value -eq "1"){
							Write-Host "$NewWitness is a vSAN Witness Appliance." -foregroundcolor black -backgroundcolor green
							
							# Check to make sure a VMKernel port is tagged for vSAN Traffic, otherwise exit. Could possibly tag a VMkernel next time
							If ( Get-VMHost $NewWitness | Get-VMHostNetworkAdapter | Where-Object {$_.VsanTrafficEnabled}) {
								Write-Host "$NewWitness has a VMKernel port setup for vSAN Traffic. Proceeding."  -foregroundcolor black -backgroundcolor green
							} else {
								Write-Host "$NewWitness does not have a VMKernel port setup for vSAN Traffic. Exiting" -foregroundcolor red -backgroundcolor white
								Exit 
							}
						} else {
							# The Witness isn't a vSAN Witness Appliance, so exit 
							Write-Host "$NewWitness is not a vSAN Witness Appliance, stopping" -foregroundcolor red -backgroundcolor white
							Write-Host "This script only supports using the vSAN Witness Appliance"  -foregroundcolor red -backgroundcolor white
							Exit
						}
					}
					
					# If the NewWitness isn't present in vCenter, suggest deploying one and rerun this script
					Catch [VMware.VimAutomation.Sdk.Types.V1.ErrorHandling.VimException.VimException]{
						Write-Host "The New Witness, $NewWitness, was not found.         " -foregroundcolor red -backgroundcolor white
						Write-Host "Please deploy a vSAN Witness Appliance and rerun this script."  -foregroundcolor black -backgroundcolor white
						Exit
						}					
				
					Write-Host "$Cluster is a $SCTYPE Cluster"
					#Write-Host "The Preferred Fault Domain is ""$PFD"""
					Write-Host "Current Witness:  ""$CWH"" New Witness: ""$NewWitness"""
					
					# If the Existing Witness is connected or in maintenance mode, go ahead and cleanly unmount the disk group
					# We will assume that if it isn't connected, it has failed, and we just need to replace it.
					If ($CWH.ConnectionState -eq "Connected" -or $CWH.ConnectionState -eq "Maintenance") {
					
						# Get the disk group of the existing vSAN Witness
						$CWHDG = Get-VsanDiskGroup | Where-Object {$_.VMHost -like $CWH} -ErrorAction SilentlyContinue
					
					
						# Remove the existing disk group, so this Witness could be used later
						Write-Host "Removing vSAN Disk Group from $CWH so it can be easily reused later" -foregroundcolor black -backgroundcolor white
						Remove-VsanDiskGroup -VsanDiskGroup $CWHDG -DataMigrationMode "NoDataMigration" -Confirm:$False 

					}
					
					# Set the cluster configuration to false - Necessary to swap Witness Appliances
					Write-Host "Removing Witness $CWH from the vSAN cluster" -foregroundcolor black -backgroundcolor white
					Set-VsanClusterConfiguration -Configuration $Cluster -StretchedClusterEnabled $false 

					# Set the cluster configuration to Stretched/2 Node, with the new witness and the previously preferred fault domain
					Write-Host "Adding Witness $NewWitness and reenabling the $SCTYPE Cluster" -foregroundcolor black -backgroundcolor white
					Set-VsanClusterConfiguration -Configuration $Cluster -StretchedClusterEnabled $True -PreferredFaultDomain $PFD -WitnessHost $NewWitness -WitnessHostCacheDisk mpx.vmhba1:C0:T2:L0 -WitnessHostCapacityDisk mpx.vmhba1:C0:T1:L0

				} else {
					# Don't let an admin remove the existing witness and re-add it
					Write-Host "$NewWitness is already the Witness for the $ClusterName Cluster"   -foregroundcolor black -backgroundcolor white
				}
				
			} else {

				# Show that the host is already set for the right value
				Write-Host "$Cluster.Name is not a Stretched Cluster " -foregroundcolor black -backgroundcolor green
				
			}
		            
    }
}
Function Set-Vsan2NodeForcedCache {
	<#
    .SYNOPSIS
       This function will enable/disable Forced Caching across hosts on a 2 Node vSAN Cluster
    .DESCRIPTION
       This function will enable/disable Forced Caching across hosts on a 2 Node vSAN Cluster

    .PARAMETER ClusterName
       Specifies the name of the Cluster you want to set change the Forced Cache state for.
    .PARAMETER ForcedCache
       Specifies whether to enable or disable Forced Cache

    .EXAMPLE
       PS C:\> Set-Vsan2NodeForcedCache -ClusterName <Cluster Name> -ForcedCache <enable/disable>

    .NOTES
       Author                                    : Jase McCarty
       Version                                   : 0.1
       ==========Tested Against Environment==========
       VMware vSphere Hypervisor(ESXi) Version   : 6.5
       VMware vCenter Server Version             : 6.5
       PowerCLI Version                          : PowerCLI 6.5.4
       PowerShell Version                        : 3.0
    #>

    # Set our Parameters
    [CmdletBinding()]Param(
	[Parameter(Mandatory=$True)][string]$ClusterName,
	[Parameter(Mandatory = $true)][ValidateSet('enable','disable')][String]$ForcedCache
  )
    
  # Get the Cluster Name
  $Cluster = Get-Cluster -Name $ClusterName
  
  # Check to ensure we have either enable or disable, and set our values/text
  Switch ($ForcedCache) {
      "disable" { 
          $ForcedValue = "0"
          $ForcedText  = "Default (local) Read Caching"
          }
      "enable" {
          $ForcedValue = "1"
          $ForcedText  = "Forced Warm Cache" 
          }
      default {
          write-host "Please include the parameter -ForcedCache enable or -ForcedCache disabled"
          exit
          }
      }
      # Display the Cluster
      Write-Host Cluster: $($Cluster.name)
      
      # Check to make sure we only have 2 Nodes in the cluster and vSAN is enabled
      $HostCount = $Cluster | Select-Object @{n="count";e={($_ | Get-VMHost).Count}}
      If($HostCount.count -eq "2" -And $Cluster.VsanEnabled){
  
          # Cycle through each ESXi Host in the cluster
          Foreach ($ESXHost in ($Cluster |Get-VMHost |Sort-Object Name)){
          
            # Get the current setting for diskIoTimeout
            $ForcedCache = Get-AdvancedSetting -Entity $ESXHost -Name "VSAN.DOMOwnerForceWarmCache"
                    
              # By default, if the IO Timeout doesn't align with KB2135494
            # the setting may or may not be changed based on Script parameters
                  If($ForcedCache.value -ne $ForcedValue){
  
              # Show that host is being updated
              Write-Host "2 Node $ForcedText Setting for $ESXHost"
              $ForcedCache | Set-AdvancedSetting -Value $ForcedValue -Confirm:$false
  
                  } else {
  
              # Show that the host is already set for the right value
              Write-Host "$ESXHost is already configured for $ForcedText"
  
          }
      }
                      
      } else {
          
          # Throw and error message that this isn't a 2 Node Cluster.
      Write-Host "The cluster ($ClusterName) is not a 2 Node cluster and/or does not have vSAN enabled."
      }
}
Function Get-Vsan2NodeForcedCache {
	<#
    .SYNOPSIS
       This function will get the current state of Forced Caching across hosts on a 2 Node vSAN Cluster
    .DESCRIPTION
	   This function will get the current state of Forced Caching across hosts on a 2 Node vSAN Cluster
	   
    .PARAMETER ClusterName
       Specifies the name of the Cluster you want to set change the Forced Cache state for.

    .EXAMPLE
       PS C:\> Get-Vsan2NodeForcedCache -ClusterName <Cluster Name>

    .NOTES
       Author                                    : Jase McCarty
       Version                                   : 0.1
       ==========Tested Against Environment==========
       VMware vSphere Hypervisor(ESXi) Version   : 6.5
       VMware vCenter Server Version             : 6.5
       PowerCLI Version                          : PowerCLI 6.5.4
       PowerShell Version                        : 3.0
    #>

    # Set our Parameters
    [CmdletBinding()]Param(
	[Parameter(Mandatory=$True)][string]$ClusterName
  )
    
	# Get the Cluster Name
	$Cluster = Get-Cluster -Name $ClusterName
  
	# Display the Cluster
    Write-Host Cluster: $($Cluster.name)
      
	# Check to make sure we only have 2 Nodes in the cluster and vSAN is enabled
	$HostCount = $Cluster | Select-Object @{n="count";e={($_ | Get-VMHost).Count}}

	If($HostCount.count -eq "2" -And $Cluster.VsanEnabled){		
		# Cycle through each ESXi Host in the cluster
		Foreach ($ESXHost in ($Cluster |Get-VMHost |Sort-Object Name)){
          
			# Get the current setting for DOMOwnerForceWarmCache
			$FORCEDCACHE = (Get-AdvancedSetting -Entity $ESXHost -Name 'VSAN.DOMOwnerForceWarmCache').Value

			Switch ($FORCEDCACHE){
				"0" { $Message = "disabled"}
				"1" { $Message = "enabled"}
			}
						
			# Show the Forced Cache setting
			Write-Host "$ESXHost has Forced Cache $message"
		}                      
      } else {
			# Throw and error message that this isn't a 2 Node Cluster.
			Write-Host "The cluster ($ClusterName) is not a 2 Node cluster and/or does not have vSAN enabled."
      }
  
  

}
Function Set-VsanStretchedClusterDrsRules {
	<#
    .SYNOPSIS
       This function will set vSphere DRS rules for a Stretched vSAN Cluster where VMs are using Tags
    .DESCRIPTION
       Use this function to set vSphere DRS rules for a Stretched vSAN Cluster.

    .PARAMETER ClusterName
       Specifies the name of the Cluster you want to set the vSAN Witness Host for.

    .EXAMPLE
       PS C:\> Set-VsanStretchedClusterDrsRules -ClusterName <Cluster Name>

    .NOTES
       Author                                    : Jase McCarty
       Version                                   : 0.1
       ==========Tested Against Environment==========
       VMware vSphere Hypervisor(ESXi) Version   : 6.5
       VMware vCenter Server Version             : 6.5
       PowerCLI Version                          : PowerCLI 6.5.4
       PowerShell Version                        : 3.0
    #>
	
	$Cluster = Get-Cluster -Name $ClusterName

	$VsanCluster = Get-VsanClusterConfiguration -Cluster $Cluster
	
	If($Cluster.VsanEnabled -and $VsanCluster.StretchedClusterEnabled){
	
		Write-Host "*******************************************"
		Write-Host "Sites:"
		Write-Host " Getting Names "
		$PreferredFaultDomain = $VsanCluster.PreferredFaultDomain.Name
		$SecondaryFaultDomain = Get-VsanFaultDomain | Where-Object {$_.Name -ne $PreferredFaultDomain}
		
		Write-Host " Getting Hosts in Each Fault Domain"
		$PreferredFaultDomainHostList = Get-VsanFaultDomain | Where-Object {$_.Name -eq $PreferredFaultDomain} |Get-VMHost
		$SecondaryFaultDomainHostList = Get-VsanFaultDomain | Where-Object {$_.Name -eq $SecondaryFaultDomain} |Get-VMHost
		
		Write-Host " Get VM Assignment based on VM Tags"
		$PreferredTag = Get-Cluster | Get-VM | Get-TagAssignment |Where-Object {$_.Tag -like $PreferredFaultDomain}
		$SecondaryTag = Get-Cluster | Get-VM | Get-TagAssignment |Where-Object {$_.Tag -like $SecondaryFaultDomain} 
		
		Write-Host " Setting the Host Group Name for each Site"
		$PreferredVMHostGroupName = "Hosts-" + $PreferredFaultDomain
		$SecondaryVMHostGroupName  = "Hosts-" + $SecondaryFaultDomain
	
		Write-Host " Setting the VM Group Name for each Site"
		$PreferredVMGroupName = "VMs-" + $PreferredFaultDomain
		$SecondaryVMGroupName = "VMs-" + $SecondaryFaultDomain
	
		#Write-Host " Setting the VMtoHost Rule Name for each Site"
		#$PreferredVMtoHostGroupName = "Assigned-" + $PreferredFaultDomain
		#$SecondaryVMtoHostGroupName = "Assigned-" + $SecondaryFaultDomain
	
		Write-Host ""
		Write-Host "*******************************************"
		Write-Host "Groups" 
		Write-Host " Creating the Site Host Groups"
		$PreferredVMHostGroup = New-DrsClusterGroup -Cluster $Cluster -Name $PreferredVMHostGroupName -VMHost $PreferredFaultDomainHostList
		$SecondaryVMHostGroup = New-DrsClusterGroup -Cluster $Cluster -Name $SecondaryVMHostGroupName -VMHost $SecondaryFaultDomainHostList
	
		Write-Host " Creating the Site VM Groups"
		$PreferredVMGroup = New-DrsClusterGroup -Cluster $Cluster -Name $PreferredVMGroupName -VM $PreferredTag.Entity
		$SecondaryVMGroup = New-DrsClusterGroup -Cluster $Cluster -Name $SecondaryVMGroupName -VM $SecondaryTag.Entity
		
		Write-Host " Setting the VM to Host Group Names"
		$PreferredVMtoHostRule = "VMtoSite" + $PreferredFaultDomain
		$SecondaryVMtoHostRule = "VMtoSite" + $SecondaryFaultDomain
	
		Write-Host ""
		Write-Host "*******************************************"
		Write-Host "Rules:"
		Write-Host " Creating/Assigning VM Groups to Host Groups"
		New-DrsVMHostRule -Name $PreferredVMtoHostRule -Cluster $Cluster -VMGroup $PreferredVMGroup -VMHostGroup $PreferredVMHostGroup -Type "ShouldRunOn" -Enabled $True
		New-DrsVMHostRule -Name $SecondaryVMtoHostRule -Cluster $Cluster -VMGroup $SecondaryVMGroup -VMHostGroup $SecondaryVMHostGroup -Type "ShouldRunOn" -Enabled $True
	
		Write-Host ""
		Write-Host "*******************************************"
		Write-Host "Checking for vSAN 6.6 Site Affinity Rule Capability"
		$Affinity = (Get-SpbmCapability |Where-Object {$_.Name -eq 'VSAN.locality'}).FriendlyName
		
		If($Affinity -eq "VSAN.locality"){
			
			Write-Host "Affinity Rule Capabilites Present, Checking for VM's with Affinity Policies"
			Foreach ($ClusterVM in (Get-Cluster |Get-VM)){
	
			Write-Host "Getting Affinty Rule for $ClusterVM"
			$AffinitySite =  ((Get-VM -Name $ClusterVM |Get-SpbmEntityConfiguration).StoragePolicy.AnyofRuleSets.AllOfRules | Where-Object {$_.Capability -like "VSAN.locality"}).Value
			
			Switch ($AffinitySite) {
					"Preferred Fault Domain" {
												Write-Host "Ensuring $ClusterVM doesn't reside in the alternate group"
												$Remove = Get-DrsClusterGroup $SecondaryVMGroup  | Set-DrsClusterGroup -VM $ClusterVM -Remove
												Write-Host "Assigning $ClusterVM to the proper group"
												$Add = Get-DrsClusterGroup $PreferredVMGroup  | Set-DrsClusterGroup -VM $ClusterVM -Add
											}
					"Secondary Fault Domain" {
												Write-Host "Ensuring $ClusterVM doesn't reside in the alternate group"
												$Remove = Get-DrsClusterGroup $PreferredVMGroup  | Set-DrsClusterGroup -VM $ClusterVM -Remove
												Write-Host "Assigning $ClusterVM to the proper group"
												$Add = Get-DrsClusterGroup $SecondaryVMGroup  | Set-DrsClusterGroup -VM $ClusterVM -Add										} 
					}			
			}
		
		}
	} else {
		Write-Host "The vSAN Cluster: $Cluster is not a vSAN Stretched Cluster"
	}

}

Function New-VsanStretchedClusterWitness {
		<#
		.SYNOPSIS
		This function will deploy a Witness for a 2 Node or Stretched vSAN Cluster
		.DESCRIPTION
		This function will deploy a Witness for a 2 Node or Stretched vSAN Cluster

		.PARAMETER Cluster
		Specifies the name of the Cluster you want to set the vSAN Witness Host for.
		.PARAMETER Datastore
		Specifies the name of the datastore to use.
		.PARAMETER OVAPath
		Full path and OVA filename for the vSAN Witness Appliance
		.PARAMETER Name
		The Virtual Machine Name of the vSAN Witness Appliance
		.PARAMETER Pass
		The root password of the vSAN Witness Appliance
		.PARAMETER Size
		The deployment size of the vSAN Witness Appliance
		.PARAMETER PG1
		The port group name for the vSAN Witness Appliance management network 
		.PARAMETER PG2
		The port group name for the vSAN Witness Appliance WitnessPg network

		.EXAMPLE
		PS C:\> New-VsanStretchedClusterWitness -Cluster <Cluster Name> -Datastrre <Datastore name> -OVAPath <c:\path\witness-xxx.ova> -Name <Witness VM Name> -Pass <password for witness> -Size <tiny/normal/large> -PG1 <port group name for Management network> -PG2 <port group name for Witness Network>

		.NOTES
		Author                                    : Jase McCarty
		Version                                   : 0.1
		==========Tested Against Environment==========
		VMware vSphere Hypervisor(ESXi) Version   : 6.5
		VMware vCenter Server Version             : 6.5
		PowerCLI Version                          : PowerCLI 6.5.4
		PowerShell Version                        : 3.0
		#>

		# Set our Parameters
		[CmdletBinding()]Param(
		[Parameter(Mandatory=$true)][String]$Cluster,
		[Parameter(Mandatory=$true)][String]$Datastore,
		[Parameter(Mandatory=$true)][String]$OVAPath,
		[Parameter(Mandatory=$true)][String]$Name,
		[Parameter(Mandatory=$true)][String]$Pass,
		[Parameter(Mandatory=$true)][String]$Size,
		[Parameter(Mandatory=$true)][String]$PG1,
		[Parameter(Mandatory=$true)][String]$PG2
		)

		# Grab a random host in the cluster to deploy to
		$TargetHost = Get-Cluster $Cluster | Get-VMHost | Where-Object {$_.PowerState -eq "PoweredOn" -and $_.ConnectionState -eq "Connected"} |Get-Random

		# Grab a random datastore
		$TargetDatastore = Get-Datastore -Name $Datastore

		# Grab the OVA properties from the vSAN Witness Appliance OVA
		$ovfConfig = Get-OvfConfiguration -Ovf $OVAPath

		# Set the Network Port Groups to use, the deployment size, and the root password for the vSAN Witness Appliance
		$ovfconfig.NetworkMapping.Management_Network.Value = $PG1
		$ovfconfig.NetworkMapping.Witness_Network.Value = $PG2
		$ovfconfig.DeploymentOption.Value = $Size
		$ovfconfig.vsan.witness.root.passwd.value = $Pass

		# Import the vSAN Witness Appliance 
		Import-VApp -Source $OVAPath -OvfConfiguration $ovfConfig -Name $Name -VMHost $TargetHost -Datastore $TargetDatastore -DiskStorageFormat Thin

}

Function Set-VsanWitnessNetwork {

		<#
		.SYNOPSIS
		This function will set vSAN Witness Networking
		.DESCRIPTION
		This function will set vSAN Witness Networking
		.PARAMETER Name
		The Virtual Machine Name of the vSAN Witness Appliance
		.PARAMETER Pass
		The root password of the vSAN Witness Appliance
		.PARAMETER VMkernel
		VMkernel Interface to be modified - either vmk0 (Management) or vmk1 (WitnessPg)
		.PARAMETER VMkernelIp
		Ip Address of the VMkernel Interface
		.PARAMETER NetMask
		NetMask for the VMkernel Interface
		.PARAMETER Gateway
		Gateway for the VMkernel Interface
		.PARAMETER DNS1
		DNS Entry for the default TCP/IP stack - used when VMkernel is vmk0
		.PARAMETER DNS2
		DNS Entry for the default TCP/IP stack - used when VMkernel is vmk0
		.PARAMETER FQDN
		The FQDN/Host Name for the vSAN Witness Appliance

		.EXAMPLE
		# Setting up the Management Network and Default TCP/IP Stack settings
		PS C:\> Set-VsanWitnessNetwork -Name <WitnessVM> -Pass <New Witness> -VMkernel <vmk0> -VMkernelIp <10.198.6.22> -NetMask <255.255.255.0> -Gateway <10.198.6.253> -DNS1 <10.198.6.11> -DNS2 <10.198.6.12> -FQDN <witness.demo.local>

		# Setting up the Witness Network
		PS C:\> Set-VsanWitnessNetwork -Name <WitnessVM> -Pass <New Witness> -VMkernel <vmk1> -VMkernelIp <192.168.10.22> -NetMask <255.255.255.0>

		.NOTES
		Author                                    : Jase McCarty
		Version                                   : 0.1
		==========Tested Against Environment==========
		VMware vSphere Hypervisor(ESXi) Version   : 6.5
		VMware vCenter Server Version             : 6.5
		PowerCLI Version                          : PowerCLI 6.5.4
		PowerShell Version                        : 3.0
		#>

	# Set our Parameters
	[CmdletBinding()]Param(
	[Parameter(Mandatory=$true)][string]$Name,
	[Parameter(Mandatory=$true)][String]$Pass,
	[Parameter(Mandatory=$true)][String]$VMkernel,
	[Parameter(Mandatory=$true)][String]$VMkernelIp,
	[Parameter(Mandatory=$true)][String]$NetMask,
	[Parameter(Mandatory=$false)][String]$Gateway,
	[Parameter(Mandatory=$false)][String]$DNS1,
	[Parameter(Mandatory=$false)][String]$DNS2,
	[Parameter(Mandatory=$false)][String]$FQDN
	)

	# Set the $WitnessVM variable, and guestos credentials
	$WitnessVM = Get-VM $Name
	$esxi_username = "root"
	$esxi_password = $Pass

	# Power on the vSAN Witness Appliance if it is not already
	If ((Get-VM $WitnessVM).PowerState -eq "PoweredOff") { Start-VM $WitnessVM} 

	# Wait until the tools are running because we'll need them to set the IP
	write-host "Waiting for VM Tools to Start"
	do {
		$toolsStatus = (Get-VM $WitnessVM | Get-View).Guest.ToolsStatus
		write-host $toolsStatus
		sleep 5
	} until ( $toolsStatus -eq 'toolsOk' )

	
	# Setup our commands to set IP/Gateway information
	$Command_Path = '/bin/python'
	
	Switch ($VMkernel) {
		"vmk0" { 
			# CMD to set VMkernel Network Settings
			$CommandVMkernel = '/bin/esxcli.py network ip interface ipv4 set -i ' + $VMKernel + ' -I ' + $VMkernelIP + ' -N ' + $NetMask  + ' -t static;/bin/esxcli.py network ip route ipv4 add -N defaultTcpipStack -n default -g ' + $Gateway
			# CMD to set DNS & Hostname Settings
			$CommandDns = '/bin/esxcli.py network ip dns server add --server=' + $DNS2 + ';/bin/esxcli.py network ip dns server add --server=' + $DNS1 + ';/bin/esxcli.py system hostname set --fqdn=' + $FQDN

			# Setup the Management Network
			Write-Host "Setting the Management Network"
			Write-Host
			runGuestOpInESXiVM -vm_moref $WitnessVM.ExtensionData.MoRef -guest_username $esxi_username -guest_password $esxi_password -guest_command_path $command_path -guest_command_args $CommandVMkernel
			runGuestOpInESXiVM -vm_moref $WitnessVM.ExtensionData.MoRef -guest_username $esxi_username -guest_password $esxi_password -guest_command_path $command_path -guest_command_args $CommandDns

			}
		"vmk1" {
			# CMD to set VMkernel Network Settings
			$CommandVMkernel = '/bin/esxcli.py network ip interface ipv4 set -i ' + $VMKernel + ' -I ' + $VMkernelIP + ' -N ' + $NetMask  + ' -t static;/bin/esxcli.py network ip route ipv4 add -N defaultTcpipStack -n default -g ' + $Gateway
			# Setup the Witness Portgroup
			Write-Host "Setting the WitnessPg Network"
			runGuestOpInESXiVM -vm_moref $WitnessVM.ExtensionData.MoRef -guest_username $esxi_username -guest_password $esxi_password -guest_command_path $command_path -guest_command_args $CommandVMkernel
			}
		default {
			write-host "Please select either vmk0 or vmk1"
			exit
			}
		}
}

Function Set-VsanWitnessNetworkRoute {

	<#
	.SYNOPSIS
	This function will set vSAN Witness Routing
	.DESCRIPTION
	This function will set vSAN Witness Routing
	.PARAMETER Name
	The ESXi hostname of the vSAN Witness Appliance
	.PARAMETER Destination
	Destination network
	.PARAMETER Gateway
	Gateway to use
	.PARAMETER Prefix
	Network Prefix

	.EXAMPLE
	PS C:\> Set-VsanWitnessNetworkRoute -Name <Witness FQDN> -Destination <192.168.110.0> -Gateway <192.168.109.253> -Prefix <24>

	.NOTES
	Author                                    : Jase McCarty
	Version                                   : 0.1
	==========Tested Against Environment==========
	VMware vSphere Hypervisor(ESXi) Version   : 6.5
	VMware vCenter Server Version             : 6.5
	PowerCLI Version                          : PowerCLI 6.5.4
	PowerShell Version                        : 3.0
	#>

	# Set our Parameters
	[CmdletBinding()]Param(
	[Parameter(Mandatory=$True)][string]$Name,
	[Parameter(Mandatory=$True)][String]$Destination,
	[Parameter(Mandatory=$True)][String]$Gateway,
	[Parameter(Mandatory=$True)][String]$Prefix
	)

	# Grab the host, so we can set Static Routes and NTP
	$WitnessHost = Get-VMhost -Name $Name

	# Set Static Routes
	Write-Host "Setting Static Route for the Witness Host $Name"
	New-VMHostRoute $WitnessHost -Destination $Destination -Gateway $Gateway -PrefixLength $Prefix -Confirm:$False

}

Function Get-VsanWitnessNetworkRoute {
	<#
	.SYNOPSIS
	This function will get vSAN Witness Routing
	.DESCRIPTION
	This function will get vSAN Witness Routing
	.PARAMETER Name
	The ESXi hostname of the vSAN Witness Appliance

	.EXAMPLE
	PS C:\> Get-VsanWitnessNetworkRoute -Name <Witness FQDN>

	.NOTES
	Author                                    : Jase McCarty
	Version                                   : 0.1
	==========Tested Against Environment==========
	VMware vSphere Hypervisor(ESXi) Version   : 6.5
	VMware vCenter Server Version             : 6.5
	PowerCLI Version                          : PowerCLI 6.5.4
	PowerShell Version                        : 3.0
	#>


	# Set our Parameters
	[CmdletBinding()]Param(
	[Parameter(Mandatory=$True)][string]$Name
	)

	# Grab the host, so we can set Static Routes and NTP
	$WitnessHost = Get-VMhost -Name $Name

	# Set Static Routes
	Write-Host "Getting Static Routes for the Witness Host $Name"
	Get-VMHostRoute -VMHost $WitnessHost 
}

Function Remove-VsanWitnessNetworkRoute {
	<#
	.SYNOPSIS
	This function will remove vSAN Witness Routing
	.DESCRIPTION
	This function will remove vSAN Witness Routing
	.PARAMETER Name
	The ESXi hostname of the vSAN Witness Appliance
	.PARAMETER Destination
	Destination network
	.PARAMETER Gateway
	Gateway to use
	.PARAMETER Prefix
	Network Prefix

	.EXAMPLE
	PS C:\> Remove-VsanWitnessNetworkRoute -Name <Witness FQDN> -Destination <192.168.110.0>

	.NOTES
	Author                                    : Jase McCarty
	Version                                   : 0.1
	==========Tested Against Environment==========
	VMware vSphere Hypervisor(ESXi) Version   : 6.5
	VMware vCenter Server Version             : 6.5
	PowerCLI Version                          : PowerCLI 6.5.4
	PowerShell Version                        : 3.0
	#>


	# Set our Parameters
	[CmdletBinding()]Param(
	[Parameter(Mandatory=$True)][string]$Name,
	[Parameter(Mandatory=$True)][String]$Destination
	)

	# Grab the host, so we can set Static Routes and NTP
	$WitnessHost = Get-VMhost -Name $Name

	# Set Static Routes
	Write-Host "Removing Static Route for the Witness Host $Name"
	$Routes = Get-VMHostRoute $WitnessHost | Where-Object {$_.Destination -contains $Destination}
	Remove-VMHostRoute -VMHostRoute $Routes -Confirm:$false
}

Function Set-VsanWitnessNtp {
	<#
	.SYNOPSIS
	This function will set vSAN Witness NTP settings
	.DESCRIPTION
	This function will set vSAN Witness NTP settings
	.PARAMETER Name
	The ESXi hostname of the vSAN Witness Appliance
	.PARAMETER Ntp1
	NTP1 Host address
	.PARAMETER Ntp2
	NTP2 Host address

	.EXAMPLE
	PS C:\> Set-VsanWitnessNtp -Name <Witness FQDN> -Ntp1 <192.5.40.41> -Ntp2 <192.5.41.41>

	.NOTES
	Author                                    : Jase McCarty
	Version                                   : 0.1
	==========Tested Against Environment==========
	VMware vSphere Hypervisor(ESXi) Version   : 6.5
	VMware vCenter Server Version             : 6.5
	PowerCLI Version                          : PowerCLI 6.5.4
	PowerShell Version                        : 3.0
	#>

	# Set our Parameters
	[CmdletBinding()]Param(
	[Parameter(Mandatory=$True)][string]$Name,
	[Parameter(Mandatory=$false)][String]$Ntp1,
	[Parameter(Mandatory=$false)][String]$Ntp2
	)

	# Grab the host, so we can set Static Routes and NTP
	$WitnessHost = Get-VMhost -Name $Name

	Write-Host "Configuring NTP" 
	#Configure NTP server & allow NTP queries outbound through the firewall
	Add-VmHostNtpServer -VMHost $WitnessHost -NtpServer $Ntp1
	Add-VmHostNtpServer -VMHost $WitnessHost -NtpServer $Ntp2

	# Get the state of the NTP client
	Get-VMHostFirewallException -VMHost $WitnessHost | Where-Object {$_.Name -eq "NTP client"} | Set-VMHostFirewallException -Enabled:$true

	Write-Host "Starting NTP Client"
	#Start NTP client service and set to automatic
	Get-VmHostService -VMHost $WitnessHost | Where-Object {$_.key -eq "ntpd"} | Start-VMHostService
	Get-VmHostService -VMHost $WitnessHost | Where-Object {$_.key -eq "ntpd"} | Set-VMHostService -policy "automatic"
	
}

Function Add-VsanWitnessHost {
	<#
	.SYNOPSIS
	This function will add a vSAN Witness Host to the vCenter Server
	.DESCRIPTION
	This function will add a vSAN Witness Host to the vCenter Server
	.PARAMETER Fqdn
	The ESXi hostname of the vSAN Witness Appliance
	.PARAMETER Ip
	Management IP address of the vSAN Witness Host
	.PARAMETER Pass
	Password of the vSAN Witness Host
	.PARAMETER Datacenter
	Name of the datacenter to add the vSAN Witness Host to

	.EXAMPLE
	PS C:\> Add-VsanWitnessHost -Fqdn <Witness FQDN> -Ip <10.198.6.22> -Pass <Witness password> -Datacenter <name of datacenter to add to>

	.NOTES
	Author                                    : Jase McCarty
	Version                                   : 0.1
	==========Tested Against Environment==========
	VMware vSphere Hypervisor(ESXi) Version   : 6.5
	VMware vCenter Server Version             : 6.5
	PowerCLI Version                          : PowerCLI 6.5.4
	PowerShell Version                        : 3.0
	#>
	
	# Set our Parameters
	[CmdletBinding()]Param(
	[Parameter(Mandatory=$true)][String]$Fqdn,
	[Parameter(Mandatory=$true)][String]$Ip,
	[Parameter(Mandatory=$true)][String]$Pass,
	[Parameter(Mandatory=$true)][String]$Datacenter

	)	# Power on the vSAN Witness Appliance

	# Grab the Datacenter that Witnesses will reside in
	$WitnessDC = Get-Datacenter -Name $Datacenter

	# Grab the DNS entry for the guest
	$DnsName = Resolve-DnsName -Name $Ip | Select-Object NameHost

	# If the DNS names match, add by DNS, if they don't add by IP
	if ($DnsName.NameHost -eq $Fqdn){
			Write-Host "Witness IP & Hostname Match"
			$NewWitnessName = $Fqdn 
		} else {
			Write-Host "Witness IP & Hostname Don't Match"
			$NewWitnessName = $Ip
	}

	# Add the new Witness host to vCenter 
	Add-VMHost $NewWitnessName -Location $WitnessDC -user root -password $Pass -Force

}

Function Get-VsanWitnessVMkernel {
	<#
	.SYNOPSIS
	This function will change the vSAN Witness Host VMkernel Interface used for vSAN Traffic
	.DESCRIPTION
	This function will change the vSAN Witness Host VMkernel Interface used for vSAN Traffic
	.PARAMETER Name
	The ESXi hostname of the vSAN Witness Appliance

	.EXAMPLE
	PS C:\> Get-VsanWitnessVMkernel -Name <Witness Name>

	.NOTES
	Author                                    : Jase McCarty
	Version                                   : 0.1
	==========Tested Against Environment==========
	VMware vSphere Hypervisor(ESXi) Version   : 6.5
	VMware vCenter Server Version             : 6.5
	PowerCLI Version                          : PowerCLI 6.5.4
	PowerShell Version                        : 3.0
	#>
	
	# Set our Parameters
	[CmdletBinding()]Param(
	[Parameter(Mandatory=$true)][String]$Name
	)

	# Grab the Datacenter that Witnesses will reside in
	$WitnessVM = Get-VMhost -Name $Name

	# Grab the VMkernel interface(s) with vSAN Traffic Enabled
	$VsanVMkernel = $WitnessVM | Get-VMHostNetworkAdapter -VMKernel | Where-Object {$_.VsanTrafficEnabled -eq $true}

	Switch ($VsanVMkernel.Count) {
		"0" {
			Write-Host "No VMkernel Interfaces are tagged with vSAN Traffic"
			Write-Host "Please enable vSAN Traffic on at least one VMkernel Interface"
		}
		"1" {
			Switch ($VsanVMkernel.Name) {
				"vmk0" {
					Write-Host "vSAN Traffic is tagged on the Management VMkernel Interface:" $VsanVMkernel.Name
				}
				"vmk1" {
					Write-Host "vSAN Traffic is tagged on the Witness VMkernel Interface:" $VsanVMkernel.Name				
				}
				default {
					Write-Host "vSAN Traffic is tagged on an alternate VMkernel Interface:" $VsanVMkernel.Name
				}
			}
		}
		default {
			Write-Host "There are more than 1 VMkernel Interfaces which have vSAN Traffic enabled"
		}

	}

}Function Get-VsanWitnessVMkernel {
	<#
	.SYNOPSIS
	This function will change the vSAN Witness Host VMkernel Interface used for vSAN Traffic
	.DESCRIPTION
	This function will change the vSAN Witness Host VMkernel Interface used for vSAN Traffic
	.PARAMETER Name
	The ESXi hostname of the vSAN Witness Appliance

	.EXAMPLE
	PS C:\> Get-VsanWitnessVMkernel -Name <Witness Name>

	.NOTES
	Author                                    : Jase McCarty
	Version                                   : 0.1
	==========Tested Against Environment==========
	VMware vSphere Hypervisor(ESXi) Version   : 6.5
	VMware vCenter Server Version             : 6.5
	PowerCLI Version                          : PowerCLI 6.5.4
	PowerShell Version                        : 3.0
	#>
	
	# Set our Parameters
	[CmdletBinding()]Param(
	[Parameter(Mandatory=$true)][String]$Name
	)

	# Grab the Datacenter that Witnesses will reside in
	$WitnessVM = Get-VMhost -Name $Name

	# Grab the VMkernel interface(s) with vSAN Traffic Enabled
	$VsanVMkernel = $WitnessVM | Get-VMHostNetworkAdapter -VMKernel | Where-Object {$_.VsanTrafficEnabled -eq $true}

	Switch ($VsanVMkernel.Count) {
		"0" {
			Write-Host "No VMkernel Interfaces are tagged with vSAN Traffic"
			Write-Host "Please enable vSAN Traffic on at least one VMkernel Interface"
		}
		"1" {
			Switch ($VsanVMkernel.Name) {
				"vmk0" {
					Write-Host "vSAN Traffic is tagged on the Management VMkernel Interface:" $VsanVMkernel.Name
				}
				"vmk1" {
					Write-Host "vSAN Traffic is tagged on the Witness VMkernel Interface:" $VsanVMkernel.Name				
				}
				default {
					Write-Host "vSAN Traffic is tagged on an alternate VMkernel Interface:" $VsanVMkernel.Name
				}
			}
		}
		default {
			Write-Host "There are more than 1 VMkernel Interfaces which have vSAN Traffic enabled"
		}

	}

}

Function Set-VsanWitnessVMkernel {
	<#
	.SYNOPSIS
	This function will change the vSAN Witness Host VMkernel Interface used for vSAN Traffic
	.DESCRIPTION
	This function will change the vSAN Witness Host VMkernel Interface used for vSAN Traffic
	.PARAMETER Name
	The ESXi hostname of the vSAN Witness Appliance
	.PARAMETER VMkernel
	The VMkernel to be used for vSAN Traffic

	.EXAMPLE
	PS C:\> Set-VsanWitnessVMkernel -Name <Witness Name> -VMkernel <vmk1>

	.NOTES
	Author                                    : Jase McCarty
	Version                                   : 0.1
	==========Tested Against Environment==========
	VMware vSphere Hypervisor(ESXi) Version   : 6.5
	VMware vCenter Server Version             : 6.5
	PowerCLI Version                          : PowerCLI 6.5.4
	PowerShell Version                        : 3.0
	#>
	
	# Set our Parameters
	[CmdletBinding()]Param(
	[Parameter(Mandatory=$true)][String]$Name,
	[Parameter(Mandatory=$true)][String]$VsanVMkernel
	)

	# Grab the Datacenter that Witnesses will reside in
	$WitnessVM = Get-VMhost -Name $Name

	# Attach to the VMkernel
	$VMkernel = $WitnessVM | Get-VMHostNetworkAdapter -VMKernel -Name $VsanVMkernel

	# Grab the VMkernel interface(s) with vSAN Traffic Enabled
	$VMkernelList = $WitnessVM | Get-VMHostNetworkAdapter -VMKernel 

	Foreach ($VMkernelInterface in $VMkernelList) {

		If ($VMkernelInterface.Name -eq $VMkernel.Name) {

			If ($VMkernelInterface.VsanTrafficEnabled -ne $true) { 
				Write-Host "Enabling vSAN Traffic on $VMkernelInterface"
				$VMkernelInterface | Set-VMHostNetworkAdapter -VsanTrafficEnabled $true -Confirm:$false
			} else { 
				Write-Host "vSAN Traffic already enabled on $VMKernelInterface"
			}
		} else {

			If ($VMkernelInterface.VsanTrafficEnabled -eq $true) { 
				Write-Host "vSAN Traffic is enabled on $VMkernelInterface - Disabling"
				$VMkernelInterface | Set-VMHostNetworkAdapter -VsanTrafficEnabled $false -Confirm:$false
			}
		}
	}

}

Function Get-VsanHostVMkernelTrafficType {
	<#
	.SYNOPSIS
	This function will list any vSAN Host VMkernel Ports tagged for Witness Traffic
	.DESCRIPTION
	This function will list any vSAN Host VMkernel Ports tagged for Witness Traffic
	.PARAMETER Cluster
	The vSAN Cluster to check
	.PARAMETER Type

	.EXAMPLE
	PS C:\> Get-VsanHostVMkernelTrafficType -Cluster <Witness Name>

	.NOTES
	Author                                    : Jase McCarty
	Version                                   : 0.1
	==========Tested Against Environment==========
	VMware vSphere Hypervisor(ESXi) Version   : 6.5
	VMware vCenter Server Version             : 6.5
	PowerCLI Version                          : PowerCLI 6.5.4
	PowerShell Version                        : 3.0
	#>
	
	# Set our Parameters
	[CmdletBinding()]Param(
	[Parameter(Mandatory=$true)][String]$Cluster,
	[Parameter(Mandatory=$false)][String]$Type
	)
    
	# Get the Cluster Name
	$VsanCluster = Get-Cluster -Name $Cluster
	
	# Check to make sure vSAN is enabled
	If($VsanCluster.VsanEnabled){

		# Cycle through each ESXi Host in the cluster
		Foreach ($ESXHost in ($VsanCluster |Get-VMHost |Sort-Object Name)){
		
			# Create an EsxCli variable for the host
			$VMHostEsxCli = Get-EsxCli -VMHost $ESXHost
					
			# Get any VMKernel Interface that is Tagged for vSAN or Witness Traffic
			$VsanNics = $VMHostEsxCli.vsan.network.list.Invoke()

			Foreach ($HostNic in $VsanNics) {
				If ($Type) {
					If ($HostNic.TrafficType -eq $Type) {
						Write-Host "Host:"$ESXHost.Name"-VMkernel:"$HostNic.VmkNicName"-Traffic Type:"$HostNic.TrafficType	
					} 
				} else {
					Write-Host "Host:"$ESXHost.Name"-VMkernel:"$HostNic.VmkNicName"-Traffic Type:"$HostNic.TrafficType
				}
			}
		}
					
	} else {
		
		# Throw and error message that this isn't a vSAN Enabled Cluster.
	Write-Host "The cluster ($Cluster) does not have vSAN enabled."
	}


	
}
Function Set-VsanHostWitnessTraffic {
	<#
	.SYNOPSIS
	This function will list any vSAN Host VMkernel Ports tagged for Witness Traffic
	.DESCRIPTION
	This function will list any vSAN Host VMkernel Ports tagged for Witness Traffic
	.PARAMETER Cluster
	The vSAN Cluster to check
	.PARAMETER Vmk
	The VMkernel Interface to set the traffic type for
	.PARAMETER Option
	Set or Unset

	.EXAMPLE
	PS C:\> Set-VsanHostWitnessTraffic -Cluster <Witness Name> -Vmk <VMkernel> -Option <enable/disable>

	.NOTES
	Author                                    : Jase McCarty
	Version                                   : 0.1
	==========Tested Against Environment==========
	VMware vSphere Hypervisor(ESXi) Version   : 6.5
	VMware vCenter Server Version             : 6.5
	PowerCLI Version                          : PowerCLI 6.5.4
	PowerShell Version                        : 3.0
	#>
	
	# Set our Parameters
	[CmdletBinding()]Param(
	[Parameter(Mandatory=$true)][String]$Cluster,
	[Parameter(Mandatory=$true)][String]$Vmk,
	[Parameter(Mandatory=$false)][String]$Option	
	)
    
	# Get the Cluster Name
	$VsanCluster = Get-Cluster -Name $Cluster
	
	# Check to make sure vSAN is enabled
	If($VsanCluster.VsanEnabled){

		# Cycle through each ESXi Host in the cluster
		Foreach ($ESXHost in ($VsanCluster |Get-VMHost |Sort-Object Name)){
		
			# Create an EsxCli variable for the host
			$VMHostEsxCli = Get-EsxCli -VMHost $ESXHost -V2

			Switch ($Option) {
				"remove" {
					# Remove the witness traffic type from the selected VMkernel
					$WitnessArgs = $VMHostEsxCli.vsan.network.ip.add.CreateArgs()
					$WitnessArgs.interfacename = $Vmk
					Write-Host "Removing vSAN Witness Traffic from" $Vmk "on host" $ESXHost.Name 
					$VMHostEsxCli.vsan.network.remove.invoke($WitnessArgs)
				}
				default {
					# Set the VMKernel Interface desired for Witness Traffic
					$WitnessArgs = $VMHostEsxCli.vsan.network.ip.add.CreateArgs()
					$WitnessArgs.interfacename = $Vmk
					$WitnessArgs.traffictype = "witness"
					Write-Host "Adding vSAN Witness Traffic to " $Vmk "on host" $ESXHost.Name
					$VMHostEsxCli.vsan.network.ip.add.Invoke($WitnessArgs)
				}
			}

		}
					
	} else {
		
		# Throw and error message that this isn't a vSAN Enabled Cluster.
	Write-Host "The cluster ($Cluster) does not have vSAN enabled."
	}


	
}


# Export Functions for 2 Node vSAN
Export-ModuleMember -Function Get-Vsan2NodeForcedCache
Export-ModuleMember -Function Set-Vsan2NodeForcedCache

# Export Functions for the vSAN Witness Deployment
Export-ModuleMember -Function Set-VsanStretchedClusterWitness
Export-ModuleMember -Function New-VsanStretchedClusterWitness
Export-ModuleMember -Function Set-VsanWitnessNetwork
Export-ModuleMember -Function Set-VsanWitnessNetworkRoute
Export-ModuleMember -Function Get-VsanWitnessNetworkRoute 
Export-ModuleMember -Function Remove-VsanWitnessNetworkRoute
Export-ModuleMember -Function Set-VsanWitnessNtp
Export-ModuleMember -Function Add-VsanWitnessHost
Export-ModuleMember -Function Get-VsanWitnessVMkernel
Export-ModuleMember -Function Set-VsanWitnessVMkernel

# Export Functions for vSAN Hosts
Export-ModuleMember -Function Get-VsanHostVMkernelTrafficType
Export-ModuleMember -Function Set-VsanHostWitnessTraffic

# Export Function for VM Placement
Export-ModuleMember -Function Set-VsanStretchedClusterDrsRules