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
       This function will enable/disable Forced Caching across hosts on a 2 Node vSAN Cluster
    .DESCRIPTION
       This function will enable/disable Forced Caching across hosts on a 2 Node vSAN Cluster

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
		[Parameter(Mandatory=$True)][string]$Server,
		[Parameter(Mandatory=$true)][String]$Cluster,
		[Parameter(Mandatory=$true)][String]$Datastore,
		[Parameter(Mandatory=$true)][String]$WitnessOVAPath,
		[Parameter(Mandatory=$true)][String]$WitnessName,
		[Parameter(Mandatory=$true)][String]$WitnessPass,
		[Parameter(Mandatory=$true)][String]$WitnessSize,
		[Parameter(Mandatory=$true)][String]$WitnessPG1,
		[Parameter(Mandatory=$true)][String]$WitnessPG2
		)

		# Grab a random host in the cluster to deploy to
		$TargetHost = Get-Cluster $Cluster | Get-VMHost | Where-Object {$_.PowerState -eq "PoweredOn" -and $_.ConnectionState -eq "Connected"} |Get-Random

		# Grab a random datastore
		$TargetDatastore = Get-Datastore -Name $Datastore

		# Grab the OVA properties from the vSAN Witness Appliance OVA
		$ovfConfig = Get-OvfConfiguration -Ovf $WitnessOVAPath

		# Set the Network Port Groups to use, the deployment size, and the root password for the vSAN Witness Appliance
		$ovfconfig.NetworkMapping.Management_Network.Value = $WitnessPG1
		$ovfconfig.NetworkMapping.Witness_Network.Value = $WitnessPG2
		$ovfconfig.DeploymentOption.Value = $WitnessSize
		$ovfconfig.vsan.witness.root.passwd.value = $WitnessPass

		# Import the vSAN Witness Appliance 
		Import-VApp -Source $WitnessOVAPath -OvfConfiguration $ovfConfig -Name $WitnessName -VMHost $TargetHost -Datastore $TargetDatastore -DiskStorageFormat Thin

}

Function Set-VsanWitnessNetwork {

	# Set our Parameters
	[CmdletBinding()]Param(
	[Parameter(Mandatory=$True)][string]$Name,
	[Parameter(Mandatory=$true)][String]$Pass,
	[Parameter(Mandatory=$true)][String]$VMkernel,
	[Parameter(Mandatory=$false)][String]$VMkernelIp,
	[Parameter(Mandatory=$false)][String]$NetMask,
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

