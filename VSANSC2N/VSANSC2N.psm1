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
Function Set-VsanStretchedClusterWitness {

    # Set our Parameters
    [CmdletBinding()]Param(

    [Parameter(Mandatory=$True)]
    [string]$ClusterName,
  
    [Parameter(Mandatory = $true)]
    [String]$NewWitness
  
  )

    # Check to see the cluster exists
    Try {
	    # Check to make sure the New Witness Host has already been added to vCenter
	    $Cluster = Get-Cluster -Name $ClusterName -ErrorAction Stop
    }
	    Catch [VMware.VimAutomation.Sdk.Types.V1.ErrorHandling.VimException.VimException]
    {
	    Write-Host "The cluster, $Clustername, was not found.               " -foregroundcolor red -backgroundcolor white
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

    # Set our Parameters
    [CmdletBinding()]Param(
    [Parameter(Mandatory=$True)]
    [string]$ClusterName,
  
    [Parameter(Mandatory = $true)]
    [ValidateSet('enable','disable')]
    [String]$ForceCache
  )
    
  # Get the Cluster Name
  $Cluster = Get-Cluster -Name $ClusterName
  
  # Check to ensure we have either enable or disable, and set our values/text
  Switch ($ForceCache) {
      "disable" { 
          $FORCEVALUE = "0"
          $FORCETEXT  = "Default (local) Read Caching"
          }
      "enable" {
          $FORCEVALUE = "1"
          $FORCETEXT  = "Forced Warm Cache" 
          }
      default {
          write-host "Please include the parameter -ForceCache enable or -ForceCache disabled"
          exit
          }
      }
      # Display the Cluster
      Write-Host Cluster: $($Cluster.name)
      
      # Check to make sure we only have 2 Nodes in the cluster and vSAN is enabled
      $HostCount = $Cluster | Select-Object @{n="count";e={($_ | Get-VMHost).Count}}
      If($HostCount.count -eq "2" -And $Cluster.VsanEnabled){
  
          # Cycle through each ESXi Host in the cluster
          Foreach ($ESXHost in ($Cluster |Get-VMHost |Sort Name)){
          
            # Get the current setting for diskIoTimeout
            $FORCEDCACHE = Get-AdvancedSetting -Entity $ESXHost -Name "VSAN.DOMOwnerForceWarmCache"
                    
              # By default, if the IO Timeout doesn't align with KB2135494
            # the setting may or may not be changed based on Script parameters
                  If($FORCEDCACHE.value -ne $FORCEVALUE){
  
              # Show that host is being updated
              Write-Host "2 Node $FORCETEXT Setting for $ESXHost"
              $FORCEDCACHE | Set-AdvancedSetting -Value $FORCEVALUE -Confirm:$false
  
                  } else {
  
              # Show that the host is already set for the right value
              Write-Host "$ESXHost is already configured for $FORCETEXT"
  
          }
      }
                      
      } else {
          
          # Throw and error message that this isn't a 2 Node Cluster.
      Write-Host "The cluster ($ClusterName) is not a 2 Node cluster and/or does not have vSAN enabled."
      }
  
  

}

Function Set-VsanStretchedClusterDrsRules {
	
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