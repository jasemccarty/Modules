# Module for vSAN Stretched Cluster & 2 Node

I took some of my existing scripts and combined them into a module

Setup requires the psd1/psm1 files to be put in a VSANSC2N directory under Powershell Modules or you can use Import-Module and the path to these.

Tested on PowerCLI 6.5.4 against vSphere 6.5/vSAN 6.6

Not supported by VMware, use at your own risk.

# Functions for 2 Node vSAN
Get-Vsan2NodeForcedCache – Determine state of DOMOwnerForceWarmCache of a cluster

Set-Vsan2NodeForcedCache – Set DOMOwnerForceWarmCache for a cluster, good for Hybrid 2 Node
 
# Functions for the vSAN Witness Deployment
Set-VsanStretchedClusterWitness – Set the vSAN Witness Appliance for a Stretched Cluster

New-VsanStretchedClusterWitness – Deploy a new vSAN Witness Appliance

Set-VsanWitnessNetwork – Set either vmk0 or vmk1 for a vSAN Witness Appliance

Set-VsanWitnessNetworkRoute – Set a static route for a vSAN Witness Appliance 

Get-VsanWitnessNetworkRoute – Get a list of any static routes

Remove-VsanWitnessNetworkRoute – Remove a static route

Set-VsanWitnessNtp – Set NTP on a vSAN Witness Appliance

Add-VsanWitnessHost – Add a vSAN Witness Host to vCenter

Get-VsanWitnessVMkernel – Get the current VMkernel that is tagged for vSAN Traffic (alert if 0 or >2)

Set-VsanWitnessVMkernel – Set a VMkernel for vSAN Traffic – Only 1 and remove any extras
 
# Functions for vSAN Hosts
Get-VsanHostVMkernelTrafficType – Get a list of traffic types for all hosts in a cluster

Set-VsanHostWitnessTraffic – Set Witness traffic for hosts in a 2 Node cluster
 
# Functions for Stretched Clusters or 2 Node
Set-VsanStretchedClusterDrsRules - Place VM’s on either site based on a VM tag

Set-VsanStretchedClusterPreferredFaultDomain - Set or Toggle the Current Preferred Fault Domain

