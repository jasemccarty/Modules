

Function Connect-HyTrustKeyControl {

	<#
    .SYNOPSIS
    This function connects to a HyTrust KeyControl Server
    .DESCRIPTION
    This function connects to a HyTrust KeyControl Server
    .PARAMETER KeyControlServer
    The HyTrust KeyControl Server to Connect to
    .PARAMETER User
    The HyTrust KeyControl Server Username
    .PARAMETER Password
    The HyTrust KeyControl Server Password

	.EXAMPLE
	PS C:\> Connect-HyTrustKeyControl -KeyControlServer $KeyControlServer -user username -password password

	.NOTES
	Author                                    : Jase McCarty
	Version                                   : 0.1
    Requires                                  : PowerCLI 11.0
    ==========Tested Against Environment==========
	VMware vSphere Hypervisor(ESXi) Version   : 6.7
	VMware vCenter Server Version             : 6.7
	PowerCLI Version                          : PowerCLI 11.0
	PowerShell Core Version                   : 6.1
	#>
	
	# Set our Parameters
	[CmdletBinding()]Param(
    [Parameter(Mandatory=$true)][String]$KmsServer,
    [Parameter(Mandatory=$false)][Int32]$KmsPort,
    [Parameter(Mandatory=$false)][String]$KmsUser,
    [Parameter(Mandatory=$false)][String]$KmsPassword
    )

        If ($KmsPassword) {
            $KmsPass = $KmsPassword | ConvertTo-SecureString -AsPlainText -Force
        }

    #Build the headers
    $headers=@{}
    $headers.add("username",$user)
    $headers.add("password",$password)

    # If the KMS Port hasn't been set, then set it
    If (-Not ($KmsPort)) {
        $KmsPort = "5696"
    }

    #Invoke the proper method to login and capture the authentication token as a variable (must be used to authenticate later API calls)
    $Token = Invoke-Restmethod -method POST -Uri "https://$KmsServer/v4/kc/login/" -body $headers
    
    #Build new iDictionary object for the headers to future API calls
    $Global:HyTrustToken=@{}
    $Global:HyTrustToken.add("Auth-Token",$Token.access_token)
    
    $Global:KeyControlServer = New-Object PSObject -Property @{            
        Name             = $KmsServer                 
        Port             = $KmsPort              
        User             = $KmsUser            
        Password         = $KmsPassword            
    }  

}
Function DisConnect-HyTrustKeyControl {

	<#
    .SYNOPSIS
    This function connects to a HyTrust KeyControl Server
    .DESCRIPTION
    This function connects to a HyTrust KeyControl Server
    .PARAMETER KeyControlServer
    The HyTrust KeyControl Server to Connect to
    .PARAMETER User
    The HyTrust KeyControl Server Username
    .PARAMETER Password
    The HyTrust KeyControl Server Password

	.EXAMPLE
	PS C:\> Connect-HyTrustKeyControl -KeyControlServer $KeyControlServer -user username -password password

	.NOTES
	Author                                    : Jase McCarty
	Version                                   : 0.1
    Requires                                  : PowerCLI 11.0
    ==========Tested Against Environment==========
	VMware vSphere Hypervisor(ESXi) Version   : 6.7
	VMware vCenter Server Version             : 6.7
	PowerCLI Version                          : PowerCLI 11.0
	PowerShell Core Version                   : 6.1
	#>
	
	# Set our Parameters
	[CmdletBinding()]Param(
    [Parameter(Mandatory=$true)][String]$KmsServer,
    [Parameter(Mandatory=$false)][String]$KmsUser,
    [Parameter(Mandatory=$false)][String]$KmsPassword
    )

    Write-Host $Global:KeyControlServer
    Write-Host $Global:KeyControlServer.Name 

    #Logout so the token is no longer valid
    Invoke-Restmethod -method POST -Uri "https://$KmsServer/v4/kc/logout/" -headers $Global:HyTrustToken


}

Function Invoke-HyTrustKeyControlBackup {

	<#
    .SYNOPSIS
    This function performs a HyTrust KeyControl Backup
    .DESCRIPTION
    This function performs a HyTrust KeyControl Backup
    .PARAMETER Cluster
    The cluster the rekey should be performed on
    .PARAMETER Depth
    Shallow or Deep?
    .PARAMETER KMS
    Select the KMS to be used

	.EXAMPLE
	PS C:\> Invoke-HyTrustKeyControlBackup -KmsServer <KMS Server> -BackupDir <Backup Directory Path> -Days <Integer number of days>

	.NOTES
	Author                                    : Jase McCarty
	Version                                   : 0.1
    Requires                                  : PowerCLI 11.0
    ==========Tested Against Environment==========
	VMware vSphere Hypervisor(ESXi) Version   : 6.7
	VMware vCenter Server Version             : 6.7
	PowerCLI Version                          : PowerCLI 11.0
	PowerShell Core Version                   : 6.1
	#>
	
	# Set our Parameters
	[CmdletBinding()]Param(
    [Parameter(Mandatory=$false)][String]$KmsServer,    
    [Parameter(Mandatory=$true)][String]$BackupDir,
    [Parameter(Mandatory=$true)][Int32]$Days
    )

    # Get the Date Values
    $CurrentDate = Get-Date
    $DeleteDate = $CurrentDate.AddDays($DaysOld)

    # Remove the old backups
    Get-ChildItem $BackupDir -Recurse | Where-Object { $_.LastWriteTime -lt $DeleteDate } | Remove-Item

    #$BackupDir = "/Users/jase/htbackup/"
    #$DaysOld = "-7"

    #Build iDictionary object for calls to system_backup method
    $Params =@{}
    $Params.add("verify","false")
    
    $KmsServer = $Global:KeyControlServer.Name

    Write-Host $KmsServer

    #Build new iDictionary object for the headers to future API calls
    $Token2=@{}
    $Token2.add("Auth-Token",$Global:HyTrustToken.access_token)

    #
    #Take a system backup - this only creates the backup and does not download it
    Invoke-Restmethod -method POST -Uri "https://"$KmsServer"/v4/system_backup/" -headers $Token2 -body $Params
    #
    #Construct date for file name yyyymmdd
    $MyDate1 = get-date -uformat %Y
    $MyDate2 = get-date -uformat %m
    $MyDate3 = get-date -uformat %d
    $MyDate = $MyDate1 + $MyDate2 + $MyDate3
    #
    #Construct time for file name hhmmss
    $MyTime1 = get-date -uformat %H
    $MyTime2 = get-date -uformat %M
    $MyTime3 = get-date -uformat %S
    $MyTime = $MyTime1 + $MyTime2 + $MyTime3
    #
    #File name will be yyyymmdd.hhmmss_servername.bu
    $FileName = $BackupDir + "" + $MyDate + "." + $MyTime + "_" + $shortserver + ".bu"
    #
    #Download the backup to a file (needs to have a .bu extension) in the location of your choice
    Invoke-Restmethod -method GET -Uri "https://$KmsServer/v4/system_backup/" -headers $Token2 -body $Params -OutFile $FileName
    #

}