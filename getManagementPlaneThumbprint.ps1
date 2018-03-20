$verboseLogFile="nsxt20-vghetto-lab-deployment.log"
Function My-Logger {
    param(
    [Parameter(Mandatory=$true)]
    [String]$message
    )

    $timeStamp = Get-Date -Format "MM-dd-yyyy_hh:mm:ss"

    Write-Host -NoNewline -ForegroundColor White "[$timestamp]"
    Write-Host -ForegroundColor Green " $message"
    $logMessage = "[$timeStamp] $message"
    $logMessage | Out-File -Append -LiteralPath $verboseLogFile
}

$NSXTMgrIPAddress = "192.168.20.201"
$NSXTMgrHostname = "192.168.20.201"
$NSXAdminUsername = "admin"
$NSXAdminPassword = "VMware1!"

Connect-NsxtServer -Server $NSXTMgrHostname -Username $NSXAdminUsername -Password $NSXAdminPassword -WarningAction SilentlyContinue
$nsxMgrID = (Get-NsxtService -Name "com.vmware.nsx.cluster.nodes").list().results.id

My-Logger "Hello"

$nsxMgrID | ForEach-Object {
    $thumbprint = (Get-NsxtService -Name "com.vmware.nsx.cluster.nodes").get($_).manager_role.api_listen_addr.                                           certificate_sha256_thumbprint
    My-Logger $thumbprint
    if ($thumbprint) { Set-Variable -Name "tp" -Value $thumbprint }
}

My-Logger "Management thumbprint is $tp"
My-Logger "Hello"


