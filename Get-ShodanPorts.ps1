#
# Script to use Shodan API to get subdomain, IP, and port data from a given domain name. Can optionally supplement with input files containing list of subdomains and IPs from other tools. Output to CSV.
#

param (
	[Parameter(Mandatory=$false,Position=1)][string]$ApiKey,
	[Parameter(Mandatory=$false,Position=2)][string]$Domain,
	[Parameter(Mandatory=$false,Position=3)][string]$SubdomainFile,
	[Parameter(Mandatory=$false,Position=4)][string]$IpFile,
	[Parameter(Mandatory=$false,Position=5)][string]$OutFile
)

Write-Host " "

# Func to show usage info and exit
function ShowUsage() {
	Write-Host "[!] Param error"
	Write-Host " "
	Write-Host "Usage:"
	Write-Host "`tGet-ShodanPorts.ps1 -ApiKey <api_key> -Domain <domain_name> -SubdomainFile <input_filepath> -IpFile <input_filepath> -OutFile <output_filepath>"
	Write-Host " "
	Write-Host "Example:"
	Write-Host "`tGet-ShodanPorts.ps1 -ApiKey asdfasdfasdfasdfasdfasdfasdf -Domain domain.com -OutFile shodan.csv"
	Write-Host " "
	Exit
}

# Checking pre-reqs
Write-Host "[+] Checking pre-reqs"
Write-Host " "
if (!($ApiKey) -or (!($Domain))) {
	ShowUsage
}
if ($SubdomainFile -and (!(Test-Path $SubdomainFile))) {
	Write-Host "[!] Subdomain input file not valid/readable"
	Write-Host " "
	ShowUsage
}
if ($IpFile -and (!(Test-Path $IpFile))) {
	Write-Host "[!] IP address input file not valid/readable"
	Write-Host " "
	ShowUsage
}
if ($OutFile) {
	"" | Set-Content $OutFile -ErrorAction SilentlyContinue
	if (!(Test-Path $OutFile)) {
		Write-Host "[!] CSV output file path not valid/writable"
		Write-Host " "
		ShowUsage
	}
}

# Create empty array to hold recon data objs
$global:shodanResults = @()

# Function to create a new results object and add to our array of recon data
function createResultsObj($domainVal, $subVal, $ipVal, $portVal, $sourceVal, $ownerVal, $geoVal) {
	$resultsObj = New-Object -TypeName PSObject
	Add-Member -InputObject $resultsObj -MemberType NoteProperty -Name "Domain" -Value $domainVal
	Add-Member -InputObject $resultsObj -MemberType NoteProperty -Name "Subdomain" -Value $subVal
	Add-Member -InputObject $resultsObj -MemberType NoteProperty -Name "IpAddress" -Value $ipVal
	Add-Member -InputObject $resultsObj -MemberType NoteProperty -Name "Ports" -Value $portVal
	Add-Member -InputObject $resultsObj -MemberType NoteProperty -Name "Owner" -Value $ownerVal
	Add-Member -InputObject $resultsObj -MemberType NoteProperty -Name "Geo" -Value $geoVal
	Add-Member -InputObject $resultsObj -MemberType NoteProperty -Name "Source" -Value $sourceVal
	$global:shodanResults += $resultsObj
}

# Populate the recon array with data from subdomain input file
if ($SubdomainFile) {
	Write-Host "[+] Populating the recon data array with contents of subdomain input file"
	Write-Host " "
	$SubdomainFileData = Get-Content $SubdomainFile | Sort-Object -Unique
	foreach ($subdomain in $SubdomainFileData) {
		createResultsObj $Domain $subdomain "N/A" "N/A" $SubdomainFile "N/A" "N/A"
	}
}

# Populate the recon array with data from IPs input file
if ($IpFile) {
	Write-Host "[+] Populating the recon data array with contents of IPs input file"
	Write-Host " "
	$IpFileData = Get-Content $IpFile | Sort-Object -Unique
	foreach ($ip in $IpFileData) {
		createResultsObj $Domain "N/A" $ip "N/A" $IpFile "N/A" "N/A"
	}
}

# Add domain root recon array if not present
if ($Domain -notin $shodanResults.Subdomain) {
	createResultsObj $Domain $Domain "N/A" "N/A" "Domain Root" "N/A" "N/A"
}

# Get subdomains from Shodan API and add them to our recon data
Write-Host "[+] Getting list of subdomains from Shodan API and adding to our recon data"
Write-Host " "
$Uri = ("https://api.shodan.io/dns/domain/" + $Domain + "?key=" + $ApiKey)
[PSObject]$response = Invoke-RestMethod -Method GET -Uri $Uri
ForEach ($subdomain in $response.data){
	if ($subdomain.subdomain) {
		if ($subdomain.subdomain -notin $shodanResults.Subdomain) {
			createResultsObj $Domain ($subdomain.subdomain + "." + $domain) "N/A" "N/A" "Shodan" "N/A" "N/A"
		}
	}
} 

# Resolve each subdomain in our recon data to an IP address
Write-Host "[+] Resolving each subdomain in our recon data to an IP address and adding to our recon data"
Write-Host " "
ForEach ($resultsObj in $shodanResults | where {$_.Subdomain -ne "N/A" -and $_.IpAddress -eq "N/A"}) {
	$response = Resolve-DnsName -Name $resultsObj.Subdomain -Server 8.8.8.8 -ErrorAction SilentlyContinue
	if ($response) {
		if ($response.namehost) {
			$record = $response[0].namehost
		} elseif ($response.ipaddress) {
			$record = ($response | Where-Object {$_.ipaddress -match "^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"})[0].ipaddress
		} else {
			$record = "No A/CNAME Record"
		}
	} else {
		$record = "No A/CNAME Record"
	}
	$resultsObj.IpAddress = $record
}

# Check for any new subdomains of the target domain discovered via DNS lookups (CNAMEs)
Write-Host "[+] Checking for any new subdomains of the target domain discovered via DNS lookups (CNAMEs)"
Write-Host " "
ForEach ($resultsObj in $shodanResults | where {$_.IpAddress -match $Domain -and $_.IpAddress -notin $shodanResults.Subdomain}) {
	$response = Resolve-DnsName -Name $resultsObj.IpAddress -Server 8.8.8.8 -ErrorAction SilentlyContinue
	if ($response) {
		if ($response.namehost) {
			$record = $response[0].namehost
		} elseif ($response.ipaddress) {
			$record = ($response | Where-Object {$_.ipaddress -match "^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"})[0].ipaddress
		} else {
			$record = "No A/CNAME Record"
		}
	} else {
		$record = "No A/CNAME Record"
	}
	createResultsObj $Domain $resultsObj.IpAddress $record "N/A" "DNS CNAME" "N/A" "N/A"
}

# Get list of open ports from Shodan API for each IP address
Write-Host "[+] Getting list of open ports from Shodan API for each IP address in our recon data"
Write-Host " "
ForEach ($resultsObj in $shodanResults | where {$_.IpAddress -match "^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"}) {
	try {
		$Uri = ("https://api.shodan.io/shodan/host/" + $resultsObj.IpAddress + "?key=" + $ApiKey)
		[PSObject]$response = Invoke-RestMethod -Method GET -Uri $Uri
		sleep 1
		$ports = ""
		$response.ports | %{$ports += [String]$_ + ", "}
		$resultsObj.Ports = $ports
		$resultsObj.Owner = $response.org
		$resultsObj.Geo = $response."country_name"
		if ($resultsObj.Source -notcontains "Shodan") {
			$resultsObj.Source += " / Shodan"
		}
	} catch {
		Continue
	}
}

# Printing output to console or to output file
if ($OutFile) {
	Write-Host "[+] Open output file to feast your eyes upon the awesome power of Shodan!!!"
	Write-Host " "
	$shodanResults | Sort-Object -Unique Subdomain | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $OutFile -Force:$true -Confirm:$false
} else {
	Write-Host "[+] Feast your eyes upon the awesome power of Shodan!!!"
	$shodanResults | Sort-Object -Unique Subdomain | ft
}

# Done
Write-Host "[+] Done!"
Write-Host " "

