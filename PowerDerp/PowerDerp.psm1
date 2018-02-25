#For formatting the formatting-sensitive XML RSS feed files
$global:Tab = [char]9
$global:Enter = [char]13

#Counter
$global:ItemsAdded

<#########################################################

Certificate-Based Encrypted Stored Credential Management

#########################################################>
function CredentialSecurity
{
	[CmdletBinding()]
	Param(
		[parameter()]
		[Switch]$Encrypt,

		[parameter()]
		[switch]$Decrypt,
		
		[parameter()]
		[switch]$NewCertificate,

		[parameter(Mandatory=$True)]
		[string]$CertPrefix,

		[parameter(Mandatory=$True)]
		$Content
	)
	
	if(($NewCertificate) -or ((Get-ChildItem Cert:\CurrentUser\My | Where-Object {$_.Subject -like "CN=$CertPrefix*"}).count -ne 1))
	{
		New-SelfSignedCertificate -DnsName $CertPrefix -CertStoreLocation "Cert:\CurrentUser\My" -KeyUsage KeyEncipherment,DataEncipherment, KeyAgreement -Type DocumentEncryptionCert
	}
	
	$Cert = Get-ChildItem Cert:\CurrentUser\My | Where-Object {$_.Subject -like "CN=$CertPrefix*"}

	
	Write-Host "Using Cert:"  $Cert.Subject
	if($Encrypt)
	{
		$Password = $Content
		$EncryptedPwd = Protect-CmsMessage -To $Cert.Subject -Content $Password
		return $EncryptedPwd
	}
	elseif($Decrypt)
	{
		$DecryptedPwd = Unprotect-CmsMessage -Path $Content
		return $DecryptedPwd
	}
}
function Create-StoredCredential
{
	[CmdletBinding()]
	Param(
		[parameter(Mandatory=$True)]
		[string]$Username,
		[parameter(Mandatory=$True)]
		[string]$CertPrefix
	)
	
	Write-Host "Creating new Secured $CertPrefix Credential..."
	$Password = Read-Host "What is the password for $Username ? "
	$EncryptedPwd = CredentialSecurity -Encrypt -CertPrefix $CertPrefix -Content $Password
	
	Add-Type -AssemblyName System.Windows.Forms
	$CredentialSave = New-Object -Typename System.Windows.Forms.SaveFileDialog
	$CredentialSave.Filter = "Credentials (*.cred) | *.cred"
	$CredentialSave.ShowDialog() | Out-Null
	$PathToSaveCredential = $CredentialSave.filename
	$EncryptedPwd > $PathToSaveCredential
	return $PathToSaveCredential
}
Function Get-StoredCredential
{
	[CmdletBinding()]
	Param(
		[parameter(Mandatory=$True)]
		[string]$Username,
		[parameter(Mandatory=$True)]
		[string]$CertPrefix,
		[parameter()]
		[string]$PathToStoredCredential
	)

	if(Test-Path "$global:CredentialsPATH\$CertPrefix.cred")
	{
		Write-Host "Credential for $CertPrefix found!"
		$PathToStoredCredential = "$global:CredentialsPATH\$CertPrefix.cred"
	}
	if((!($PathToStoredCredential)) -or (!(Test-Path $PathToStoredCredential)))
	{
		Add-Type -AssemblyName System.Windows.Forms
		$SavedCredential = New-Object -Typename System.Windows.Forms.OpenFileDialog
		$SavedCredential.Filter = "Credentials (*.cred) | *.cred"
		if($SavedCredential.ShowDialog() -eq 'Cancel')
		{
			$PathToStoredCredential = Create-StoredCredential -Username $Username -CertPrefix $CertPrefix
		}
		else{
			$PathToStoredCredential = $SavedCredential.FileName
		}
		
	}
	$EncryptedPwd = Get-Content -path "$PathToStoredCredential"
	$DecryptedPwd = CredentialSecurity -Decrypt -CertPrefix $CertPrefix -Content $PathToStoredCredential  
	$Password = $DecryptedPwd | ConvertTo-SecureString -AsPlainText -Force
	$Credential = New-Object System.Management.Automation.PSCredential ($Username,$Password)
	Return $Credential
}

<#########################################################

Derpibooru Information Gathering

#########################################################>
function Get-StoredDerpibooruAPIKey
{
	Write-Host "Getting Stored Derpibooru API Key"
	$DerpibooruAPIKey = Get-StoredCredential -Username "Your-Derpibooru-Username" -CertPrefix "derpibooru"
	return $DerpibooruAPIKey
}

function Get-DerpibooruWatchedImages
{
	#Connect to your unique feed of watched images and store the resulting raw JSON in a variable
	$Derpibooru =  New-Object Microsoft.PowerShell.Commands.WebRequestSession
	$APIKey = Get-StoredDerpibooruAPIKey
	$MyWatchedImages = iwr https://derpibooru.org/images/watched.json?key=$APIKey  -websession $Derpibooru | ConvertFrom-JSON

	#Split into an array of image objects
	$WatchedImagesArray = @()
	foreach($Image in $MyWatchedImages.images){$WatchedImagesArray += $Image}
	return $WatchedImagesArray
}

# Functions for handeling an encrypted stored list of tags used to distinguish individual feeds based on tag preferec
function Create-StoredPreferredTagList
{

}
function Modify-StoredPreferredTagList
{

}
function Get-StoredPreferredTagList
{
	
}
function Process-DerpibooruIngest
{
	[CmdletBinding()]
	Param(
		[parameter()]
		$WatchedImagesArray,

		[parameter()]
		[switch]$RSSIndividualPosts,

		[parameter()]
		[switch]$RSSCompilationPosts,

		[parameter()]
		[switch]$DownloadImages

	)
}

<#########################################################

RSS Handling

#########################################################>
function Start-RSSFile
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$True)]
		[string]$Tag,

		[Parameter(Mandatory=$True)]
		[string]$RSSLocalFolderPath,

		[Parameter()]
		[string]$RssFeedNamePrefix,

		[Parameter()]
		[string]$RSSFeedTitle,

		[Parameter()]
		[string]$RSSFeedLink,

		[Parameter()]
		[string]$RSSFeedDescription

	)

	#Establishing default values if not defined
	if(!($RssFeedNamePrefix))
	{
		[string]$RssFeedNamePrefix = "DerpibooruTagFeed"
	}
	
	if(!($RSSFeedTitle))
	{
		[string]$RSSFeedTitle = "$RssFeedNamePrefix-$Tag"
	}
	
	if(!($RSSFeedLink))
	{
		[string]$RSSFeedLink = "https://github.com/the4thaggie/PowerDerp"
	}

	if(!($RSSFeedDescription))
	{
		[string]$RSSFeedDescription = "This feed was created with PowerDerp!  Check it out at https://github.com/the4thaggie/PowerDerp"
	}

	$RSSLocalPath = "$RSSLocalFolderPath\$RssFeedNamePrefix-$Tag.rss"
	Remove-Item -Path $RSSLocalPath
	New-Item -Path $RSSLocalPath

	#Begin RSS String
$rsscontent = @"
<?xml version="1.0" encoding="UTF-8" standalone="no" ?>
<rss version="2.0">
$global:Tab<channel>
$global:Tab$global:Tab<title>$RSSFeedTitle</title>
$global:Tab$global:Tab<link>$RSSFeedLink</link>
$global:Tab$global:Tab<description>$RSSFeedDescription</description>
"@
	#End RSS String

	Write-Host "Creating $RSSLocalPath"
	$rsscontent | Out-File -Encoding utf8 "$RSSLocalPath" -Append
}

function Add-RSSItem
{
	[CmdletBinding()]
	Param(
		[parameter(Mandatory=$True)]
		[string]$RSSItemDumpFolderPath,

		[parameter(Mandatory=$True)]
		[string]$RSSItemTitle,

		[parameter(Mandatory=$True)]
		[string]$Tag,

		[parameter(Mandatory=$True)]
		[string]$PubDate,

		[parameter(Mandatory=$True)]
		[int]$Width,

		[parameter(Mandatory=$True)]
		[int]$Height,

		[parameter(Mandatory=$True)]
		[string]$DerpibooruUID,

		[parameter(Mandatory=$True)]
		[string]$ImageURL
	)

	#Begin RSS String
$IndividualItem = @"
$global:Tab$global:Tab<item>
$global:Tab$global:Tab<title>$RSSItemTitle</title>
$global:Tab$global:Tab$global:Tab<description>
$global:Tab$global:Tab$global:Tab$global:Tab<![CDATA[
$global:Tab$global:Tab$global:Tab$global:Tab$global:Tab<a alt="Size: $($Width)x$($Height)" title="Size: $($Width)x$($Height)" href="$($ImageURL)"><img src="$($ImageURL)" alt="Full" /></a>
$global:Tab$global:Tab$global:Tab$global:Tab]]>
$global:Tab$global:Tab$global:Tab</description>
$global:Tab$global:Tab$global:Tab<pubDate>$($PubDate)</pubDate>
$global:Tab$global:Tab$global:Tab<link>https://derpibooru.org/$($DerpibooruUID)</link>
$global:Tab$global:Tab$global:Tab<guid>https://derpibooru.org/$($DerpibooruUID)</guid>
$global:Tab$global:Tab</item>
"@
	#End RSS String

	$global:ItemsAdded += 1
	$RSSDUMP = "$RSSItemDumpFolderPath\RSSItemDump-$Tag.rss"
	try{
			$RSSDumpContent = Get-Content $RSSDump
			if([string]$RSSDumpContent -notmatch [string]$DerpibooruUID)
			{
				$IndividualItem | Out-File -Encoding utf8 $RSSDUMP -Append
			}
		}
		catch{Write-Host "There are no items for the tag: $Tag"}
}

Function End-RSSFile
{
	[CmdletBinding()]
	Param(
			[parameter(Mandatory=$True)]
			[string]$RSSItemDumpFolderPath,

			[Parameter(Mandatory=$True)]
			[string]$RSSLocalFolderPath,

			[Parameter()]
			[string]$RssFeedNamePrefix,

			[parameter(Mandatory=$True)]
			[string]$Tag
		)

	$RSSDUMP = "$RSSItemDumpFolderPath\RSSItemDump-$Tag.rss"
	$RSSFeedFile = "$RSSLocalFolderPath\$RssFeedNamePrefix-$Tag.rss"

	#Add every individual RSS item previously stored (as formatted XML content) in middle of RSS feed file
	if(Test-Path($DUMP))
	{
        $DumpContent = Get-Content $Dump
        $DumpContent | Out-File -Encoding utf8 $RSSFeedFile -Append
	}
	else{Write-Host "There are no items for the tag: $Tag"}

	<#The following check ensures the final formatting on RSS feed file is correct for the amount
	of items added on this iteration of running the script#>
	if($global:ItemsAdded -eq 0)
	{
$rsscontent = @"
$global:Enter$global:Tab</channel>
</rss>
"@
	}
	else
	{
$rsscontent = @"
$global:Tab</channel>
</rss>
"@
	}
    #Add the final formatting at the end of the RSS feed file
    $rsscontent | Out-File -Encoding utf8 $RSSFeedFile -Append
}


<#########################################################

Downloading

#########################################################>
Function Download-WebM
{
    [Cmdletbinding()]
	Param(
		[parameter(Mandatory=$True)]
		[string]$Path,
		[parameter(Mandatory=$True)]
		[string]$URL,
		[parameter(Mandatory=$True)]
		[string]$DerpibooruUID,
		[parameter()]
		[string]$TagName,
		[parameter()]
		[switch]$Verbose
	)
    $TagName= $TagName -replace ",",""
    $OutputFileName = "$DerpibooruUID-$TagName.webm"
    if(!(Test-Path -Path "$Path\$OutputFileName"))
    {
        if($Verbose)
		{
			Write-Host "Downloading WebM: $OutputFileName"
        }
		Invoke-WebRequest -Uri $URL -OutFile "$Path\$OutputFileName"
    }
}
<#########################################################

Uploading

#########################################################>
Function Send-FTP
{
    [CmdletBinding()]
	Param(
		[Parameter(Mandatory=$True)]
		[string]$FTPHost,

		[Parameter()]
		[string]$FTPFolder,

		[Parameter()]
		[System.Management.Automation.PSCredential]$FTPCredential,

		[Parameter()]
		[string]$Username,

		[Parameter()]
		[string]$Password,

		[Parameter(Mandatory=$True)]
		[string]$RSSLocalFolderPath
	)
	
	#Define the URI where the files will be uploaded to
	if(!($FTPFolder))
	{
		$FTPFolder = "/"
	}
	$FTPFullFolderPath = "$FTPHost/$FTPFolder" 
	$FTPConnection = New-Object System.Net.WebClient
	
	#Define the login credentials for the FTP host
	if($FTPCredential)
	{
		$FTPConnection.Credentials = $FTPCredential
	}
	elseif(($Username) -and ($Password))
	{
		$FTPConnection.Credentials = New-Object System.Net.NetworkCredential($Username,$Password) 
	}
	else
	{
		$Username = Read-Host "What is your FTP Username?  "
		$Password = Read-Host "What is your FTP Password?  "
		$FTPConnection.Credentials = New-Object System.Net.NetworkCredential($Username,$Password) 
	}
     

	#Upload all files with the .rss extension to FTP
    foreach($item in (dir $RSSLocalFolderPath "*.rss"))
    { 
        "Uploading $item..." 
        try
        {
            $uri = New-Object System.Uri($FTPFullFolderPath+$item.Name)
            $FTPConnection.UploadFile($uri, $item.FullName)
        } 
        catch [Exception] 
        {
            $onNetwork = "0"
            write-host $_.Exception.Message;
        }           
    } 
}