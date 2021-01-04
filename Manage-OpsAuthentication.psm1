<#
  Purpose: Support authentication with the vRealize Operations Manager RESTful API
  Version: 1.9 (2021/1/4) 
  Author: Craig Risinger
  License: freeware, without any warranty
  
  
  To load these functions:
    Import-Module <pathToThisFile>.psm1  

    # If Import-Module fails, options include:
    #  1. See about_Execution_Policies in PowerShell doc, notice and use the Unblock-File option. Then retry Import-Module.
    #  2. Execute the definition of the functions by highlighting in ISE then Run Selection.
    #
  
  To see commands available from this module:
    Get-Command -Module <nameOfThisModule>  

  To get help including examples:
    Get-Help <functionName> -Full


  To see how to get a session:
    Get-Help Get-OpsSession -Full    

  Typical way to get a session:
    $server,$authtoken = Get-OpsSession -returnValues -TrustAllCerts 

  To see how to store and use multiple server/authtoken pairs (for working across multiple vROps clusters):
    Get-Help -Full Get-OpsAuthHash

#>


function Get-OpsSession {
<#
    .SYNOPSIS
      Get a sort of session with vROps by prompting for login information and returning server name and authentication token values. Save those in $server and $authtoken.
  
    .DESCRIPTION
      This function prompts you for login input, gets an authentication token, and returns the relevant values, which you should save in variables.
      Recommended variable names are $server and $authtoken to obviate some typing.
      Some PowerShell vROps commands have parameters for -server and -authtoken. Many of those commands will inherit
      any values you have already set at the command line for variables called $server and $authtoken. So, if you set valid
      values for $server and $authtoken, you can just say "Do-OpsSomething" instead of "Do-OpsSomething -server $server -authtoken $authtoken"
      
    .EXAMPLE
      $server,$authtoken = Get-OpsSession -returnValues
  
      Prompt user for login information. Return both the servername of the vROps and a valid authentication token for it, and
      save those in $server and $authtoken. It is recommended to use `'$server`' and `'$authtoken`' as the variable names, because
      many functions will inherit those values without having to specify -server or -authtoken parameters.
  
   .EXAMPLE
      $server,$authtoken = Get-OpsSession -returnValues -TrustAllCerts
  
      -TrustAllCerts means that your PowerShell session will trust self-signed certificates when attempting secure connections.
    
#>

  [cmdletbinding()]Param(
    # Location of the vROps to login to, usually FQDN. If not specified as a parameter, you will be prompted.
    $server,

    # Name of the authentication source you choose on the login page of the vROps UI. If not specified as a parameter, you will be prompted.
    $vRopsAuthSource,

    # Username for login into vROps. If not specified as a parameter, you will be prompted.
    $username,
    
    # If used, function returns values which can be saved into $server,$authtoken. 
    # Note that we do not want to display authtoken carelessly on the screen, because that is equivalent to a username and password. So if you do not read the doc and
    # just run the command without this parameter, we throw an error rather than risk displaying sensitive information.
    [switch]$returnValues,

    # If used, all certificates will be trusted. Useful if your vROps certificate is not signed by a regular Certificate Authority (CA).
    [switch]$TrustAllCerts,

    # Security protocol to be used for connections. vROps 7.5 requires TLS 1.2.
    $SecurityProtocol = 'TLS12'
  )
  
  # Prompt users who have not read the help
  if (-not $returnValues ) {
      throw "Do `"Get-Help -Full Get-OpsSession`" for full details. In short, invoke this function saving output into variables called `$server and `$authtoken, like this: 

          `$server,`$authtoken = Get-OpsSession -returnValues

      "
  }

  # security
  if ( $TrustAllCerts ) {
      Set-SecurityCertificateSettings -TrustAllCerts
  }
  Set-SecurityProtocol $SecurityProtocol   

  # prompt for login info
  if ( -not $server ) { $server = Read-Host -Prompt "Enter FQDN of vROps server" }
  if ( -not $local:vropsAuthSource ) { $local:vropsAuthSource = Read-Host -Prompt "Enter name of the Authentication Source for logging into vROps. If local user, enter nothing or `"local`"." }
  if ( -not $local:vropsAuthSource ) { $local:vropsAuthSource = 'local' } # default
  if ( -not $local:username) { $local:username = Read-Host -prompt "Enter username for $server" }
  $local:secStringPassword = Read-Host -asSecureString -Prompt "Enter password for username $($username) on server $($server)"
  $local:BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secStringPassword)
  $local:password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

  $authtoken = Get-OpsAuthToken -noMetadata -Server $server -username $username -password $password -vROpsAuthSource $vropsAuthSource 

  if ($returnValues) {
      $server,$authtoken
  }
      
}


function Get-OpsAuthHash {
<#
  .SYNOPSIS
    Get a vrops-to-authenticationToken hashtable, to facilitate operating on multiple vROps servers.

  .DESCRIPTION
    Return a hashtable where the key is a vROps FQDN and the value is a corresponding authentication token.
    Once you have this, it is easier to do commands across multiple vROps, because this associates vROps name to an authentication
    token. See examples.

  .EXAMPLE
    # Read list of vROps cluster names
    $servers = Get-Content <listOfvRopsClusters.txt>
    
    # Get authtoken for the same local username on each server, but prompt user for the password on each server (in case 
    # they are different across servers). Ignore SSL cert errors.
    $myCreds = $servers | Get-OpsAuthHash -username myServiceAcct -TrustAllCerts

    # Using in a loop to do same command across multiple vROps
    $servers | foreach {
        $s = $_
        $a = $myCreds[$s]
        write-host "Getting all notification rules on server $($s):"
        Get-OpsAllNotificationRules -server $s -authtoken $a
    }

  .EXAMPLE
    # Prompt user on each server for both username and password.
    $myCreds = Get-OpsAuthHash -serverList $servers -SameUsernames $false 

  .EXAMPLE
    # Prompt user once for username to be used on all servers, but prompt user on each server for password for AD login via MyMainAD auth source on vROps.
    $myCreds = $servers | Get-OpsAuthHash -SameUsernames $true  -vropsAuthSource MyMainAD

  .EXAMPLE
    # Take existing AuthHash and add new servers or correct mistaken or expired authtoken entries.E.g. maybe $ah has authtokens for myVROps01..22, except
    # you messed up typing the password for myVRops04 and did not get a valid authtoken for it, and you also need to add one for myVROps23.
    $ah = @("myVRops23","myVRops04") | Get-OpsAuthHash -AuthHash $ah
     


#>

    [cmdletbinding()]Param(
        [parameter(Mandatory=$true,ValueFromPipeline=$true)][string[]]
        # List of the FQDNs of all vROps for which you want to get auth tokens.
        $serverList,

        [string]
        $username,

        [string]
        $vRopsAuthSource = 'local',

        # Optional. Existing hashtable of server-to-authentication token (so that you can add to what you already have or redo some records).
        $AuthHash,

        # Switch. If used, will assume to trust all certs when getting vROps auth tokens.
        [switch]
        $TrustAllCerts,

        # If set to $false, will be prompted for username on each server.
        $SameUsernames = $true
        
    )
    
    BEGIN {
        if ( -not $AuthHash ) {
            $AuthHash = @{}
        }
    }

    PROCESS {

        $serverList | Foreach {

            $s = $_ 

            if ( -not $SameUsernames ) {
                $username = read-host "Enter username for authentication source $($vRopsAuthSource) on vROps $($s)"
            }

            if ( $TrustAllCerts ) {
                $srv,$token = Get-OpsSession -returnValues -server $s -username $username -vRopsAuthSource $vRopsAuthSource -TrustAllCerts 
            } else {
                $srv,$token = Get-OpsSession -returnValues -server $s -username $username -vRopsAuthSource $vRopsAuthSource 
            }

            $AuthHash[$srv] = $token 

        }

    }

    END {
        $AuthHash
    }

}

    
function Get-OpsAuthToken {
<#
    .SYNOPSIS
      Get an authentication token object which can be used for future calls into vROps.
    
    .DESCRIPTION
      If called with -noMetadata, returns just the authentication token string. Otherwise, returns an object, and
      the authentication token string itself is contained within the 'token' property of the object.
    
    
    .EXAMPLE
      # Allow self-signed certificates
      Set-SecurityCertificateSettings -TrustAllCerts
    
      # Tell PowerShell to use TLS1.2 by default for encrypted network traffic
      Set-SecurityProtocol
    
      # Get just the token, excluding metadata like Expiration info. Assumes $server, $username, $password are set and you are using a local username
      $authtoken = Get-OpsAuthToken -noMetadata -server $server -username $username -password $password -vRopsAuthSource 'local'
    
  
    .EXAMPLE
      # Get full token object including Expiration info. Assumes $server, $username, $password are set and you are using a local username
      $fulltoken = Get-OpsAuthToken -server $server -username $username -password $password -vRopsAuthSource 'local'
  
      # Extract just the token itself
      $authtoken = $fulltoken.token
    
    
    .EXAMPLE
      $server = read-host -prompt "Enter the name of your vROps server"
      $tokenObj = Get-OpsAuthToken $server $username $password $authsource 
      $tokenObj | Get-Member 
      $tokenObj.token
    
      Get a token object for your vRops, assuming you have valid values set in variables $server, $username, $password, $authsource.
      See the properties of the token object returned, which includes the token itself and expiration info.
      Then see just the token itself, in the ".token" property of the returned object. (This is like a password. Do not let others see it!)
  
    
    
    .EXAMPLE
      # In case an older version has a bug where getting an auth token sometimes needs multiple attempts
      write "Looping to repeatedly try to get a token."
      $results = @()
      Foreach ($j in (1..15)) {
          write "------ Try $($j)"
          $results += Get-OpsAuthToken -username $username -password $password -vROpsAuthSource $authsource -Server $server -silent
          if ($results.count -gt 0) {
              break
          } else {
              sleep 2
          }
      }
      $authToken = $results[0].token
      write "You now have an authentication token saved in `$authToken."
    
      Execute this function up to 15 times, saving the first positive result, and sleeping 2 seconds between each run.
      Save in $authToken the value of the token property in the first positive result.
      -silent prevents printing warning
    
#>
      
    [cmdletbinding()]Param(
        # The vROps FQDN (fully-qualified domain name).
        [Parameter(Mandatory=$true,Position=0)]
        [string]
        $Server,
  
        # Username as you would enter it at the vROps GUI login page.
        [Parameter(Mandatory=$true,Position=1)]
        [string]
        $username,
    
        # Password as you would enter it at the vROps GUI login page.
        [Parameter(Mandatory=$true,Position=2)]
        [string]
        $password,
    
        # The authentication source you choose from the popup menu on the vROps GUI login page. If "Local Users", specify this as "local", or leave blank as that is the default.
        [Parameter(Mandatory=$false,Position=3)]
        [string]
        $vROpsAuthSource='local',
  
        # Switch. If used, return only the token itself, excluding metadata like expirationdate.
        [switch]$noMetadata,
    
        # Switch. If $true (i.e. if -silent is used), do not print a warning about the need to keep your authtoken private.
        [switch]$silent
    )
  
    $baseURL = "https://$($Server)/suite-api"
    $commandURL = "/api/auth/token/acquire"
    $URL = $baseURL + $commandURL 
    $RestMethod = 'POST'
    
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Content-Type", "application/json")
    $headers.Add("Accept", "application/json")
    $headers.Add("Cache-Control", "no-cache")
    
    $body = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $body.Add("username", "$username")
    $body.Add("password", "$password")
    $body.Add("authSource", "$vROpsAuthSource")
        
    $jsonBody = $body | ConvertTo-Json
    
    if ( -not $silent ){ Write-Warning "Keep your authentication token hidden. Remember, it is equivalent to a username and password." }
    
    $fullToken = Invoke-RestMethod -Method $RestMethod -Uri $URL -Headers $Headers -Body $JsonBody 
    
    if ($noMetadata) {
        $fullToken.token
    } else {
        $fullToken
    }
  
}

  
function Revoke-OpsAuthToken {
<#
  .SYNOPSIS
    Release an authentication token to invalidate it for vROps API calls.

  .DESCRIPTION
    Release an authentication token to invalidate it for vROps API calls.

  .EXAMPLE
    # Tell vROps at $server to stop treating $authtoken as a valid authentication token
    Revoke-OpsAuthToken -server $server -authtoken $authtoken
#>
      
    [cmdletbinding()]Param(
        # The vROps FQDN (fully-qualified domain name).
        [Parameter(Mandatory=$true,Position=0)]
        [string]
        $Server,
          
        # The authentication token to be released.
        [Parameter(Mandatory=$true,Position=1)]
        [string]
        $authToken 
    )
  
    $baseURL = "https://$($Server)/suite-api"
    $commandURL = "/api/auth/token/release"
    $URL = $baseURL + $commandURL 
    $RestMethod = 'POST'

    if ( ! $authtoken  ) {
        throw {"You must specify an authenticationtoken."}
    } 

    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Authorization", "vRealizeOpsToken $($authToken)")

    Invoke-RestMethod -Method $RestMethod -Uri $URL -Headers $Headers 

}
    



function Set-SecurityCertificateSettings {
<#
      .SYNOPSIS
        Set system settings about how to handle security certificates.
    
      .DESCRIPTION
        Set system settings about how to handle security certificates. 
    
        This may be necessary to fix errors such as:
            The underlying connection was closed. An unexpected error occurred on a send.
        
        Changes [System.Net.ServicePointManager]::CertificatePolicy
#>
    
    [cmdletbinding()]Param(
        # If this switch is used, change this session's [System.Net.ServicePointManager]::CertificatePolicy to accept any certificate.
        [switch]
        $TrustAllCerts
    )
    
    # Security protocols and Certificate Policy.
    # Fix for error, "The underlying connection was closed. An unexpected error occurred on a send."
    add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@  # Make sure this line is indented all the way to the left so that it closes the block quote.
  
    Write-Verbose "$(get-date) Current certificate policy: $([System.Net.ServicePointManager]::CertificatePolicy) "
    if ( $TrustAllCerts ) {
        [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
        Write-Verbose "$(get-date) New certificate policy: $([System.Net.ServicePointManager]::CertificatePolicy) "
    }
    
       
}
  
      
function Set-SecurityProtocol {
<#
    .SYNOPSIS
      Specify which security protocol to use for web requests e.g. TLS 1.2 vs. SSL3.
#>
    
    [cmdletbinding()]Param(
        # Name of one security protocol which should be used during this PowerShell session. E.g. 'Tls12' or 'Ssl3'.
        [Parameter(Mandatory=$false,Position=0)]
        [string]
        $protocol = 'Tls12'                      
    )                       
        
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::$protocol
        
} 
  
    
function Get-SecurityProtocol {   
<#
  .SYNOPSIS
      Display which security protocol to use for web requests e.g. TLS 1.2 vs. SSL3.
#>                                                                                             
    [Net.ServicePointManager]::SecurityProtocol         
}
    
    
    
  
function Show-HowToGetOpsSession {
  
    write-host "For help getting a session, do: get-help -examples Get-OpsSession"
    write-host `n
    write-host 'If you need to work with multiple vROps, try: get-help Get-OpsAuthHash -full'
  
}



  
