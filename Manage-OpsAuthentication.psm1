<#
  Purpose: Support authentication with the vRealize Operations Manager RESTful API
  Version: 1.5 (2019/09/20)
  Author: Craig Risinger
  License: freeware, without any warranty

  
  To load these functions:
    Import-Module <pathToThisFile>.psm1
  
  To see commands available from this module:
    Get-Command -Module <nameOfThisModule>  

  To get help including examples:
    Get-Help <functionName> -Full


  To see how to get a session:
    Get-Help Get-OpsSession -Full    

  Typical way to get a session:
    $server,$authtoken = Get-OpsSession -returnValues -TrustAllCerts 

#>


function Get-OpsSession {
<#
  .SYNOPSIS
    Get a sort of session with vROps by prompting for login information and returning server name and authentication token values. Save those in $server and $authtoken.

  .DESCRIPTION
    Some PowerShell vROps commands have parameters for -server and -authtoken. Many of those commands will inherit
    any values you have already set at the command line for $server and $authtoken. So, if you set valid
    values for $server and $authtoken, you can just say "Do-OpsSomething" instead of "Do-OpSomething -server <myserver> -authtoken <myauthtoken>"
    This function prompts you for login input, gets an authentication token, and returns the relevant values.
    
  .EXAMPLE
    $server,$authtoken = Get-OpsSession -returnValues

    This is the recommended way.

    Prompt user for login information. Return both the servername of the vROps and a valid authentication token for it, and
    save those in $server and $authtoken.

 .EXAMPLE
    $server,$authtoken = Get-OpsSession -returnValues -TrustAllCerts

    -TrustAllCerts means that your PowerShell session will trust self-signed certificates when attempting secure connections.

  .EXAMPLE
    . Get-OpsSession 

    This way is deprecated. It is provided for simplicity of use.
    
    Note the initial ". ", which is "dot-sourcing" the function. That makes the values of variables
    set inside this function persist after the function stops running. This means $server and $authtoken will have values (but so 
    will some other variable names which are meant to be internal to this function, for example $password which holds the password you enter).

#>

    [cmdletbinding()]Param(
        # If used, function returns values which can be saved into $server,$authtoken. Otherwise, you must dot-source to set those variables in the calling function/shell.
        # Note that we do not want to display authtoken carelessly on the screen, because that is equivalent to a username and password.
        [switch]$returnValues,

        # If used, all certificates will be trusted. Useful if your vROps certificate is not signed by a regular Certificate Authority (CA).
        [switch]$TrustAllCerts,

        # Security protocol to be used for connections. vROps 7.5 requires TLS 1.2.
        $SecurityProtocol = 'TLS12'
    )



    # Prompt users who have not read the help
    if (-not $returnValues ) {
        write-warning "Invoke this function saving output into variables called `$server and `$authtoken, like this: 

            `$server,`$authtoken = Get-OpsSession -returnValues

        "
        write-host "The above is preferable, but you could dot-source this function to get the variable values to persist:  . Get-OpsSession"
        write-host "Dot-sourcing will make values for `$server and `$authtoken (but also all other variables inside this function) persist after the function finishes running."
    }

    # security
    if ( $TrustAllCerts ) {
        Set-SecurityCertificateSettings -TrustAllCerts
    }
    Set-SecurityProtocol $SecurityProtocol   

    # prompt for login info
    $server = Read-Host -Prompt "Enter FQDN of vROps server"
    $local:vropsAuthSource = Read-Host -Prompt "Enter name of the Authentication Source for logging into vROps. If local user, enter nothing or `"local`"."
    if ( -not $local:vropsAuthSource ) { $local:vropsAuthSource = 'local' }
    $local:username = Read-Host -prompt "Enter username for $server"
    $local:secStringPassword = Read-Host -asSecureString -Prompt "Enter password for username"
    $local:BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secStringPassword)
    $local:password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

    $authtoken = Get-OpsAuthToken -noMetadata -Server $server -username $username -password $password -vROpsAuthSource $vropsAuthSource 

    if ($returnValues) {
        $server,$authtoken
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

    write-host "Getting a session:"
    write-host ""
    write-host 'Use a username and password to get an authentication token. Save the vROps name in $server and the token in $authtoken. That gives you 
a sort of session. Commands can use those variables to connect to the vROps. You can pass them in as parameters to commands (such as 
"get-OpsSomething -server $server -authtoken $authtoken XYZ..."). Some commands might not require explicitly stating the parameters but instead use 
the values automatically as long as you save them in variables called $server and $authtoken (just "get-OpsSomething XYZ...").
'

    write-host 'Run the following commands:

      # set $server and $authtoken
        # set variables
        $server = Read-Host -Prompt "Enter FQDN of vROps server"
        $username = Read-Host -prompt "Enter username for $server"
        $vropsAuthSource = Read-Host -Prompt "Enter name of the Authentication Source for logging into vROps. If local user, enter `"local`"."
        $secStringPassword = Read-Host -asSecureString -Prompt "Enter password for username"
        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secStringPassword)
        $password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)


        # get authentication token
        $authtoken = Get-OpsAuthToken -noMetadata -Server $server -username $username -password $password -vROpsAuthSource $vropsAuthSource 
    '
    write-host 'If you get errors, you might need to run these commands first and retry:
      # Trust all certificates including self-signed
        Set-SecurityCertificateSettings -TrustAllCerts
        
      # Tell PowerShell to use TLS1.2 for encryption, required by vROps as of 7.5
        Set-SecurityProtocol TLS12   
    '

}



