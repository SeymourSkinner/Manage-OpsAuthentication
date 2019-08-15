<#
  Purpose: Support authentication with the vRealize Operations Manager RESTful API
  Version: 1.1 (2019/08)
  Author: Craig Risinger
  License: freeware, without any warranty

  
  To load these functions:
    Import-Module <pathToThisFile>.psm1
  
  To see commands available:
    Get-Command -Module <nameOfThisModule>  

  To get help including examples:
    Get-Help <functionName> -Full

  Common workflow:
    # set variables
    $server = <yourvROpsFQDN>
    $username = <yourUsername>
    $password = <yourPassword>  # remember to clear screen and clear-history and, once you have the token, "remove-variable password" 
    $authSource = <name of the source in popup on login page, or "local">

    Set-SecurityCertificateSettings -TrustAllCerts # if using self-signed certs
    Set-SecurityProtocol # defaults to TLS 1.2, which is required by vROps 7.5
    $fulltoken = Get-OpsAuthToken -server $server -username $username -password $password -vRopsAuthSource $authSource
    $authtoken = $fulltoken.token
#>



function Get-OpsAuthToken {
  <#
    .SYNOPSIS
      Get an authentication token object which can be used for future calls into vROps.
  
    .DESCRIPTION
      Returns an object. The authentication token string itself is contained within the 'token' property of the object.
  
      NOTE: Do not assume that the call works. Check that a token is delivered.
  
  
    .EXAMPLE
        # Allow self-signed certificates
        Set-SecurityCertificateSettings -TrustAllCerts
  
        # Tell PowerShell to use TLS1.2 by default for encrypted network traffice
        Set-SecurityProtocol
  
        # Get full token object including Expiration info. Assumes $server, $username, $password are set and you are using a local username
        $fulltoken = Get-OpsAuthToken -server $server -username $username -password $password -vRopsAuthSource 'local'
  
        # Get just the token itself
        $authtoken = $fulltoken.token
  
    .EXAMPLE
      $server = read-host -prompt "Enter the name of your vROps server"
      $tokenObj = Get-OpsAuthToken -username $username -password $password -vROpsAuthSource $authsource -Server $server
      $tokenObj | Get-Member 
      $tokenObj.token
  
      Get a token object for your vRops, assuming you have valid values set in variables $username, $password, $authsource.
      See the properties of the token object returned, which includes the token itself and expiration info.
      Then see just the token itself, in the ".token" property of the returned object. (This is like a password. Do not let others see it!)
  
  
    .EXAMPLE
      # In case an older version has a bug where getting an auth token sometimes needs multiple attempts
      write "Looping to repeatedly try to get a token."
      $results = @()
      Foreach ($j in (1..15)) {
          write "------ Try $($j)"
          $results += Get-OpsAuthToken -username $username -password $password -vROpsAuthSource $authsource -Server $server
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
  
  #>
  
  
      [cmdletbinding()]Param(
          # Username as you would enter it at the vROps GUI login page.
          $username,
  
          # Password as you would enter it at the vROps GUI login page.
          $password,
  
          # The authentication source you choose from the popup menu on the vROps GUI login page. If "Local Users", specify this as "local", or leave blank as that is the default.
          $vROpsAuthSource='local',
  
          # The vROps FQDN (fully-qualified domain name).
          $Server,
  
          # If $true, do not print a warning about the need to keep your authtoken private.
          [boolean]$silent=$false
      )
  
      $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
      $headers.Add("Content-Type", "application/json")
      $headers.Add("Accept", "application/json")
      $headers.Add("Cache-Control", "no-cache")
  
      $body = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
      $body.Add("username", "$username")
      $body.Add("password", "$password")
      $body.Add("authSource", "$vROpsAuthSource")
      
      $jsonBody = $body | ConvertTo-Json
  
      $baseURL = "https://$($Server)/suite-api"
      $commandURL = "/api/auth/token/acquire"
      $URL = $baseURL + $commandURL 
      $RestMethod = 'POST'
  
      if ( -not $silent ){ Write-Warning "Keep your authentication token hidden. Remember, it is equivalent to a username and password." }
  
      Invoke-RestMethod -Method $RestMethod -Uri $URL -Headers $Headers -Body $JsonBody 
  
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
  
  
  