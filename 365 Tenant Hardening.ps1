Write-Host "-----------------------------------------------" -Foregroundcolor white -BackgroundColor DarkCyan
Write-Host "Welcome to the STS Tenant Hardening Script." -Foregroundcolor white -BackgroundColor DarkCyan
Write-Host "-----------------------------------------------" -Foregroundcolor white -BackgroundColor DarkCyan
Write-Host ""

if (Get-Module -ListAvailable -Name ExchangeOnlineManagement) {
} else {
  Install-Module ExchangeOnlineManagement
}
Write-Host "Logging into the Exchange Online module..." -ForegroundColor Yellow
Connect-Exchangeonline
Write-Host "Success." -ForegroundColor DarkGreen

#Enable Organization Customization
Write-Host "Checking if tenant has been enabled for customization..." -ForegroundColor Yellow
$status = Get-OrganizationConfig | fl IsDehydrated
if ($status -contains "True") {
  Write-Host "Attempting to dehydrate tenant..." -ForegroundColor Yellow
  Enable-OrganizationCustomization
  Write-Host "Tenant was not enabled. Please wait 60-90 minutes for tenant to upgrade before proceeding." -ForegroundColor Red
  Pause
  Write-Host "Exiting...." -ForegroundColor Red
  Start-Sleep 5
  Exit-PSSession
} else {
  Write-Host "Success." -ForegroundColor DarkGreen
}

#Get list of licenses available
Write-Host "Checking licensing on tenant..." -ForegroundColor Yellow
if (Get-Module -ListAvailable -Name Microsoft.Graph) {
  } else {
    Install-Module Microsoft.Graph
  }
Connect-MgGraph
$licenses = Get-MgSubscribedSku | select SkuPartNumber,@{N='ActiveUnits';E={$_.PrepaidUnits.enabled}},ConsumedUnits

#Check for Defender Licensing
if (($licenses.SkuPartNumber -contains "O365_BUSINESS_PREMIUM") -or ($licenses.SkuPartNumber -contains "ATP_ENTERPRISE")) {
    Write-Host "Defender licensing detected. Tenant can be hardened." -ForegroundColor Green
    start-sleep 5
} else {
  Write-Host "Defender licensing not detected. You will not be able to harden this tenant until this is added." -ForegroundColor Red
  start-sleep 5
  Write-Host "This program will exit." -ForegroundColor Yellow
  pause
  exit
}

#Check for AIP Licensing
if ($licenses.SkuPartNumber -notcontains "RIGHTSMANAGEMENT_CE") {
  Write-Host "AIP licensing not detected. You will not be able to provision email encryption." -ForegroundColor Red
  start-sleep 5
  $AIP = $false
} else {
  Write-Host "AIP licensing detected. Email encryption can be provisioned." -ForegroundColor Green
  start-sleep 5
  $AIP = $true
}

Write-Host "NOTE: Ensure at least (1) Defender license and (1) AIP license (if applicable) has been assigned before continuing." -BackgroundColor Yellow -ForegroundColor Black
pause

#Obtain Primary Domain
Write-Host "Logging into the Azure AD module..." -ForegroundColor Yellow
Connect-AzureAD 
Write-Host "Success." -ForegroundColor DarkGreen
$primaryDomain = ((Get-AzureADTenantDetail).verifieddomains | where {$_._default -eq $true}).name

if (Get-Module -ListAvailable -Name MSOnline) {
} else {
  Install-Module MSOnline
}
Write-Host "Logging into the MS Online module..." -ForegroundColor Yellow
Connect-MsolService
Write-Host "Success." -ForegroundColor DarkGreen


#Create LOG file and directory
$global:log = "C:\temp\$PrimaryDomain - M365 INFO.log"
if (Test-Path C:\temp) {  
  New-Item $global:log
} else {
    New-Item C:\temp\ -ItemType Directory
    New-Item $global:log
}

Write-Host "LOG file will be created at $($global:log). Review this after completion."
pause
Add-Content -Path $global:log -Value "~~~~~~~~TENANT CONFIGURATION LOG FOR $($primaryDomain)~~~~~~~~"
Add-Content -Path $global:log -Value ""
Add-Content -Path $global:log -Value "Organization settings changed:"

#Set default Usage Location
Set-MsolCompanySettings -DefaultUsageLocation US
Add-Content -Path $global:log -Value "  - Set default usage location to US"
Write-Host "Set default usage location to US" -ForegroundColor Green

#Set Passwords to Never Expire
$opt = Read-Host -Prompt 'Set passwords to never expire? (Y/N)'
if ($opt -contains 'Y') {
  Get-msoluser | set-msoluser -PasswordNeverExpires $true
  Add-Content -Path $global:log -Value "  - Set password expiration policy to NEVER EXPIRE."
  Write-Host "Set password expiration policy to NEVER EXPIRE." -ForegroundColor Green
} else {
  Add-Content -Path $global:log -Value "  - Password expiration policy not changed."
  Write-Host "Password expiration policy not changed." -ForegroundColor Green
}

function Disable-UserConsent {
  #Disable user consent to apps
  Connect-MgGraph -Scopes "Policy.ReadWrite.Authorization"
  Update-MgPolicyAuthorizationPolicy -DefaultUserRolePermissions @{
  "PermissionGrantPoliciesAssigned" = @() }
  Set-MsolCompanySettings -UsersPermissionToUserConsentToAppEnabled $False 
  Add-Content -Path $global:log -Value "  - Disabled user consent to apps"
  Write-Host "Disabled user consent to apps" -ForegroundColor Green
  Add-Content -Path $global:log -Value ""

}

function Set-EAC {
  Add-Content -Path $global:log -Value "Exchange Admin Center settings changed:"
  
  #Disable Executable Content in Attachments
  New-TransportRule -Name "Block Executable Content" `
  -AttachmentHasExecutableContent $true `
  -StopRuleProcessing $true `
  -DeleteMessage $true
  Add-Content -Path $global:log -Value "  - Block Executable Content rule created."
  Write-Host "Block Executable Content rule created." -ForegroundColor Green
  
  #Add External Source Disclaimer Message
  New-TransportRule `
    -Name "External Email Disclaimer" `
    -Priority "1" `
    -Enabled $true `
    -FromScope "NotInOrganization" `
    -SentToScope InOrganization `
    -ApplyHtmlDisclaimerText '<!DOCTYPE html><html><body><table width="100%" border="3" cellspacing="0" cellpadding="4"><tbody><tr><th align="center" style="color:white;" bgcolor="#081d41">EXTERNAL EMAIL</th></tr></tbody></table></body></html><br><br>' `
    -ApplyHtmlDisclaimerLocation "Prepend" `
    -ApplyHtmlDisclaimerFallbackAction Wrap `
    -Comments "This rule adds an external email disclaimer." 
  Add-Content -Path $global:log -Value "  - External source disclaimer message rule added."
  Write-Host "External source disclaimer message rule added." -ForegroundColor Green
    
  
  #Block OnMicrosoft Domains
  $BlockedDomains = @("onmicrosoft.com", "mail.onmicrosoft.com")
  #Inbound Rule
  New-TransportRule `
    -Name "Block Inbound onmicrosoft.com Emails" `
    -Enabled $true `
    -StopRuleProcessing $true `
    -Comments "Block Inbound Emails with onmicrosoft.com or mail.onmicrosoft.com Domains" -SenderDomainIs $BlockedDomains -DeleteMessage:$true
  Add-Content -Path $global:log -Value "  - Inbound 'OnMicrosoft.com' domain emails blocked."
  Write-Host "Inbound 'OnMicrosoft.com' domain emails blocked." -ForegroundColor Green
    
  #Outbound Rule
  New-TransportRule `
  -Name "Block Outbound onmicrosoft.com Emails" `
  -Enabled $true `
  -Comments "This rule blocks outbound emails with the domains 'onmicrosoft.com' or 'mail.onmicrosoft.com', and rejects the message with an explanation 'You are not allowed to send from this domain (onmicrosoft.com).'" `
  -RejectMessageReasonText "You are not allowed to send from this domain (onmicrosoft.com)." `
  -SenderDomainIs $BlockedDomains `
  -RejectMessageEnhancedStatusCode "5.7.1" `
  -StopRuleProcessing $true `
  -Mode Enforce
  Add-Content -Path $global:log -Value "  - Outbound 'OnMicrosoft.com' domain emails blocked."
  Write-Host "Outbound 'OnMicrosoft.com' domain emails blocked." -ForegroundColor Green
  
  #Disable Protocols
  Get-CASMailboxPlan `
    -Filter {ImapEnabled -eq "true" -or PopEnabled -eq "true" } `
    | set-CASMailboxPlan -ImapEnabled $false -PopEnabled $false
    
  Get-CASMailbox -Filter {ImapEnabled -eq "true" -or PopEnabled -eq "true" } `
  | Select-Object @{n = "Identity"; e = {$_.primarysmtpaddress}} `
  | Set-CASMailbox -ImapEnabled $false -PopEnabled $false
  
  Set-TransportConfig -SmtpClientAuthenticationDisabled $true
  
  Add-Content -Path $global:log -Value "  - IMAP, POP, and Authenticated SMTP disabled for all users."
  Write-Host "IMAP, POP, and Authenticated SMTP disabled for all users." -ForegroundColor Green
  
  #Disable automatic forwarding
  Set-RemoteDomain Default -AutoForwardEnabled $False
  Add-Content -Path $global:log -Value "  - Automatic email forwarding disabled for all users."
  Write-Host "Automatic email forwarding disabled for all users." -ForegroundColor Green
  Add-Content -Path $global:log -Value ""
}

function Set-Security {
  Add-Content -Path $global:log -Value "Security Admin settings changed:"
  #Create Anti-Spam policy
  New-HostedContentFilterPolicy `
    -Name STS-SpamPolicy `
    -HighConfidencePhishAction Quarantine `
    -HighConfidencePhishQuarantineTag DefaultFullAccessPolicy `
    -HighConfidenceSpamAction Quarantine `
    -HighConfidenceSpamQuarantineTag DefaultFullAccessPolicy `
    -IncreaseScoreWithNumericIps on `
    -InlineSafetyTipsEnabled $true `
    -PhishSpamAction MoveToJmf `
    -SpamAction MoveToJmf `
    -PhishZapEnabled $true `
    -SpamZapEnabled $true `
    -BulkThreshold 7 `
    -MarkAsSpamBulkMail on `
    -QuarantineRetentionPeriod 30 `
    -EnableRegionBlockList $true `
    -RegionBlockList AR,BR,CN,IR,JP,KR,KP,RU,SG,TW,TH `
    -EnableEndUserSpamNotifications $true
  
  #Create Anti-Spam Rule
  New-HostedContentFilterRule STS-Default-Spam `
    -HostedContentFilterPolicy STS-SpamPolicy `
    -RecipientDomainIs (Get-AcceptedDomain).Name `
    -Enabled $true
  
  Add-Content -Path $global:log -Value "  - Anti-spam policy created."
  Write-Host "Anti-spam policy created." -ForegroundColor Green
  
  #Create Anti-Malware Policy
  New-MalwareFilterPolicy -Name STS-MalwarePolicy `
    -EnableFileFilter $true `
    -FileTypeAction Reject `
    -ZapEnabled $true `
    -QuarantineTag AdminOnlyAccessPolicy 
  
  #Create Anti-Malware Rule
  New-MalwareFilterRule -Name STS-Default-Malware `
    -MalwareFilterPolicy STS-MalwarePolicy `
    -Enabled $true `
    -RecipientDomainIs (Get-AcceptedDomain).Name
  
  Add-Content -Path $global:log -Value "  - Anti-malware policy created."
  Write-Host "Anti-malware policy created." -ForegroundColor Green
  
  #Create Anti-Phishing Policy
  New-AntiPhishPolicy `
    -Name STS-PhishPolicy `
    -AdminDisplayName "STS-Default-Phishing" `
    -Enabled $true `
    -EnableMailboxIntelligence $true `
    -EnableMailboxIntelligenceProtection $true `
    -EnableSpoofIntelligence $true `
    -MailboxIntelligenceProtectionAction MoveToJmf `
    -EnableViaTag $true `
    -EnableUnauthenticatedSender $true `
    -EnableFirstContactSafetyTips $true `
    -EnableOrganizationDomainsProtection $true `
    -PhishThresholdLevel 2 
  
  #Create Anti-Phishing Rule
  New-AntiPhishRule `
    -Name STS-Default-Phishing `
    -AntiPhishPolicy STS-PhishPolicy `
    -Enabled $true `
    -RecipientDomainIs (Get-AcceptedDomain).Name
  
    Add-Content -Path $global:log -Value "  - Anti-phishing policy created."
    Write-Host "Anti-phishing policy created." -ForegroundColor Green
  
  #Create ATP Mailbox
  New-Mailbox -Shared "ATP Mailbox" -DisplayName "ATP Mailbox" -Alias ATP
  $redirect = "atp@" + $primaryDomain
  
  Add-Content -Path $global:log -Value "  - Advanced Threat Protection (ATP) mailbox created."
  Write-Host "Advanced Threat Protection (ATP) mailbox created." -ForegroundColor Green
  
  #Create Safe-Attachment Policy
  New-SafeAttachmentPolicy `
    -Name STS-SafeAttachPolicy `
    -Action DynamicDelivery `
    -Enable $true `
    -QuarantineTag AdminOnlyAccessPolicy `
    -Redirect $true `
    -RedirectAddress $redirect
  
  #Create Safe-Attachment Rule
  New-SafeAttachmentRule `
    -Name STS-Default-SafeAttach `
     -SafeAttachmentPolicy STS-SafeAttachPolicy `
     -Enabled $true `
     -RecipientDomainIs (Get-AcceptedDomain).Name
  
     Add-Content -Path $global:log -Value "  - Safe-Attachment policy created."
     Write-Host "Safe-Attachment policy created." -ForegroundColor Green
  
  #Create Safe-Links Policy
  New-SafeLinksPolicy `
     -Name STS-SafeLinksPolicy `
     -AllowClickThrough $false `
     -DeliverMessageAfterScan $true `
     -DisableUrlRewrite $true `
     -EnableForInternalSenders $true `
     -EnableOrganizationBranding $false `
     -EnableSafeLinksForEmail $true `
     -EnableSafeLinksForOffice $true `
     -EnableSafeLinksForTeams $true `
     -ScanUrls $true `
     -TrackClicks $true
  
  #Create Safe-Links Rule
  New-SafeLinksRule `
     -Name STS-Default-SafeLinks `
     -SafeLinksPolicy STS-SafeLinksPolicy `
     -Enabled $true `
     -RecipientDomainIs (Get-AcceptedDomain).Name
  
     Add-Content -Path $global:log -Value "  - Safe-Link policy created."
     Write-Host "Safe-Links policy created." -ForegroundColor Green
  
}

function Disable-PowershellRM {
  #Disable Powershell RM
  $role = Get-MsolRole `
    -RoleName "company administrator"  
  $members = Get-MsolRoleMember `
    -RoleObjectId $role.objectid
  
  foreach ($user in get-user -Filter { RemotePowerShellEnabled -eq "true" }) { 
    if ($members.emailaddress -contains $user.MicrosoftOnlineServicesID) {   
    Write-Host "Global Admin - Skipping $($user.MicrosoftOnlineServicesID)" `
      -ForegroundColor green  
      continue
    }  
    else {  
      Write-Host "Disabling remote powershell for: $($user.MicrosoftOnlineServicesID)" `
          -ForegroundColor DarkGreen  
      set-user `
          -identity $user.MicrosoftOnlineServicesID `
          -RemotePowerShellEnabled $false `
          -confirm:$false 
    }  
  }
  
  Add-Content -Path $global:log -Value "  - PowerShell Remote Management disabled for existing users; this will need to be completed for future users independently."
  Add-Content -Path $global:log -Value ""
  Add-Content -Path $global:log -Value "Purview settings changed:"
  #Turn on Auditing
  Set-OrganizationConfig -AuditDisabled $false
  Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true
  
  Add-Content -Path $global:log -Value "  - Auditing enabled."
  Write-Host "Auditing enabled." -ForegroundColor Green
  Add-Content -Path $global:log -Value ""
  Add-Content -Path $global:log -Value "Other settings changed:"
  
}

function Set-EmailEncryption {
  if (Get-Module -ListAvailable -Name AIPService) {
  } else {
    Install-module -name AIPService -Force
  }
  
  #Setup the RMS Template

  Write-Host "Logging into the AIP module..." -ForegroundColor Yellow
  Connect-AipService
  Write-Host "Success." -ForegroundColor DarkGreen
  Enable-AipService
  $RMSConfig = Get-AIPServiceConfiguration   
  $LicenseUri = $RMSConfig.LicensingIntranetDistributionPointUrl
  Set-IRMConfiguration -LicensingLocation $LicenseUri
  Set-IRMConfiguration -AzureRMSLicensingEnabled $true
  Set-IRMConfiguration -InternalLicensingEnabled $true

  # Create the mail flow rule
  $Name = "Apply Office 365 Message encryption"
  $Words = "encrypt", "encrypted", "secure"
  $Template = "Encrypt"

  New-TransportRule `
    -Name $Name `
    -SubjectOrBodyContainsWords $Words `
    -ApplyOME $true `
    -ApplyRightsProtectionTemplate $Template
    Add-Content -Path $global:log -Value "  - Email encryption enabled. The keywords 'encrypt', 'encrypted', or 'secure' can be used in the subject line to encrypt outbound email."
    Write-Host "Email encryption enabled." -ForegroundColor Green
}

function Enable-DKIM {
  $domainList = Get-MsolDomain | Select-Object Name

  foreach ($domain in $domainList.name) {
    New-DkimSigningConfig `
      -DomainName $domain `
      -KeySize 2048 `
      -Enabled $true
  }

  Write-Host "DKIM keys enabled." -ForegroundColor Green

  Add-Content -Path $global:log -Value "  - DKIM partially enabled. The following CNAMES need to be added, and DKIM must be manually enabled."
  Add-Content -Path $global:log -Value ""
  Add-Content -Path $global:log -Value "~~~~~~~~~~DKIM CONFIGURATION~~~~~~~~~~"
  Add-Content -Path $global:log -Value "NOTE: These are CNAME records that need to be added."
  Add-Content -Path $global:log -Value "---------------------------------------------------"

  foreach ($domain in $domainList.name) {
    Add-Content -Path $global:log -Value "DOMAIN:   $($domain)"
    Add-Content -Path $global:log -Value ""
    Add-Content -Path $global:log -Value "HOST:     Selector1._domainkey"
    $s1DKIM = Get-DkimSigningConfig -Identity $domain | Select-Object -ExpandProperty Selector1CNAME
    Add-Content -Path $global:log -Value "VALUE:    $($s1DKIM)"
    Add-Content -Path $global:log -Value ""
    Add-Content -Path $global:log -Value "HOST:     Selector2._domainkey"
    $s2DKIM = Get-DkimSigningConfig -Identity $domain | Select-Object -ExpandProperty Selector2CNAME
    Add-Content -Path $global:log -Value "VALUE:    $($s2DKIM)"
    Add-Content -Path $global:log -Value "---------------------------------------------------"
    
  }

  Write-Host "DKIM records will need to be added. Check the LOG for details."

}

Disable-UserConsent
Set-EAC
Set-Security
Disable-PowershellRM
if ($AIP) {
  Set-EmailEncryption
}
Enable-DKIM

Write-Host ""
Write-Host "*****Tenant configuration complete.*******" -ForegroundColor Green
pause