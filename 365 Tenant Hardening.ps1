Write-Host "---------------------------------------------" -Foregroundcolor white -BackgroundColor DarkCyan
Write-Host "Welcome to the STS Tenant Hardening Script." -Foregroundcolor white -BackgroundColor DarkCyan
Write-Host "---------------------------------------------" -Foregroundcolor white -BackgroundColor DarkCyan
Write-Host ""

#Obtain Primary Domain
Connect-AzureAD 
$primaryDomain = ((Get-AzureADTenantDetail).verifieddomains | where {$_._default -eq $true}).name

Install-Module -Name ExchangeOnlineManagement
Install-Module MSOnline
Import-Module MSOnline
Connect-Exchangeonline
Connect-MsolService
Connect-MgGraph -Scopes "Policy.ReadWrite.Authorization"

#Create LOG file and directory
$log = "C:\temp\$PrimaryDomain - M365 INFO.log"
if (Test-Path C:\temp) {  
  New-Item $log
} else {
    New-Item C:\temp\ -ItemType Directory
    New-Item $log
}

Write-Host "LOG file will be created at $($log). Review this after completion."
pause
Add-Content -Path $log -Value "~~~~~~~~TENANT HARDENING LOG FOR $($primaryDomain)~~~~~~~~"
Add-Content -Path $log -Value ""
Add-Content -Path $log -Value "Organization settings changed:"

#Disable user consent to apps
Update-MgPolicyAuthorizationPolicy -DefaultUserRolePermissions @{
    "PermissionGrantPoliciesAssigned" = @() }
Set-MsolCompanySettings -UsersPermissionToUserConsentToAppEnabled $False 
Add-Content -Path $log -Value "  - Disabled user consent to apps"

#Set default Usage Location
Set-MsolCompanySettings -DefaultUsageLocation US
Add-Content -Path $log -Value "  - Set default usage location to US"

#Set Passwords to Never Expire
$opt = Read-Host -Prompt 'Set passwords to never expire? (Y/N)'
if ($opt -contains 'Y') {
  Get-msoluser | set-msoluser -PasswordNeverExpires $true
  Add-Content -Path $log -Value "  - Set password expiration policy to NEVER EXPIRE."
} else {
  Add-Content -Path $log -Value "  - Password expiration policy not changed."
}

Add-Content -Path $log -Value ""
Add-Content -Path $log -Value "Exchange Admin Center settings changed:"

#Disable Executable Content in Attachments
New-TransportRule -Name "Block Executable Content" `
-AttachmentHasExecutableContent $true `
-StopRuleProcessing $true `
-DeleteMessage $true
Add-Content -Path $log -Value "  - Block Executable Content rule created."

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
Add-Content -Path $log -Value "  - External source disclaimer message rule added."
  

#Block OnMicrosoft Domains
$BlockedDomains = @("onmicrosoft.com", "mail.onmicrosoft.com")
#Inbound Rule
New-TransportRule `
  -Name "Block Inbound onmicrosoft.com Emails" `
  -Enabled $true `
  -StopRuleProcessing $true `
  -Comments "Block Inbound Emails with onmicrosoft.com or mail.onmicrosoft.com Domains" -SenderDomainIs $BlockedDomains -DeleteMessage:$true
Add-Content -Path $log -Value "  - Inbound 'OnMicrosoft.com' domain emails blocked."
  
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
Add-Content -Path $log -Value "  - Outbound 'OnMicrosoft.com' domain emails blocked."

#Disable Protocols
Get-CASMailboxPlan `
  -Filter {ImapEnabled -eq "true" -or PopEnabled -eq "true" } `
  | set-CASMailboxPlan -ImapEnabled $false -PopEnabled $false
  
Get-CASMailbox -Filter {ImapEnabled -eq "true" -or PopEnabled -eq "true" } `
| Select-Object @{n = "Identity"; e = {$_.primarysmtpaddress}} `
| Set-CASMailbox -ImapEnabled $false -PopEnabled $false

Set-TransportConfig -SmtpClientAuthenticationDisabled $true

Add-Content -Path $log -Value "  - IMAP, POP, and Authenticated SMTP disabled for all users."

#Disable automatic forwarding
Set-RemoteDomain Default -AutoForwardEnabled $False
Add-Content -Path $log -Value "  - Automatic forwarding disabled for all users."
Add-Content -Path $log -Value ""
Add-Content -Path $log -Value "Security Admin settings changed:"

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

Add-Content -Path $log -Value "  - Anti-spam policy created."

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

Add-Content -Path $log -Value "  - Anti-malware policy created."

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

  Add-Content -Path $log -Value "  - Anti-phishing policy created."

#Create ATP Mailbox
New-Mailbox -Shared "ATP Mailbox" -DisplayName "ATP Mailbox" -Alias ATP
$redirect = "atp@" + $primaryDomain

Add-Content -Path $log -Value "  - Advanced Threat Protection (ATP) mailbox created."

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

   Add-Content -Path $log -Value "  - Safe-Attachment policy created."

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

   Add-Content -Path $log -Value "  - Safe-Link policy created."

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

Add-Content -Path $log -Value "  - PowerShell Remote Management disabled for existing users; this will need to be completed for future users independently."
Add-Content -Path $log -Value ""
Add-Content -Path $log -Value "Purview settings changed:"
#Turn on Auditing
Set-OrganizationConfig -AuditDisabled $false
Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true

Add-Content -Path $log -Value "  - Auditing enabled."
Add-Content -Path $log -Value ""
Add-Content -Path $log -Value "Optional settings changed:"


$encryptOpt = Read-Host -Prompt 'Turn on Email Encryption? (Y/N)'
if ($encryptOpt -contains 'Y') {
    #Setup the RMS Template
    Install-module -name AIPService 
    Connect-AipService
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
    pause
    Add-Content -Path $log -Value "  - Email encryption enabled. The keywords 'encrypt', 'encrypted', or 'secure' can be used in the subject line to encrypt outbound email."
}



$domainList = Get-MsolDomain | Select-Object Name
foreach ($domain in $domainList.name) {
  New-DkimSigningConfig `
    -DomainName $domain `
    -KeySize 2048 `
    -Enabled $true
}

Add-Content -Path $log -Value "  - DKIM partially enabled. The following CNAMES need to be added, and DKIM must be manually enabled."
Add-Content -Path $log -Value ""
Add-Content -Path $log -Value "~~~~~~~~~~DKIM CONFIGURATION~~~~~~~~~~"
Add-Content -Path $log -Value "NOTE: These are CNAME records that need to be added."
Add-Content -Path $log -Value "---------------------------------------------------"

foreach ($domain in $domainList.name) {
    Add-Content -Path $log -Value "DOMAIN:   $($domain)"
    Add-Content -Path $log -Value ""
    Add-Content -Path $log -Value "HOST:     Selector1._domainkey."
    $s1DKIM = Get-DkimSigningConfig -Identity $domain | Select-Object -ExpandProperty Selector1CNAME
    Add-Content -Path $log -Value "VALUE:    $($s1DKIM)"
    Add-Content -Path $log -Value ""
    Add-Content -Path $log -Value "HOST:     Selector2._domainkey."
    $s2DKIM = Get-DkimSigningConfig -Identity $domain | Select-Object -ExpandProperty Selector2CNAME
    Add-Content -Path $log -Value "VALUE:    $($s2DKIM)"
    Add-Content -Path $log -Value "---------------------------------------------------"

    
}
Write-Host "DKIM records will need to be added. Check the LOG for details."
Write-Host ""
Write-Host "Tenant hardening complete." -ForegroundColor Green
pause