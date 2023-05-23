Write-Host "---------------------------------------------" -Foregroundcolor white -BackgroundColor DarkCyan
Write-Host "Welcome to the STS Tenant Hardening Script." -Foregroundcolor white -BackgroundColor DarkCyan
Write-Host "---------------------------------------------" -Foregroundcolor white -BackgroundColor DarkCyan
Write-Host ""

#Obtain Primary Domain
Connect-AzureAD 
$domain = ((Get-AzureADTenantDetail).verifieddomains | where {$_._default -eq $true}).name

Install-Module -Name ExchangeOnlineManagement
Connect-Exchangeonline
Install-Module MSOnline
Import-Module MSOnline
Connect-MsolService

#Disable user consent to apps
Connect-MgGraph -Scopes "Policy.ReadWrite.Authorization"
Update-MgPolicyAuthorizationPolicy -DefaultUserRolePermissions @{
  "PermissionGrantPoliciesAssigned" = @() }
Update-MgPolicyAuthorizationPolicy -DefaultUserRolePermissions @{
  "PermissionGrantPoliciesAssigned" = @("managePermissionGrantsForSelf.{consent-policy-id}") }

#Set Passwords to Never Expire
Get-msoluser | set-msoluser -PasswordNeverExpires $true

#Disable Executable Content in Attachments
New-TransportRule -Name "Block Executable Content" `
-AttachmentHasExecutableContent $true `
-StopRuleProcessing $true `
-DeleteMessage $true

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
  

#Block OnMicrosoft Domains
$BlockedDomains = @("onmicrosoft.com", "mail.onmicrosoft.com")
#Inbound Rule
New-TransportRule `
  -Name "Block Inbound onmicrosoft.com Emails" `
  -Enabled $true `
  -StopRuleProcessing $true `
  -Comments "Block Inbound Emails with onmicrosoft.com or mail.onmicrosoft.com Domains" -SenderDomainIs $BlockedDomains -DeleteMessage:$true
  
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

#Create ATP Mailbox
New-Mailbox -Shared "ATP Mailbox" -DisplayName "ATP Mailbox" -Alias ATP
$redirect = "atp@" + $domain

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

#Disable Protocols
Get-CASMailboxPlan `
  -Filter {ImapEnabled -eq "true" -or PopEnabled -eq "true" } `
  | set-CASMailboxPlan -ImapEnabled $false -PopEnabled $false
  
Get-CASMailbox -Filter {ImapEnabled -eq "true" -or PopEnabled -eq "true" } `
| Select-Object @{n = "Identity"; e = {$_.primarysmtpaddress}} `
| Set-CASMailbox -ImapEnabled $false -PopEnabled $false

Set-TransportConfig -SmtpClientAuthenticationDisabled $true

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

Write-Host "Remote Powershell access is something that is enabled by default for all users. New users will be enabled by default and will need to be disabled after they are created" `
  -ForegroundColor Yellow 
pause

#Turn on Auditing
Set-OrganizationConfig -AuditDisabled $false
Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true

#Disable automatic forwarding
Set-RemoteDomain Default -AutoForwardEnabled $False

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
}

$DKIMopt = Read-Host -Prompt 'Turn on DKIM? (Y/N)'
if ($DKIMopt -contains 'Y') {
    New-DkimSigningConfig `
        -DomainName $domain `
        -KeySize 2048 `
        -Enabled $true
    Write-Host "DKIM records will also need to be added if the command failed."
    pause
}