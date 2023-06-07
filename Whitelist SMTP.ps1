Write-Host "Use this script to fix SMTP authentication issues after tenant hardening is complete." -Foregroundcolor white -BackgroundColor DarkCyan

if (Get-Module -ListAvailable -Name ExchangeOnlineManagement) {
} else {
  Install-Module ExchangeOnlineManagement
}
Write-Host "Logging into the Exchange Online module..." -ForegroundColor Yellow
Connect-Exchangeonline
Write-Host "Success." -ForegroundColor DarkGreen

#Enable Protocols
$loop = "y"

while ($loop -contains "y") {
  $email = Read-Host -Prompt "Enter the email address to whitelist"

  Get-CASMailbox $email | Set-CASMailbox -SmtpClientAuthenticationDisabled $false

  Write-Host "Authenticated SMTP re-enabled for $email." -ForegroundColor Green

  $loop = Read-Host -Prompt "Add another email to whitelist?"
}

exit