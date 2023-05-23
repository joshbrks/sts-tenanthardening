# sts-tenanthardening
Run the following CMD via an elevated PS session:

$ScriptFromGitHub = Invoke-WebRequest "https://raw.githubusercontent.com/joshkwestbrook/sts-tenanthardening/main/365%20Tenant%20Hardening.ps1"
Invoke-Expression $($ScriptFromGitHub.Content)
