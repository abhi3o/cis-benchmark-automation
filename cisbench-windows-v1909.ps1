$score=0

#1.1.2
if ($(Get-ItemPropertyValue -Path HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters -Name "MaximumPasswordAge") -In 1..60) {$score++} 

#1.2.1
if ($(Get-ItemPropertyValue -Path HKLM:\SYSTEM\CurrentControlSet\Services\RemoteAccess\Parameters\AccountLockout -Name "ResetTime (mins)") -ge 15) {$score++} 

#1.2.2
if ($(Get-ItemPropertyValue -Path HKLM:\SYSTEM\CurrentControlSet\Services\RemoteAccess\Parameters\AccountLockout -Name "MaxDenials") -In 1..10) {$score++} 

#2.3.1.4
if ($(Get-ItemPropertyValue -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name "LimitBlankPasswordUse") -eq 1) {$score++} 

#2.3.2.2
if ($(Get-ItemPropertyValue -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name "crashonauditfail") -eq 0) {$score++} 

#2.3.6.1
if ($(Get-ItemPropertyValue -Path HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters -Name "RequireSignOrSeal") -eq 1) {$score++} 

#2.3.6.2
if ($(Get-ItemPropertyValue -Path HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters -Name "SealSecureChannel") -eq 1) {$score++} 

#2.3.6.3
if ($(Get-ItemPropertyValue -Path HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters -Name "SignSecureChannel") -eq 1) {$score++} 

#2.3.6.4
if ($(Get-ItemPropertyValue -Path HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters -Name "DisablePasswordChange") -eq 0) {$score++} 

#2.3.6.6
if ($(Get-ItemPropertyValue -Path HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters -Name "RequireStrongKey") -eq 1) {$score++} 

#2.3.7.2
if ($(Get-ItemPropertyValue -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name "dontdisplaylastusername") -eq 1) {$score++} 

#2.3.8.1
if ($(Get-ItemPropertyValue -Path HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters -Name "RequireSecuritySignature") -eq 1) {$score++} 

#2.3.8.2
if ($(Get-ItemPropertyValue -Path HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters -Name "EnableSecuritySignature") -eq 1) {$score++} 

#.2.3.9.1
if ($(Get-ItemPropertyValue -Path HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters -Name "autodisconnect") -le 15) {$score++} 

#2.3.9.2
if ($(Get-ItemPropertyValue -Path HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters -Name "requiresecuritysignature") -eq 1) {$score++} 

#2.3.10.2
if ($(Get-ItemPropertyValue -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name "restrictanonymoussam") -eq 1) {$score++} 

#2.3.10.3
if ($(Get-ItemPropertyValue -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name "restrictanonymous") -eq 1) {$score++} 

#2.3.11.5
if ($(Get-ItemPropertyValue -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name "NoLmHash") -eq 1) {$score++} 

#2.3.15.1
if ($(Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel" -Name "obcaseinsensitive") -eq 1) {$score++} 

#2.3.15.2
if ($(Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "ProtectionMode") -eq 1) {$score++} 

#2.3.17.2
if ($(Get-ItemPropertyValue -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name "ConsentPromptBehaviorAdmin") -eq 2) {$score++} 

#2.3.17.3
if ($(Get-ItemPropertyValue -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name "ConsentPromptBehaviorUser") -eq 0) {$score++} 

#5.1
if ($(Get-ItemPropertyValue -Path HKLM:\SYSTEM\CurrentControlSet\Services\BTAGService -Name "Start") -eq 4) {$score++} 

#5.2
if ($(Get-ItemPropertyValue -Path HKLM:\SYSTEM\CurrentControlSet\Services\bthserv -Name "Start") -eq 4) {$score++} 

#18.1.3 Check
#if ($(Get-ItemPropertyValue -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -Name "AllowOnlineTips") -eq 0) {$score++} 

#18.2.1
if ($(Test-Path -Path "HKLM:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions\{D76B9641-3288-4f75-942D-087DE603E3EA}")) {$score++} 

#18.4.1
if ($(Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoAdminLogon") -eq 0) {$score++} 

#18.4.5
if ($(Get-ItemPropertyValue -Path HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters -Name "EnableICMPRedirect") -eq 0) {$score++} 

#18.5.10.2
if ($(Get-ItemPropertyValue -Path HKLM:\SOFTWARE\Policies\Microsoft\Peernet -Name "Disabled") -eq 1) {$score++} 

#18.8.22.1.4
if ($(Get-ItemPropertyValue -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports -Name "PreventHandwritingErrorReports") -eq 1) {$score++} 

#18.8.22.1.14
if ($(Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" -Name "Disabled") -eq 1) {$score++} 

#18.9.13.1
if ($(Get-ItemPropertyValue -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent -Name "DisableWindowsConsumerFeatures") -eq 1) {$score++} 

#18.9.16.1
if ($(Get-ItemPropertyValue -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection -Name "AllowTelemetry") -eq 0) {$score++} 

#18.9.16.3
if ($(Get-ItemPropertyValue -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection -Name "DoNotShowFeedbackNotifications") -eq 1) {$score++} 

#18.9.39.2
if ($(Get-ItemPropertyValue -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors -Name "DisableLocation") -eq 1) {$score++} 

Write-Output("Benchmark Score of $($score) of 36")
