---
title: "Malicious Nishang PowerShell Commandlets"
aliases:
  - "/rule/f772cee9-b7c2-4cb2-8f07-49870adc02e0"
ruleid: f772cee9-b7c2-4cb2-8f07-49870adc02e0

tags:
  - attack.execution
  - attack.t1059.001



status: experimental





date: Thu, 16 May 2019 17:51:45 +0300


---

Detects Commandlet names and arguments from the Nishang exploitation framework

<!--more-->


## Known false-positives

* Penetration testing



## References

* https://github.com/samratashok/nishang


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/powershell/powershell_script/posh_ps_nishang_malicious_commandlets.yml))
```yaml
title: Malicious Nishang PowerShell Commandlets
id: f772cee9-b7c2-4cb2-8f07-49870adc02e0
status: experimental
description: Detects Commandlet names and arguments from the Nishang exploitation framework
date: 2019/05/16
modified: 2021/10/16
references:
    - https://github.com/samratashok/nishang
tags:
    - attack.execution
    - attack.t1059.001
author: Alec Costello
logsource:
    product: windows
    category: ps_script
    definition: Script block logging must be enabled
detection:
    Nishang:
        ScriptBlockText|contains:
            - Add-ConstrainedDelegationBackdoor
            - Set-DCShadowPermissions
            - DNS_TXT_Pwnage
            - Execute-OnTime
            - HTTP-Backdoor
            - Set-RemotePSRemoting
            - Set-RemoteWMI
            - Invoke-AmsiBypass
            - Out-CHM
            - Out-HTA
            - Out-SCF
            - Out-SCT
            - Out-Shortcut
            - Out-WebQuery
            - Out-Word
            - Enable-Duplication
            - Remove-Update
            - Download-Execute-PS
            - Download_Execute
            - Execute-Command-MSSQL
            - Execute-DNSTXT-Code
            - Out-RundllCommand
            - Copy-VSS
            - FireBuster
            - FireListener
            - Get-Information
            - Get-PassHints
            - Get-WLAN-Keys
            - Get-Web-Credentials
            - Invoke-CredentialsPhish
            - Invoke-MimikatzWDigestDowngrade
            - Invoke-SSIDExfil
            - Invoke-SessionGopher
            - Keylogger
            - Invoke-Interceptor
            - Create-MultipleSessions
            - Invoke-NetworkRelay
            - Run-EXEonRemote
            - Invoke-Prasadhak
            - Invoke-BruteForce
            - Password-List
            - Invoke-JSRatRegsvr
            - Invoke-JSRatRundll
            - Invoke-PoshRatHttps
            - Invoke-PowerShellIcmp
            - Invoke-PowerShellUdp
            - Invoke-PSGcat
            - Invoke-PsGcatAgent
            - Remove-PoshRat
            - Add-Persistance
            - ExetoText
            - Invoke-Decode
            - Invoke-Encode
            - Parse_Keys
            - Remove-Persistence
            - StringtoBase64
            - TexttoExe
            - Powerpreter
            - Nishang
            - DataToEncode
            - LoggedKeys
            - OUT-DNSTXT
            # - Jitter  # Prone to FPs
            - ExfilOption
            - DumpCerts
            - DumpCreds
            - Shellcode32
            - Shellcode64
            - NotAllNameSpaces
            - exfill
            - FakeDC
    condition: Nishang
falsepositives:
    - Penetration testing
level: high

```