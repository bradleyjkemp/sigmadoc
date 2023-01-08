---
title: "Suspicious PowerShell Invocations - Specific"
aliases:
  - "/rule/fce5f582-cc00-41e1-941a-c6fabf0fdb8c"
ruleid: fce5f582-cc00-41e1-941a-c6fabf0fdb8c

tags:
  - attack.execution
  - attack.t1059.001



status: deprecated





date: Sun, 5 Mar 2017 15:01:51 +0100


---

Detects suspicious PowerShell invocation command parameters

<!--more-->


## Known false-positives

* Penetration tests




## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/deprecated/powershell_suspicious_invocation_specific.yml))
```yaml
title: Suspicious PowerShell Invocations - Specific
id: fce5f582-cc00-41e1-941a-c6fabf0fdb8c
status: deprecated
description: Detects suspicious PowerShell invocation command parameters
tags:
    - attack.execution
    - attack.t1059.001
author: Florian Roth (rule), Jonhnathan Ribeiro
date: 2017/03/05
modified: 2022/02/21
logsource:
    product: windows
    service: powershell
    definition: Script block logging must be enabled for 4104, Module Logging must be enabled for 4103
detection:
    convert_b64:
        - '-nop'
        - ' -w '
        - 'hidden'
        - ' -c '
        - '[Convert]::FromBase64String'
    iex_selection:
        - ' -w '
        - 'hidden'
        - '-noni'
        - '-nop'
        - ' -c '
        - 'iex'
        - 'New-Object'
    enc_selection:
        - ' -w '
        - 'hidden'
        - '-ep'
        - 'bypass'
        - '-Enc'
    reg_selection:
        - 'powershell'
        - 'reg'
        - 'add'
        - 'HKCU\software\microsoft\windows\currentversion\run'
    webclient_selection:
        - 'bypass'
        - '-noprofile'
        - '-windowstyle'
        - 'hidden'
        - 'new-object'
        - 'system.net.webclient'
        - '.download'
    iex_webclient:
        - 'iex'
        - 'New-Object'
        - 'Net.WebClient'
        - '.Download'
    filter_chocolatey:
        - "(New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1"
        - "(New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1')"
        - 'Write-ChocolateyWarning'
    condition: (all of convert_b64 or all of iex_selection or all of enc_selection or all of reg_selection or all of webclient_selection or all of iex_webclient) and not 1 of filter_*
falsepositives:
    - Penetration tests
level: high

```
