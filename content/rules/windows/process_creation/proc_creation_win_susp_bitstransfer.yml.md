---
title: "Suspicious Bitstransfer via PowerShell"
aliases:
  - "/rule/cd5c8085-4070-4e22-908d-a5b3342deb74"


tags:
  - attack.exfiltration
  - attack.persistence
  - attack.t1197



status: experimental





date: Thu, 19 Aug 2021 21:57:37 -0500


---

Detects transferring files from system on a server bitstransfer Powershell cmdlets

<!--more-->


## Known false-positives

* Unknown



## References

* https://docs.microsoft.com/en-us/powershell/module/bitstransfer/add-bitsfile?view=windowsserver2019-ps


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_bitstransfer.yml))
```yaml
title: Suspicious Bitstransfer via PowerShell
id: cd5c8085-4070-4e22-908d-a5b3342deb74
status: experimental
description: Detects transferring files from system on a server bitstransfer Powershell cmdlets
references:
    - https://docs.microsoft.com/en-us/powershell/module/bitstransfer/add-bitsfile?view=windowsserver2019-ps
tags:
    - attack.exfiltration 
    - attack.persistence
    - attack.t1197
date: 2021/08/19
author: Austin Songer @austinsonger
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: 
            - '\powershell.exe'
            - '\powershell_ise.exe'
            - '\pwsh.exe'
        CommandLine|contains: 
            - 'Get-BitsTransfer'
            - 'Add-BitsFile'
    condition: selection
fields:
    - ComputerName
    - User
    - CommandLine
falsepositives:
    - Unknown
level: medium

```
