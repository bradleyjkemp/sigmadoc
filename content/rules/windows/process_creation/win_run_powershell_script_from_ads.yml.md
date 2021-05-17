---
title: "Run PowerShell Script from ADS"
aliases:
  - "/rule/45a594aa-1fbd-4972-a809-ff5a99dd81b8"

tags:
  - attack.defense_evasion
  - attack.t1096
  - attack.t1564.004



status: experimental



level: high



date: Sat, 7 Dec 2019 01:45:55 +0100


---

Detects PowerShell script execution from Alternate Data Stream (ADS)

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/p0shkatz/Get-ADS/blob/master/Get-ADS.ps1


## Raw rule
```yaml
title: Run PowerShell Script from ADS
id: 45a594aa-1fbd-4972-a809-ff5a99dd81b8
status: experimental
description: Detects PowerShell script execution from Alternate Data Stream (ADS)
references:
    - https://github.com/p0shkatz/Get-ADS/blob/master/Get-ADS.ps1
author: Sergey Soldatov, Kaspersky Lab, oscd.community
date: 2019/10/30
tags:
    - attack.defense_evasion
    - attack.t1096 # an old one
    - attack.t1564.004
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\powershell.exe'
        Image|endswith: '\powershell.exe'
        CommandLine|contains|all:
            - 'Get-Content'
            - '-Stream'
    condition: selection
falsepositives:
    - Unknown
level: high

```
