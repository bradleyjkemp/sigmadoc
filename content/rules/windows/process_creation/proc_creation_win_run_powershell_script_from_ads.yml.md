---
title: "Run PowerShell Script from ADS"
aliases:
  - "/rule/45a594aa-1fbd-4972-a809-ff5a99dd81b8"
ruleid: 45a594aa-1fbd-4972-a809-ff5a99dd81b8

tags:
  - attack.defense_evasion
  - attack.t1564.004



status: test





date: Sat, 7 Dec 2019 01:45:55 +0100


---

Detects PowerShell script execution from Alternate Data Stream (ADS)

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/p0shkatz/Get-ADS/blob/master/Get-ADS.ps1


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_run_powershell_script_from_ads.yml))
```yaml
title: Run PowerShell Script from ADS
id: 45a594aa-1fbd-4972-a809-ff5a99dd81b8
status: test
description: Detects PowerShell script execution from Alternate Data Stream (ADS)
author: Sergey Soldatov, Kaspersky Lab, oscd.community
references:
  - https://github.com/p0shkatz/Get-ADS/blob/master/Get-ADS.ps1
date: 2019/10/30
modified: 2021/11/27
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
tags:
  - attack.defense_evasion
  - attack.t1564.004

```
