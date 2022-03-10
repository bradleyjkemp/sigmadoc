---
title: "PowerShell SAM Copy"
aliases:
  - "/rule/1af57a4b-460a-4738-9034-db68b880c665"


tags:
  - attack.credential_access
  - attack.t1003.002



status: experimental





date: Thu, 29 Jul 2021 18:12:10 +0200


---

Detects suspicious PowerShell scripts accessing SAM hives

<!--more-->


## Known false-positives

* Some rare backup scenarios
* PowerShell scripts fixing HiveNightmare / SeriousSAM ACLs



## References

* https://twitter.com/splinter_code/status/1420546784250769408


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_powershell_sam_access.yml))
```yaml
title: PowerShell SAM Copy
id: 1af57a4b-460a-4738-9034-db68b880c665
description: Detects suspicious PowerShell scripts accessing SAM hives
status: experimental
references:
    - https://twitter.com/splinter_code/status/1420546784250769408
author: Florian Roth
date: 2021/07/29
modified: 2021/12/02
tags:
    - attack.credential_access
    - attack.t1003.002
logsource:
    category: process_creation
    product: windows
detection:
    selection_1:
        CommandLine|contains|all: 
            - '\HarddiskVolumeShadowCopy'
            - 'ystem32\config\sam'
    selection_2:
        CommandLine|contains:
            - 'Copy-Item'
            - 'cp $_.'
            - 'cpi $_.'
            - 'copy $_.'
            - '.File]::Copy('
    condition: all of selection*
falsepositives: 
    - Some rare backup scenarios
    - PowerShell scripts fixing HiveNightmare / SeriousSAM ACLs
level: high

```
