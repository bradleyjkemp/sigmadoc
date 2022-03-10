---
title: "Data Compressed - PowerShell"
aliases:
  - "/rule/6dc5d284-69ea-42cf-9311-fb1c3932a69a"


tags:
  - attack.exfiltration
  - attack.t1560



status: experimental





date: Tue, 22 Oct 2019 14:00:52 +0300


---

An adversary may compress data (e.g., sensitive documents) that is collected prior to exfiltration in order to make it portable and minimize the amount of data sent over the network.

<!--more-->


## Known false-positives

* Highly likely if archive operations are done via PowerShell.



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1560/T1560.md


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/powershell/powershell_script/posh_ps_data_compressed.yml))
```yaml
title: Data Compressed - PowerShell
id: 6dc5d284-69ea-42cf-9311-fb1c3932a69a
status: experimental
description: An adversary may compress data (e.g., sensitive documents) that is collected prior to exfiltration in order to make it portable and minimize the amount of data sent over the network.
author: Timur Zinniatullin, oscd.community
date: 2019/10/21
modified: 2021/10/16
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1560/T1560.md
logsource:
    product: windows
    category: ps_script
    definition: Script block logging must be enabled
detection:
    selection:
        ScriptBlockText|contains|all:
            - '-Recurse'
            - '|'
            - 'Compress-Archive'
    condition: selection
falsepositives:
    - Highly likely if archive operations are done via PowerShell.
level: low
tags:
    - attack.exfiltration
    - attack.t1560

```
