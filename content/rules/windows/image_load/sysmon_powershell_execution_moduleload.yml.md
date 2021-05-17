---
title: "PowerShell Execution"
aliases:
  - "/rule/867613fb-fa60-4497-a017-a82df74a172c"

tags:
  - attack.execution
  - attack.t1086
  - attack.t1059.001



status: experimental



level: medium



date: Thu, 24 Oct 2019 15:48:38 +0200


---

Detects execution of PowerShell

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/hunters-forge/ThreatHunter-Playbook/blob/8869b7a58dba1cff63bae1d7ab923974b8c0539b/playbooks/WIN-190410151110.yaml


## Raw rule
```yaml
title: PowerShell Execution
id: 867613fb-fa60-4497-a017-a82df74a172c
description: Detects execution of PowerShell
status: experimental
date: 2019/09/12
modified: 2019/11/10
author: Roberto Rodriguez @Cyb3rWard0g
references:
    - https://github.com/hunters-forge/ThreatHunter-Playbook/blob/8869b7a58dba1cff63bae1d7ab923974b8c0539b/playbooks/WIN-190410151110.yaml
tags:
    - attack.execution
    - attack.t1086          # an old one
    - attack.t1059.001
logsource:
    category: image_load
    product: windows
detection:
    selection: 
        Description: 'system.management.automation'
        ImageLoaded|contains: 'system.management.automation'
    condition: selection
fields:
    - ComputerName
    - Image
    - ProcessID
    - ImageLoaded
falsepositives:
    - Unknown
level: medium

```
