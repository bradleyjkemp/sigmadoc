---
title: "SyncAppvPublishingServer VBS Execute Arbitrary PowerShell Code"
aliases:
  - "/rule/36475a7d-0f6d-4dce-9b01-6aeb473bbaf1"
ruleid: 36475a7d-0f6d-4dce-9b01-6aeb473bbaf1

tags:
  - attack.defense_evasion
  - attack.t1218
  - attack.t1216



status: experimental





date: Fri, 16 Jul 2021 08:28:25 +0200


---

Executes arbitrary PowerShell code using SyncAppvPublishingServer.vbs

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1216/T1216.md
* https://lolbas-project.github.io/lolbas/Binaries/Syncappvpublishingserver/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_syncappvpublishingserver_vbs_execute_powershell.yml))
```yaml
title: SyncAppvPublishingServer VBS Execute Arbitrary PowerShell Code
id: 36475a7d-0f6d-4dce-9b01-6aeb473bbaf1
status: experimental
author: frack113
date: 2021/07/16
modified: 2022/01/24
description: Executes arbitrary PowerShell code using SyncAppvPublishingServer.vbs
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1216/T1216.md
    - https://lolbas-project.github.io/lolbas/Binaries/Syncappvpublishingserver/
tags:
    - attack.defense_evasion
    - attack.t1218
    - attack.t1216
logsource:
    category: process_creation
    product: windows
detection:
    select_vbs:
        CommandLine|contains|all:
            - '\SyncAppvPublishingServer.vbs'
            - '"\n;'
    condition: select_vbs
fields:
    - ComputerName
    - User
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Unknown
level: medium

```
