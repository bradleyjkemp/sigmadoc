---
title: "SyncAppvPublishingServer Execution to Bypass Powershell Restriction"
aliases:
  - "/rule/fde7929d-8beb-4a4c-b922-be9974671667"
ruleid: fde7929d-8beb-4a4c-b922-be9974671667

tags:
  - attack.defense_evasion
  - attack.t1218



status: deprecated





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects SyncAppvPublishingServer process execution which usually utilized by adversaries to bypass PowerShell execution restrictions.

<!--more-->


## Known false-positives

* App-V clients



## References

* https://lolbas-project.github.io/lolbas/Binaries/Syncappvpublishingserver/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/deprecated/process_creation_syncappvpublishingserver_exe.yml))
```yaml
title: SyncAppvPublishingServer Execution to Bypass Powershell Restriction
id: fde7929d-8beb-4a4c-b922-be9974671667
description: Detects SyncAppvPublishingServer process execution which usually utilized by adversaries to bypass PowerShell execution restrictions.
references:
    - https://lolbas-project.github.io/lolbas/Binaries/Syncappvpublishingserver/
author: 'Ensar Şamil, @sblmsrsn, OSCD Community'
date: 2020/10/05
modified: 2021/09/11
tags:
    - attack.defense_evasion
    - attack.t1218
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith: '\SyncAppvPublishingServer.exe'
    condition: selection
falsepositives:
    - App-V clients
level: medium
status: deprecated
```
