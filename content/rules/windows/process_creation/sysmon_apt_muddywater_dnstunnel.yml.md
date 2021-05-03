---
title: "DNS Tunnel Technique from MuddyWater"
aliases:
  - "/rule/36222790-0d43-4fe8-86e4-674b27809543"

tags:
  - attack.command_and_control
  - attack.t1071
  - attack.t1071.004



date: Thu, 4 Jun 2020 14:27:19 +0300


---

Detecting DNS tunnel activity for Muddywater actor

<!--more-->


## Known false-positives

* Unknown



## References

* https://www.virustotal.com/gui/file/5ad401c3a568bd87dd13f8a9ddc4e450ece61cd9ce4d1b23f68ce0b1f3c190b7/
* https://www.vmray.com/analyses/5ad401c3a568/report/overview.html


## Raw rule
```yaml
title: DNS Tunnel Technique from MuddyWater
id: 36222790-0d43-4fe8-86e4-674b27809543
description: Detecting DNS tunnel activity for Muddywater actor
author: '@caliskanfurkan_'
status: experimental
date: 2020/06/04
references:
    - https://www.virustotal.com/gui/file/5ad401c3a568bd87dd13f8a9ddc4e450ece61cd9ce4d1b23f68ce0b1f3c190b7/
    - https://www.vmray.com/analyses/5ad401c3a568/report/overview.html
tags:
    - attack.command_and_control
    - attack.t1071 # an old one
    - attack.t1071.004
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\powershell.exe'
        ParentImage|endswith:
            - '\excel.exe'
        CommandLine|contains:
            - 'DataExchange.dll'
    condition: selection
falsepositives:
    - Unknown
level: critical

```