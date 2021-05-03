---
title: "Leviathan Registry Key Activity"
aliases:
  - "/rule/70d43542-cd2d-483c-8f30-f16b436fd7db"

tags:
  - attack.persistence
  - attack.t1060
  - attack.t1547.001



date: Tue, 7 Jul 2020 13:27:57 +0100


---

Detects registry key used by Leviathan APT in Malaysian focused campaign

<!--more-->




## References

* https://www.elastic.co/blog/advanced-techniques-used-in-malaysian-focused-apt-campaign


## Raw rule
```yaml
title: Leviathan Registry Key Activity
id: 70d43542-cd2d-483c-8f30-f16b436fd7db
status: experimental
description: Detects registry key used by Leviathan APT in Malaysian focused campaign
references:
    - https://www.elastic.co/blog/advanced-techniques-used-in-malaysian-focused-apt-campaign
tags:
    - attack.persistence
    - attack.t1060 # an old one
    - attack.t1547.001
author: Aidan Bracher
date: 2020/07/07
modified: 2020/09/06
logsource:
    category: registry_event
    product: windows
detection:
    selection:
        TargetObject: 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run\ntkd'
    condition: selection
level: critical

```