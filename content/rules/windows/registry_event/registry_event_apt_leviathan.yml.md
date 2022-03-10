---
title: "Leviathan Registry Key Activity"
aliases:
  - "/rule/70d43542-cd2d-483c-8f30-f16b436fd7db"


tags:
  - attack.persistence
  - attack.t1547.001



status: experimental





date: Tue, 7 Jul 2020 13:27:57 +0100


---

Detects registry key used by Leviathan APT in Malaysian focused campaign

<!--more-->




## References

* https://www.elastic.co/blog/advanced-techniques-used-in-malaysian-focused-apt-campaign


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/registry_event/registry_event_apt_leviathan.yml))
```yaml
title: Leviathan Registry Key Activity
id: 70d43542-cd2d-483c-8f30-f16b436fd7db
status: experimental
description: Detects registry key used by Leviathan APT in Malaysian focused campaign
references:
    - https://www.elastic.co/blog/advanced-techniques-used-in-malaysian-focused-apt-campaign
author: Aidan Bracher
date: 2020/07/07
modified: 2021/09/13
logsource:
    category: registry_event
    product: windows
detection:
    selection:
        TargetObject: 'HKCU\Software\Microsoft\Windows\CurrentVersion\Run\ntkd'
    condition: selection
level: critical
tags:
    - attack.persistence
    - attack.t1547.001
```
