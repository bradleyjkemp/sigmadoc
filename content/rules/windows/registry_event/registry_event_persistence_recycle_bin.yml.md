---
title: "Registry Persistence Mechanisms in Recycle Bin"
aliases:
  - "/rule/277efb8f-60be-4f10-b4d3-037802f37167"
ruleid: 277efb8f-60be-4f10-b4d3-037802f37167

tags:
  - attack.persistence
  - attack.t1547



status: experimental





date: Thu, 18 Nov 2021 18:39:20 +0100


---

Detects persistence registry keys for Recycle Bin

<!--more-->


## Known false-positives

* unknown



## References

* https://github.com/vxunderground/VXUG-Papers/blob/main/The%20Persistence%20Series/Persistence%20via%20Recycle%20Bin/Persistence_via_Recycle_Bin.pdf


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/registry_event/registry_event_persistence_recycle_bin.yml))
```yaml
title: Registry Persistence Mechanisms in Recycle Bin
id: 277efb8f-60be-4f10-b4d3-037802f37167
status: experimental
description: Detects persistence registry keys for Recycle Bin
references:
    - https://github.com/vxunderground/VXUG-Papers/blob/main/The%20Persistence%20Series/Persistence%20via%20Recycle%20Bin/Persistence_via_Recycle_Bin.pdf
date: 2021/11/18
author: frack113
logsource:
    category: registry_event
    product: windows
detection:
    Create_key:
        EventType: RenameKey
        NewName: HKCR\CLSID\{645FF040-5081-101B-9F08-00AA002F954E}\shell\open
    Set_key:
        EventType: SetValue
        TargetObject: HKCR\CLSID\{645FF040-5081-101B-9F08-00AA002F954E}\shell\open\command\(Default)
    condition: Create_key or Set_key
tags:
    - attack.persistence
    - attack.t1547 
falsepositives:
    - unknown
level: critical

```
