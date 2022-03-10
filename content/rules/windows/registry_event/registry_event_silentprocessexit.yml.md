---
title: "SilentProcessExit Monitor Registrytion"
aliases:
  - "/rule/c81fe886-cac0-4913-a511-2822d72ff505"


tags:
  - attack.persistence
  - attack.t1546.012



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects changes to the Registry in which a monitor program gets registered to monitor the exit of another process

<!--more-->


## Known false-positives

* Unknown



## References

* https://oddvar.moe/2018/04/10/persistence-using-globalflags-in-image-file-execution-options-hidden-from-autoruns-exe/
* https://www.deepinstinct.com/2021/02/16/lsass-memory-dumps-are-stealthier-than-ever-before-part-2/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/registry_event/registry_event_silentprocessexit.yml))
```yaml
title: SilentProcessExit Monitor Registrytion
id: c81fe886-cac0-4913-a511-2822d72ff505
description: Detects changes to the Registry in which a monitor program gets registered to monitor the exit of another process
status: experimental
author: Florian Roth
references:
    - https://oddvar.moe/2018/04/10/persistence-using-globalflags-in-image-file-execution-options-hidden-from-autoruns-exe/
    - https://www.deepinstinct.com/2021/02/16/lsass-memory-dumps-are-stealthier-than-ever-before-part-2/
date: 2021/02/26
modified: 2022/01/13
tags:
    - attack.persistence
    - attack.t1546.012
logsource:
    category: registry_event
    product: windows
detection:
    selection:   
        EventType: SetValue 
        TargetObject|contains: 'Microsoft\Windows NT\CurrentVersion\SilentProcessExit'
        Details|contains: 'MonitorProcess'
    condition: selection
falsepositives:
    - Unknown
level: high
```
