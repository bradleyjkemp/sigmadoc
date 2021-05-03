---
title: "COM Hijack via Sdclt"
aliases:
  - "/rule/07743f65-7ec9-404a-a519-913db7118a8d"

tags:
  - attack.privilege_escalation
  - attack.t1546
  - attack.t1548



date: Sun, 27 Sep 2020 21:19:04 +0530


---

Detects changes to 'HKCU\Software\Classes\Folder\shell\open\command\DelegateExecute'

<!--more-->


## Known false-positives

* unknown



## References

* http://blog.sevagas.com/?Yet-another-sdclt-UAC-bypass
* https://www.exploit-db.com/exploits/47696


## Raw rule
```yaml
title: COM Hijack via Sdclt
id: 07743f65-7ec9-404a-a519-913db7118a8d
status: experimental
description: Detects changes to 'HKCU\Software\Classes\Folder\shell\open\command\DelegateExecute'
author: Omkar Gudhate
date: 2020/09/27
references:
    - http://blog.sevagas.com/?Yet-another-sdclt-UAC-bypass
    - https://www.exploit-db.com/exploits/47696
tags:
    - attack.privilege_escalation
    - attack.t1546
    - attack.t1548
logsource:
    category: registry_event
    product: windows
detection:
    selection:
        TargetObject:
            - 'HKCU\Software\Classes\Folder\shell\open\command\DelegateExecute'
        EventType:
            - SetValue
    condition: selection
falsepositives:
    - unknown
level: high

```
