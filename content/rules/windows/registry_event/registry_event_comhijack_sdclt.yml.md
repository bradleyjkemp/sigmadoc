---
title: "COM Hijack via Sdclt"
aliases:
  - "/rule/07743f65-7ec9-404a-a519-913db7118a8d"
ruleid: 07743f65-7ec9-404a-a519-913db7118a8d

tags:
  - attack.privilege_escalation
  - attack.t1546
  - attack.t1548



status: test





date: Sun, 27 Sep 2020 21:19:04 +0530


---

Detects changes to 'HKCU\Software\Classes\Folder\shell\open\command\DelegateExecute'

<!--more-->


## Known false-positives

* unknown



## References

* http://blog.sevagas.com/?Yet-another-sdclt-UAC-bypass
* https://www.exploit-db.com/exploits/47696


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/registry_event/registry_event_comhijack_sdclt.yml))
```yaml
title: COM Hijack via Sdclt
id: 07743f65-7ec9-404a-a519-913db7118a8d
status: test
description: Detects changes to 'HKCU\Software\Classes\Folder\shell\open\command\DelegateExecute'
author: Omkar Gudhate
references:
  - http://blog.sevagas.com/?Yet-another-sdclt-UAC-bypass
  - https://www.exploit-db.com/exploits/47696
date: 2020/09/27
modified: 2021/11/27
logsource:
  category: registry_event
  product: windows
detection:
  selection:
    TargetObject:
      - 'HKCU\Software\Classes\Folder\shell\open\command\DelegateExecute'
  condition: selection
falsepositives:
  - unknown
level: high
tags:
  - attack.privilege_escalation
  - attack.t1546
  - attack.t1548

```
