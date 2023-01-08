---
title: "WINEKEY Registry Modification"
aliases:
  - "/rule/b98968aa-dbc0-4a9c-ac35-108363cbf8d5"
ruleid: b98968aa-dbc0-4a9c-ac35-108363cbf8d5

tags:
  - attack.persistence
  - attack.t1547



status: test





date: Fri, 30 Oct 2020 13:15:11 +0530


---

Detects potential malicious modification of run keys by winekey or team9 backdoor

<!--more-->


## Known false-positives

* Unknown



## References

* https://www.fireeye.com/blog/threat-research/2020/10/kegtap-and-singlemalt-with-a-ransomware-chaser.html


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/registry_event/registry_event_runkey_winekey.yml))
```yaml
title: WINEKEY Registry Modification
id: b98968aa-dbc0-4a9c-ac35-108363cbf8d5
status: test
description: Detects potential malicious modification of run keys by winekey or team9 backdoor
author: omkar72
references:
  - https://www.fireeye.com/blog/threat-research/2020/10/kegtap-and-singlemalt-with-a-ransomware-chaser.html
date: 2020/10/30
modified: 2021/11/27
logsource:
  category: registry_event
  product: windows
detection:
  selection:
    TargetObject|endswith:
      - 'Software\Microsoft\Windows\CurrentVersion\Run\Backup Mgr'
  condition: selection
fields:
  - ComputerName
  - Image
  - EventType
  - TargetObject
falsepositives:
  - Unknown
level: high
tags:
  - attack.persistence
  - attack.t1547

```
