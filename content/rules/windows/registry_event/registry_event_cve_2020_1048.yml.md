---
title: "Suspicious New Printer Ports in Registry (CVE-2020-1048)"
aliases:
  - "/rule/7ec912f2-5175-4868-b811-ec13ad0f8567"


tags:
  - attack.persistence
  - attack.execution
  - attack.defense_evasion
  - attack.t1112



status: test





date: Fri, 15 May 2020 12:08:31 +0200


---

Detects a new and suspicious printer port creation in Registry that could be an attempt to exploit CVE-2020-1048

<!--more-->


## Known false-positives

* New printer port install on host



## References

* https://windows-internals.com/printdemon-cve-2020-1048/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/registry_event/registry_event_cve_2020_1048.yml))
```yaml
title: Suspicious New Printer Ports in Registry (CVE-2020-1048)
id: 7ec912f2-5175-4868-b811-ec13ad0f8567
status: test
description: Detects a new and suspicious printer port creation in Registry that could be an attempt to exploit CVE-2020-1048
author: EagleEye Team, Florian Roth, NVISO
references:
  - https://windows-internals.com/printdemon-cve-2020-1048/
date: 2020/05/13
modified: 2022/01/13
logsource:
  product: windows
  category: registry_event
detection:
  selection:
    EventType: SetValue
    TargetObject|startswith: 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Ports'
    Details|contains:
      - '.dll'
      - '.exe'
      - '.bat'
      - '.com'
      - 'C:'
  condition: selection
falsepositives:
  - New printer port install on host
level: high
tags:
  - attack.persistence
  - attack.execution
  - attack.defense_evasion
  - attack.t1112

```
