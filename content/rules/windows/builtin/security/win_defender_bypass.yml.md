---
title: "Windows Defender Exclusion Set"
aliases:
  - "/rule/e9c8808f-4cfb-4ba9-97d4-e5f3beaa244d"


tags:
  - attack.defense_evasion
  - attack.t1562.001



status: test





date: Sun, 27 Oct 2019 00:06:49 +0800


---

Detects scenarios where an windows defender exclusion was added in registry where an entity would want to bypass antivirus scanning from windows defender

<!--more-->


## Known false-positives

* Intended inclusions by administrator



## References

* https://www.bleepingcomputer.com/news/security/gootkit-malware-bypasses-windows-defender-by-setting-path-exclusions/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/security/win_defender_bypass.yml))
```yaml
title: Windows Defender Exclusion Set
id: e9c8808f-4cfb-4ba9-97d4-e5f3beaa244d
status: test
description: 'Detects scenarios where an windows defender exclusion was added in registry where an entity would want to bypass antivirus scanning from windows defender'
author: '@BarryShooshooga'
references:
  - https://www.bleepingcomputer.com/news/security/gootkit-malware-bypasses-windows-defender-by-setting-path-exclusions/
date: 2019/10/26
modified: 2021/11/27
logsource:
  product: windows
  service: security
  definition: 'Requirements: Audit Policy : Security Settings/Local Policies/Audit Policy, Registry System Access Control (SACL): Auditing/User'
detection:
  selection:
    EventID:
      - 4657
      - 4656
      - 4660
      - 4663
    ObjectName|contains: '\Microsoft\Windows Defender\Exclusions\'
  condition: selection
falsepositives:
  - Intended inclusions by administrator
level: high
tags:
  - attack.defense_evasion
  - attack.t1562.001

```