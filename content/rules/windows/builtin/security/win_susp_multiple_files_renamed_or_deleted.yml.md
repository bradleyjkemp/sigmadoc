---
title: "Suspicious Multiple File Rename Or Delete Occurred"
aliases:
  - "/rule/97919310-06a7-482c-9639-92b67ed63cf8"


tags:
  - attack.impact
  - attack.t1486



status: test





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects multiple file rename or delete events occurrence within a specified period of time by a same user (these events may signalize about ransomware activity).

<!--more-->


## Known false-positives

* Software uninstallation
* Files restore activities



## References

* https://www.manageengine.com/data-security/how-to/how-to-detect-ransomware-attacks.html


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/security/win_susp_multiple_files_renamed_or_deleted.yml))
```yaml
title: Suspicious Multiple File Rename Or Delete Occurred
id: 97919310-06a7-482c-9639-92b67ed63cf8
status: test
description: Detects multiple file rename or delete events occurrence within a specified period of time by a same user (these events may signalize about ransomware activity).
author: Vasiliy Burov, oscd.community
references:
  - https://www.manageengine.com/data-security/how-to/how-to-detect-ransomware-attacks.html
date: 2020/10/16
modified: 2021/11/27
logsource:
  product: windows
  service: security
  definition: 'Requirements: Audit Policy : Policies/Windows Settings/Security Settings/Local Policies/Audit Policy/Audit object access, Policies/Windows Settings/Security Settings/Advanced Audit Policy Configuration/Object Access'
detection:
  selection:
    EventID: 4663
    ObjectType: 'File'
    AccessList: '%%1537'
    Keywords: '0x8020000000000000'
  timeframe: 30s
  condition: selection | count() by SubjectLogonId > 10
falsepositives:
  - Software uninstallation
  - Files restore activities
level: medium
tags:
  - attack.impact
  - attack.t1486

```
