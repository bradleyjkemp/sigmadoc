---
title: "Suspicious Unattend.xml File Access"
aliases:
  - "/rule/1a3d42dd-3763-46b9-8025-b5f17f340dfb"
ruleid: 1a3d42dd-3763-46b9-8025-b5f17f340dfb

tags:
  - attack.credential_access
  - attack.t1552.001



status: experimental





date: Sun, 19 Dec 2021 11:20:42 +0100


---

Attempts to access unattend.xml, where credentials are commonly stored, within the Panther directory where installation logs are stored.
If these files exist, their contents will be displayed. They are used to store credentials/answers during the unattended windows install process


<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1552.001/T1552.001.md


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/file_event/file_event_win_access_susp_unattend_xml.yml))
```yaml
title: Suspicious Unattend.xml File Access
id: 1a3d42dd-3763-46b9-8025-b5f17f340dfb
status: experimental
description: |
  Attempts to access unattend.xml, where credentials are commonly stored, within the Panther directory where installation logs are stored.
  If these files exist, their contents will be displayed. They are used to store credentials/answers during the unattended windows install process
author: frack113
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1552.001/T1552.001.md
date: 2021/12/19
logsource:
  product: windows
  category: file_event
detection:
  selection:
    TargetFilename|endswith: '\unattend.xml'
  condition: selection
falsepositives:
  - Unknown
level: medium
tags:
  - attack.credential_access
  - attack.t1552.001

```
