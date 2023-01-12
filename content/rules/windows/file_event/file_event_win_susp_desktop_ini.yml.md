---
title: "Suspicious desktop.ini Action"
aliases:
  - "/rule/81315b50-6b60-4d8f-9928-3466e1022515"
ruleid: 81315b50-6b60-4d8f-9928-3466e1022515

tags:
  - attack.persistence
  - attack.t1547.009



status: test





date: Thu, 19 Mar 2020 21:36:14 +0100


---

Detects unusual processes accessing desktop.ini, which can be leveraged to alter how Explorer displays a folder's content (i.e. renaming files) without changing them on disk.

<!--more-->


## Known false-positives

* Operations performed through Windows SCCM or equivalent
* read only access list authority



## References

* https://isc.sans.edu/forums/diary/Desktopini+as+a+postexploitation+tool/25912/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/file_event/file_event_win_susp_desktop_ini.yml))
```yaml
title: Suspicious desktop.ini Action
id: 81315b50-6b60-4d8f-9928-3466e1022515
status: test
description: Detects unusual processes accessing desktop.ini, which can be leveraged to alter how Explorer displays a folder's content (i.e. renaming files) without changing them on disk.
author: Maxime Thiebaut (@0xThiebaut), Tim Shelton (HAWK.IO)
references:
  - https://isc.sans.edu/forums/diary/Desktopini+as+a+postexploitation+tool/25912/
date: 2020/03/19
modified: 2021/12/03
logsource:
  product: windows
  category: file_event
detection:
  selection:
    TargetFilename|endswith: '\desktop.ini'
  filter:
    Image|startswith:
      - 'C:\Windows\'
      - 'C:\Program Files\'
      - 'C:\Program Files (x86)\'
  condition: selection and not filter
falsepositives:
  - Operations performed through Windows SCCM or equivalent
  - read only access list authority
level: medium
tags:
  - attack.persistence
  - attack.t1547.009

```