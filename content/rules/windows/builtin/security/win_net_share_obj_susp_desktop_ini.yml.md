---
title: "Windows Network Access Suspicious desktop.ini Action"
aliases:
  - "/rule/35bc7e28-ee6b-492f-ab04-da58fcf6402e"


tags:
  - attack.persistence
  - attack.t1547.009



status: test





date: Mon, 6 Dec 2021 22:02:24 +0000


---

Detects unusual processes accessing desktop.ini remotely over network share, which can be leveraged to alter how Explorer displays a folder's content (i.e. renaming files) without changing them on disk.

<!--more-->


## Known false-positives

* Read only access list authority



## References

* https://isc.sans.edu/forums/diary/Desktopini+as+a+postexploitation+tool/25912/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/security/win_net_share_obj_susp_desktop_ini.yml))
```yaml
title: Windows Network Access Suspicious desktop.ini Action
id: 35bc7e28-ee6b-492f-ab04-da58fcf6402e
status: test
description: Detects unusual processes accessing desktop.ini remotely over network share, which can be leveraged to alter how Explorer displays a folder's content (i.e. renaming files) without changing them on disk.
author: Tim Shelton (HAWK.IO)
references:
  - https://isc.sans.edu/forums/diary/Desktopini+as+a+postexploitation+tool/25912/
date: 2021/12/06
modified: 2022/01/16
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 5145
    ObjectType: File
    RelativeTargetName|endswith: '\desktop.ini'
    AccessList|contains:
      - 'WriteData'
      - 'DELETE'
      - 'WriteDAC'
      - 'AppendData'
      - 'AddSubdirectory'
  condition: selection
falsepositives:
  - Read only access list authority
level: medium
tags:
  - attack.persistence
  - attack.t1547.009

```
