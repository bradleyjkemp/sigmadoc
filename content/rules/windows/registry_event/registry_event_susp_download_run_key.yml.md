---
title: "Suspicious Run Key from Download"
aliases:
  - "/rule/9c5037d1-c568-49b3-88c7-9846a5bdc2be"


tags:
  - attack.persistence
  - attack.t1547.001



status: test





date: Tue, 1 Oct 2019 16:08:13 +0200


---

Detects the suspicious RUN keys created by software located in Download or temporary Outlook/Internet Explorer directories

<!--more-->


## Known false-positives

* Software installers downloaded and used by users



## References

* https://app.any.run/tasks/c5bef5b7-f484-4c43-9cf3-d5c5c7839def/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/registry_event/registry_event_susp_download_run_key.yml))
```yaml
title: Suspicious Run Key from Download
id: 9c5037d1-c568-49b3-88c7-9846a5bdc2be
status: test
description: Detects the suspicious RUN keys created by software located in Download or temporary Outlook/Internet Explorer directories
author: Florian Roth
references:
  - https://app.any.run/tasks/c5bef5b7-f484-4c43-9cf3-d5c5c7839def/
date: 2019/10/01
modified: 2021/11/27
logsource:
  category: registry_event
  product: windows
detection:
  selection:
    Image|contains:
      - '\Downloads\'
      - '\Temporary Internet Files\Content.Outlook\'
      - '\Local Settings\Temporary Internet Files\'
    TargetObject|contains: '\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\'
  condition: selection
falsepositives:
  - Software installers downloaded and used by users
level: high
tags:
  - attack.persistence
  - attack.t1547.001

```
