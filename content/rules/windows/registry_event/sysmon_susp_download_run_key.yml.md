---
title: "Suspicious RUN Key from Download"
aliases:
  - "/rule/9c5037d1-c568-49b3-88c7-9846a5bdc2be"

tags:
  - attack.persistence
  - attack.t1060
  - attack.t1547.001



status: experimental



level: high



date: Tue, 1 Oct 2019 16:08:13 +0200


---

Detects the suspicious RUN keys created by software located in Download or temporary Outlook/Internet Explorer directories

<!--more-->


## Known false-positives

* Software installers downloaded and used by users



## References

* https://app.any.run/tasks/c5bef5b7-f484-4c43-9cf3-d5c5c7839def/


## Raw rule
```yaml
title: Suspicious RUN Key from Download
id: 9c5037d1-c568-49b3-88c7-9846a5bdc2be
status: experimental
description: Detects the suspicious RUN keys created by software located in Download or temporary Outlook/Internet Explorer directories
references:
    - https://app.any.run/tasks/c5bef5b7-f484-4c43-9cf3-d5c5c7839def/
author: Florian Roth
date: 2019/10/01
modified: 2020/09/06
tags:
    - attack.persistence
    - attack.t1060 # an old one
    - attack.t1547.001
logsource:
    category: registry_event
    product: windows
detection:
    selection:
        Image: 
            - '*\Downloads\\*'
            - '*\Temporary Internet Files\Content.Outlook\\*'
            - '*\Local Settings\Temporary Internet Files\\*'
        TargetObject: '*\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\\*'
    condition: selection
falsepositives:
    - Software installers downloaded and used by users
level: high

```
