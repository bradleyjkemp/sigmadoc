---
title: "An Application Is Uninstall"
aliases:
  - "/rule/570ae5ec-33dc-427c-b815-db86228ad43e"
ruleid: 570ae5ec-33dc-427c-b815-db86228ad43e

tags:
  - attack.impact
  - attack.t1489



status: experimental





date: Fri, 28 Jan 2022 16:12:38 +0100


---

An application have been remove check if it is a critical

<!--more-->


## Known false-positives

* Unknown




## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/application/win_builtin_remove_application.yml))
```yaml
title: An Application Is Uninstall
id: 570ae5ec-33dc-427c-b815-db86228ad43e
status: experimental
description: An application have been remove check if it is a critical
author: frack113
date: 2022/01/28
logsource:
    product: windows
    service: application
detection:
    selection:
        Provider_Name: 'MsiInstaller'
        EventID:
            - 11724
            - 1034
    condition: selection
falsepositives:
    - Unknown
level: low
tags:
    - attack.impact
    - attack.t1489 

```
