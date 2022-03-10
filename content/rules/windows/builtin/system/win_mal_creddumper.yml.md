---
title: "Credential Dumping Tools Service Execution"
aliases:
  - "/rule/4976aa50-8f41-45c6-8b15-ab3fc10e79ed"


tags:
  - attack.credential_access
  - attack.execution
  - attack.t1003.001
  - attack.t1003.002
  - attack.t1003.004
  - attack.t1003.005
  - attack.t1003.006
  - attack.t1569.002
  - attack.s0005



status: experimental





date: Sun, 5 Mar 2017 23:52:02 +0100


---

Detects well-known credential dumping tools execution via service execution events

<!--more-->


## Known false-positives

* Legitimate Administrator using credential dumping tool for password recovery



## References

* https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/system/win_mal_creddumper.yml))
```yaml
title: Credential Dumping Tools Service Execution
id: 4976aa50-8f41-45c6-8b15-ab3fc10e79ed
description: Detects well-known credential dumping tools execution via service execution events
status: experimental
author: Florian Roth, Teymur Kheirkhabarov, Daniil Yugoslavskiy, oscd.community
date: 2017/03/05
modified: 2021/11/30
references:
    - https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment
tags:
    - attack.credential_access
    - attack.execution
    - attack.t1003.001
    - attack.t1003.002
    - attack.t1003.004
    - attack.t1003.005
    - attack.t1003.006
    - attack.t1569.002
    - attack.s0005
logsource:
    product: windows
    service: system
detection:
    selection:
        Provider_Name: 'Service Control Manager'
        EventID: 7045
        ImagePath|contains:
            - 'fgexec'
            - 'dumpsvc'
            - 'cachedump'
            - 'mimidrv'
            - 'gsecdump'
            - 'servpw'
            - 'pwdump'
    condition: selection
falsepositives:
    - Legitimate Administrator using credential dumping tool for password recovery
level: high
```
