---
title: "Possible SPN Enumeration"
aliases:
  - "/rule/1eeed653-dbc8-4187-ad0c-eeebb20e6599"

tags:
  - attack.credential_access
  - attack.t1558.003
  - attack.t1208



---

Detects Service Principal Name Enumeration used for Kerberoasting

<!--more-->


## Known false-positives

* Administrator Activity



## References

* https://p16.praetorian.com/blog/how-to-use-kerberoasting-t1208-for-privilege-escalation


## Raw rule
```yaml
title: Possible SPN Enumeration
id: 1eeed653-dbc8-4187-ad0c-eeebb20e6599
description: Detects Service Principal Name Enumeration used for Kerberoasting
status: experimental
references:
    - https://p16.praetorian.com/blog/how-to-use-kerberoasting-t1208-for-privilege-escalation
author: Markus Neis, keepwatch
date: 2018/11/14
tags:
    - attack.credential_access
    - attack.t1558.003
    - attack.t1208      # an old one
logsource:
    category: process_creation
    product: windows
detection:
    selection_image:
        Image: '*\setspn.exe'
    selection_desc:
        Description: '*Query or reset the computer* SPN attribute*'
    cmd:
        CommandLine: '*-q*'
    condition: (selection_image or selection_desc) and cmd
falsepositives:
    - Administrator Activity
level: medium

```