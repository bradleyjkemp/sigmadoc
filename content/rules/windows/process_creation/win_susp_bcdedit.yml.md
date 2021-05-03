---
title: "Possible Ransomware or Unauthorized MBR Modifications"
aliases:
  - "/rule/c9fbe8e9-119d-40a6-9b59-dd58a5d84429"

tags:
  - attack.defense_evasion
  - attack.t1070
  - attack.persistence
  - attack.t1542.003
  - attack.t1067



---

Detects, possibly, malicious unauthorized usage of bcdedit.exe

<!--more-->




## References

* https://docs.microsoft.com/en-us/windows-hardware/drivers/devtest/bcdedit--set


## Raw rule
```yaml
title: Possible Ransomware or Unauthorized MBR Modifications
id: c9fbe8e9-119d-40a6-9b59-dd58a5d84429
status: experimental
description: Detects, possibly, malicious unauthorized usage of bcdedit.exe
references:
    - https://docs.microsoft.com/en-us/windows-hardware/drivers/devtest/bcdedit--set
author: '@neu5ron'
date: 2019/02/07
tags:
    - attack.defense_evasion
    - attack.t1070
    - attack.persistence
    - attack.t1542.003
    - attack.t1067      # an old one
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image: '*\bcdedit.exe'
        CommandLine:
            - '*delete*'
            - '*deletevalue*'
            - '*import*'
    condition: selection
level: medium

```