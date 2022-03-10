---
title: "Exchange PowerShell Snap-Ins Used by HAFNIUM"
aliases:
  - "/rule/25676e10-2121-446e-80a4-71ff8506af47"


tags:
  - attack.execution
  - attack.t1059.001
  - attack.collection
  - attack.t1114



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects adding and using Exchange PowerShell snap-ins to export mailbox data by HAFNIUM

<!--more-->


## Known false-positives

* Unknown



## References

* https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/
* https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/web/win_powershell_snapins_hafnium.yml))
```yaml
title: Exchange PowerShell Snap-Ins Used by HAFNIUM 
id: 25676e10-2121-446e-80a4-71ff8506af47
status: experimental
description: Detects adding and using Exchange PowerShell snap-ins to export mailbox data by HAFNIUM
author: FPT.EagleEye 
references:
    - https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/
    - https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers/
date: 2021/03/03
modified: 2021/08/09
tags:
    - attack.execution
    - attack.t1059.001
    - attack.collection
    - attack.t1114
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image: '*\powershell.exe'
        CommandLine: '*add-pssnapin microsoft.exchange.powershell.snapin*'
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Unknown
level: high

```
