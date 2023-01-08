---
title: "Lazarus Activity"
aliases:
  - "/rule/4a12fa47-c735-4032-a214-6fab5b120670"
ruleid: 4a12fa47-c735-4032-a214-6fab5b120670

tags:
  - attack.g0032
  - attack.execution
  - attack.t1106



status: experimental





date: Tue, 20 Apr 2021 20:05:51 +0545


---

Detects different process creation events as described in Malwarebytes's threat report on Lazarus group activity

<!--more-->


## Known false-positives

* Should not be any false positives



## References

* https://blog.malwarebytes.com/malwarebytes-news/2021/04/lazarus-apt-conceals-malicious-code-within-bmp-file-to-drop-its-rat/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_apt_lazarus_activity_apr21.yml))
```yaml
title: Lazarus Activity
id: 4a12fa47-c735-4032-a214-6fab5b120670
description: Detects different process creation events as described in Malwarebytes's threat report on Lazarus group activity
status: experimental
references:
    - https://blog.malwarebytes.com/malwarebytes-news/2021/04/lazarus-apt-conceals-malicious-code-within-bmp-file-to-drop-its-rat/
tags:
    - attack.g0032
    - attack.execution
    - attack.t1106 
author: Bhabesh Raj
date: 2021/04/20
modified: 2021/06/27
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        CommandLine|contains|all:
            - 'mshta'
            - '.zip'
    selection2:
        ParentImage:
            - 'C:\Windows\System32\wbem\wmiprvse.exe'
        Image:
            - 'C:\Windows\System32\mshta.exe'
    selection3:
        ParentImage|contains:
            - ':\Users\Public\'
        Image:
            - 'C:\Windows\System32\rundll32.exe'
    condition: 1 of selection*
falsepositives:
    - Should not be any false positives
level: critical
```
