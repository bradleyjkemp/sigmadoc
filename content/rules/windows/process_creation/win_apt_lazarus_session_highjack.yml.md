---
title: "Lazarus Session Highjacker"
aliases:
  - "/rule/3f7f5b0b-5b16-476c-a85f-ab477f6dd24b"

tags:
  - attack.defense_evasion
  - attack.t1036
  - attack.t1036.005



date: Wed, 3 Jun 2020 17:38:03 -0400


---

Detects executables launched outside their default directories as used by Lazarus Group (Bluenoroff)

<!--more-->


## Known false-positives

* unknown



## References

* https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/07180244/Lazarus_Under_The_Hood_PDF_final.pdf


## Raw rule
```yaml
title: Lazarus Session Highjacker
id: 3f7f5b0b-5b16-476c-a85f-ab477f6dd24b
description: Detects executables launched outside their default directories as used by Lazarus Group (Bluenoroff)
status: experimental
references:
    - https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/07180244/Lazarus_Under_The_Hood_PDF_final.pdf
tags:
    - attack.defense_evasion
    - attack.t1036 # an old one
    - attack.t1036.005
author: Trent Liffick (@tliffick), Bartlomiej Czyz (@bczyz1)
date: 2020/06/03
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image: 
            - '*\msdtc.exe'
            - '*\gpvc.exe'
    filter:
        Image:
            - 'C:\Windows\System32\\*'
            - 'C:\Windows\SysWOW64\\*'
    condition: selection and not filter
falsepositives:
    - unknown
level: high

```
