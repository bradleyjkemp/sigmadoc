---
title: "Lazarus Session Highjacker"
aliases:
  - "/rule/3f7f5b0b-5b16-476c-a85f-ab477f6dd24b"
ruleid: 3f7f5b0b-5b16-476c-a85f-ab477f6dd24b

tags:
  - attack.defense_evasion
  - attack.t1036.005



status: test





date: Wed, 3 Jun 2020 17:38:03 -0400


---

Detects executables launched outside their default directories as used by Lazarus Group (Bluenoroff)

<!--more-->


## Known false-positives

* unknown



## References

* https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/07180244/Lazarus_Under_The_Hood_PDF_final.pdf


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_apt_lazarus_session_highjack.yml))
```yaml
title: Lazarus Session Highjacker
id: 3f7f5b0b-5b16-476c-a85f-ab477f6dd24b
status: test
description: Detects executables launched outside their default directories as used by Lazarus Group (Bluenoroff)
author: Trent Liffick (@tliffick), Bartlomiej Czyz (@bczyz1)
references:
  - https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/07180244/Lazarus_Under_The_Hood_PDF_final.pdf
date: 2020/06/03
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith:
      - '\msdtc.exe'
      - '\gpvc.exe'
  filter:
    Image|startswith:
      - 'C:\Windows\System32\'
      - 'C:\Windows\SysWOW64\'
  condition: selection and not filter
falsepositives:
  - unknown
level: high
tags:
  - attack.defense_evasion
  - attack.t1036.005

```
