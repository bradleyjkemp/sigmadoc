---
title: "Suspicious Creation with Colorcpl"
aliases:
  - "/rule/e15b518d-b4ce-4410-a9cd-501f23ce4a18"
ruleid: e15b518d-b4ce-4410-a9cd-501f23ce4a18

tags:
  - attack.defense_evasion
  - attack.t1564



status: experimental





date: Fri, 21 Jan 2022 14:16:35 +0100


---

Once executed, colorcpl.exe will copy the arbitrary file to c:\windows\system32\spool\drivers\color\

<!--more-->


## Known false-positives

* Unknown



## References

* https://twitter.com/eral4m/status/1480468728324231172?s=20


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/file_event/file_event_win_susp_colorcpl.yml))
```yaml
title: Suspicious Creation with Colorcpl
id: e15b518d-b4ce-4410-a9cd-501f23ce4a18
status: experimental
description: Once executed, colorcpl.exe will copy the arbitrary file to c:\windows\system32\spool\drivers\color\
author: frack113
references:
  - https://twitter.com/eral4m/status/1480468728324231172?s=20
date: 2022/01/21
logsource:
  product: windows
  category: file_event
detection:
  selection:
    Image|endswith: \colorcpl.exe
  valid_ext:
    TargetFilename|endswith:
        - .icm
        - .gmmp
        - .cdmp
        - .camp
  condition: selection and not valid_ext
falsepositives:
  - Unknown
level: high
tags:
  - attack.defense_evasion
  - attack.t1564

```
