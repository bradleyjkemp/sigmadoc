---
title: "Suspicious Load of Advapi31.dll"
aliases:
  - "/rule/d813d662-785b-42ca-8b4a-f7457d78d5a9"


tags:
  - attack.defense_evasion
  - attack.t1070



status: experimental





date: Thu, 3 Feb 2022 18:54:34 +0100


---

Detects the load of advapi31.dll by a process running in an uncommon folder

<!--more-->


## Known false-positives

* unknown



## References

* https://github.com/hlldz/Phant0m


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/image_load/image_load_susp_advapi32_dll.yml))
```yaml
title: Suspicious Load of Advapi31.dll
id: d813d662-785b-42ca-8b4a-f7457d78d5a9
status: experimental
description: Detects the load of advapi31.dll by a process running in an uncommon folder
author: frack113
references:
  - https://github.com/hlldz/Phant0m
date: 2022/02/03
modified: 2022/02/11
logsource:
  product: windows
  category: image_load
detection:
  selection:
    ImageLoaded|endswith: '\advapi32.dll'
  filter_common:
    Image|startswith:
        - 'C:\Windows\'
        - 'C:\Program Files (x86)\'
        - 'C:\Program Files\'
  filter_defender:
    Image|startswith: 'C:\ProgramData\Microsoft\Windows Defender\platform\'
    Image|endswith: '\MpCmdRun.exe'
  filter_onedrive:
    Image|startswith: 'C:\Users\'
    Image|contains: '\AppData\Local\Microsoft\OneDrive\'
    Image|endswith: 'FileCoAuth.exe'
  condition: selection and not 1 of filter_*
falsepositives:
  - unknown
level: informational
tags:
  - attack.defense_evasion
  - attack.t1070

```
