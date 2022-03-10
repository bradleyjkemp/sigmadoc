---
title: "Winnti Malware HK University Campaign"
aliases:
  - "/rule/3121461b-5aa0-4a41-b910-66d25524edbb"


tags:
  - attack.defense_evasion
  - attack.t1574.002
  - attack.g0044



status: test





date: Sat, 1 Feb 2020 15:43:30 +0100


---

Detects specific process characteristics of Winnti malware noticed in Dec/Jan 2020 in a campaign against Honk Kong universities

<!--more-->


## Known false-positives

* Unlikely



## References

* https://www.welivesecurity.com/2020/01/31/winnti-group-targeting-universities-hong-kong/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_apt_winnti_mal_hk_jan20.yml))
```yaml
title: Winnti Malware HK University Campaign
id: 3121461b-5aa0-4a41-b910-66d25524edbb
status: test
description: Detects specific process characteristics of Winnti malware noticed in Dec/Jan 2020 in a campaign against Honk Kong universities
author: Florian Roth, Markus Neis
references:
  - https://www.welivesecurity.com/2020/01/31/winnti-group-targeting-universities-hong-kong/
date: 2020/02/01
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  selection1:
    ParentImage|contains:
      - 'C:\Windows\Temp'
      - '\hpqhvind.exe'
    Image|startswith: 'C:\ProgramData\DRM'
  selection2:
    ParentImage|startswith: 'C:\ProgramData\DRM'
    Image|endswith: '\wmplayer.exe'
  selection3:
    ParentImage|endswith: '\Test.exe'
    Image|endswith: '\wmplayer.exe'
  selection4:
    Image: 'C:\ProgramData\DRM\CLR\CLR.exe'
  selection5:
    ParentImage|startswith: 'C:\ProgramData\DRM\Windows'
    Image|endswith: '\SearchFilterHost.exe'
  condition: 1 of selection*
falsepositives:
  - Unlikely
level: critical
tags:
  - attack.defense_evasion
  - attack.t1574.002
  - attack.g0044

```