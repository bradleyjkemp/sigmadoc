---
title: "Findstr Launching .lnk File"
aliases:
  - "/rule/33339be3-148b-4e16-af56-ad16ec6c7e7b"


tags:
  - attack.defense_evasion
  - attack.t1036
  - attack.t1202
  - attack.t1027.003



status: test





date: Wed, 3 Jun 2020 17:38:03 -0400


---

Detects usage of findstr to identify and execute a lnk file as seen within the HHS redirect attack

<!--more-->


## Known false-positives

* unknown



## References

* https://www.bleepingcomputer.com/news/security/hhsgov-open-redirect-used-by-coronavirus-phishing-to-spread-malware/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_findstr_lnk.yml))
```yaml
title: Findstr Launching .lnk File
id: 33339be3-148b-4e16-af56-ad16ec6c7e7b
status: test
description: Detects usage of findstr to identify and execute a lnk file as seen within the HHS redirect attack
author: Trent Liffick
references:
  - https://www.bleepingcomputer.com/news/security/hhsgov-open-redirect-used-by-coronavirus-phishing-to-spread-malware/
date: 2020/05/01
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\findstr.exe'
    CommandLine|endswith: '.lnk'
  condition: selection
fields:
  - Image
  - CommandLine
  - ParentCommandLine
falsepositives:
  - unknown
level: medium
tags:
  - attack.defense_evasion
  - attack.t1036
  - attack.t1202
  - attack.t1027.003

```