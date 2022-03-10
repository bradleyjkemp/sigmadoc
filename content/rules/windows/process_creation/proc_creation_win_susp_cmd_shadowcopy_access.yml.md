---
title: "Conti Volume Shadow Listing"
aliases:
  - "/rule/c73124a7-3e89-44a3-bdc1-25fe4df754b1"


tags:
  - attack.impact
  - attack.t1490



status: experimental





date: Mon, 16 Aug 2021 09:10:05 +0200


---

Detects a command used by conti to access volume shadow backups

<!--more-->


## Known false-positives

* Some rare backup scenarios



## References

* https://twitter.com/vxunderground/status/1423336151860002816?s=20
* https://www.virustotal.com/gui/file/03e9b8c2e86d6db450e5eceec057d7e369ee2389b9daecaf06331a95410aa5f8/detection


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_cmd_shadowcopy_access.yml))
```yaml
title: Conti Volume Shadow Listing
id: c73124a7-3e89-44a3-bdc1-25fe4df754b1
description: Detects a command used by conti to access volume shadow backups
author: Max Altgelt, Tobias Michalski
date: 2021/08/09
status: experimental
references:
    - https://twitter.com/vxunderground/status/1423336151860002816?s=20
    - https://www.virustotal.com/gui/file/03e9b8c2e86d6db450e5eceec057d7e369ee2389b9daecaf06331a95410aa5f8/detection
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: 'copy \\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy'
    condition: selection
falsepositives:
    - Some rare backup scenarios
level: medium
tags:
    - attack.impact
    - attack.t1490 
```
