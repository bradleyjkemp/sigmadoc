---
title: "Shadow Copies Creation Using Operating Systems Utilities"
aliases:
  - "/rule/b17ea6f7-6e90-447e-a799-e6c0a493d6ce"


tags:
  - attack.credential_access
  - attack.t1003
  - attack.t1003.002
  - attack.t1003.003



status: test





date: Mon, 4 Nov 2019 04:26:34 +0300


---

Shadow Copies creation using operating systems utilities, possible credential access

<!--more-->


## Known false-positives

* Legitimate administrator working with shadow copies, access for backup purposes



## References

* https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment
* https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/tutorial-for-ntds-goodness-vssadmin-wmis-ntdsdit-system/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_shadow_copies_creation.yml))
```yaml
title: Shadow Copies Creation Using Operating Systems Utilities
id: b17ea6f7-6e90-447e-a799-e6c0a493d6ce
status: test
description: Shadow Copies creation using operating systems utilities, possible credential access
author: Teymur Kheirkhabarov, Daniil Yugoslavskiy, oscd.community
references:
  - https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment
  - https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/tutorial-for-ntds-goodness-vssadmin-wmis-ntdsdit-system/
date: 2019/10/22
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith:
      - '\powershell.exe'
      - '\wmic.exe'
      - '\vssadmin.exe'
    CommandLine|contains|all:
      - shadow
      - create
  condition: selection
falsepositives:
  - Legitimate administrator working with shadow copies, access for backup purposes
level: medium
tags:
  - attack.credential_access
  - attack.t1003
  - attack.t1003.002
  - attack.t1003.003

```
