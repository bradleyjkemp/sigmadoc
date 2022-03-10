---
title: "Devtoolslauncher.exe Executes Specified Binary"
aliases:
  - "/rule/cc268ac1-42d9-40fd-9ed3-8c4e1a5b87e6"


tags:
  - attack.defense_evasion
  - attack.t1218



status: test





date: Wed, 23 Oct 2019 13:00:21 +0200


---

The Devtoolslauncher.exe executes other binary

<!--more-->


## Known false-positives

* Legitimate use of devtoolslauncher.exe by legitimate user



## References

* https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OtherMSBinaries/Devtoolslauncher.yml
* https://twitter.com/_felamos/status/1179811992841797632


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_devtoolslauncher.yml))
```yaml
title: Devtoolslauncher.exe Executes Specified Binary
id: cc268ac1-42d9-40fd-9ed3-8c4e1a5b87e6
status: test
description: The Devtoolslauncher.exe executes other binary
author: Beyu Denis, oscd.community (rule), @_felamos (idea)
references:
  - https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OtherMSBinaries/Devtoolslauncher.yml
  - https://twitter.com/_felamos/status/1179811992841797632
date: 2019/10/12
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\devtoolslauncher.exe'
    CommandLine|contains: 'LaunchForDeploy'
  condition: selection
falsepositives:
  - Legitimate use of devtoolslauncher.exe by legitimate user
level: critical
tags:
  - attack.defense_evasion
  - attack.t1218 

```
