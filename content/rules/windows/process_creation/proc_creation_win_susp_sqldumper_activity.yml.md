---
title: "Dumping Process via Sqldumper.exe"
aliases:
  - "/rule/23ceaf5c-b6f1-4a32-8559-f2ff734be516"
ruleid: 23ceaf5c-b6f1-4a32-8559-f2ff734be516

tags:
  - attack.credential_access
  - attack.t1003.001



status: test





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects process dump via legitimate sqldumper.exe binary

<!--more-->


## Known false-positives

* Legitimate MSSQL Server actions



## References

* https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OtherMSBinaries/Sqldumper.yml
* https://twitter.com/countuponsec/status/910977826853068800
* https://twitter.com/countuponsec/status/910969424215232518
* https://lolbas-project.github.io/lolbas/OtherMSBinaries/Sqldumper/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_sqldumper_activity.yml))
```yaml
title: Dumping Process via Sqldumper.exe
id: 23ceaf5c-b6f1-4a32-8559-f2ff734be516
status: test
description: Detects process dump via legitimate sqldumper.exe binary
author: Kirill Kiryanov, oscd.community
references:
  - https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OtherMSBinaries/Sqldumper.yml
  - https://twitter.com/countuponsec/status/910977826853068800
  - https://twitter.com/countuponsec/status/910969424215232518
  - https://lolbas-project.github.io/lolbas/OtherMSBinaries/Sqldumper/
date: 2020/10/08
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\sqldumper.exe'
    CommandLine|contains:
      - '0x0110'
      - '0x01100:40'
  condition: selection
falsepositives:
  - Legitimate MSSQL Server actions
level: medium
tags:
  - attack.credential_access
  - attack.t1003.001

```
