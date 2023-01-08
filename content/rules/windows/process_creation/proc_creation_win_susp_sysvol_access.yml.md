---
title: "Suspicious SYSVOL Domain Group Policy Access"
aliases:
  - "/rule/05f3c945-dcc8-4393-9f3d-af65077a8f86"
ruleid: 05f3c945-dcc8-4393-9f3d-af65077a8f86

tags:
  - attack.credential_access
  - attack.t1552.006



status: test





date: Wed, 16 Jan 2019 23:36:31 +0100


---

Detects Access to Domain Group Policies stored in SYSVOL

<!--more-->


## Known false-positives

* administrative activity



## References

* https://adsecurity.org/?p=2288
* https://www.hybrid-analysis.com/sample/f2943f5e45befa52fb12748ca7171d30096e1d4fc3c365561497c618341299d5?environmentId=100


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_sysvol_access.yml))
```yaml
title: Suspicious SYSVOL Domain Group Policy Access
id: 05f3c945-dcc8-4393-9f3d-af65077a8f86
status: test
description: Detects Access to Domain Group Policies stored in SYSVOL
author: Markus Neis, Jonhnathan Ribeiro, oscd.community
references:
  - https://adsecurity.org/?p=2288
  - https://www.hybrid-analysis.com/sample/f2943f5e45befa52fb12748ca7171d30096e1d4fc3c365561497c618341299d5?environmentId=100
date: 2018/04/09
modified: 2022/01/07
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains|all:
      - '\SYSVOL\'
      - '\policies\'
  condition: selection
falsepositives:
  - administrative activity
level: medium
tags:
  - attack.credential_access
  - attack.t1552.006

```
