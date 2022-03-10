---
title: "Judgement Panda Credential Access Activity"
aliases:
  - "/rule/b83f5166-9237-4b5e-9cd4-7b5d52f4d8ee"


tags:
  - attack.credential_access
  - attack.t1552.001
  - attack.t1003.003



status: test





date: Thu, 21 Feb 2019 09:54:01 +0100


---

Detects Russian group activity as described in Global Threat Report 2019 by Crowdstrike

<!--more-->


## Known false-positives

* unknown



## References

* https://www.crowdstrike.com/resources/reports/2019-crowdstrike-global-threat-report/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_apt_bear_activity_gtr19.yml))
```yaml
title: Judgement Panda Credential Access Activity
id: b83f5166-9237-4b5e-9cd4-7b5d52f4d8ee
status: test
description: Detects Russian group activity as described in Global Threat Report 2019 by Crowdstrike
author: Florian Roth
references:
  - https://www.crowdstrike.com/resources/reports/2019-crowdstrike-global-threat-report/
date: 2019/02/21
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  selection1:
    Image|endswith: '\xcopy.exe'
    CommandLine|contains|all:
      - '/S'
      - '/E'
      - '/C'
      - '/Q'
      - '/H'
      - '\\'
  selection2:
    Image|endswith: '\adexplorer.exe'
    CommandLine|contains|all:
      - '-snapshot'
      - '""'
      - 'c:\users\'
  condition: selection1 or selection2
falsepositives:
  - unknown
level: critical
tags:
  - attack.credential_access
  - attack.t1552.001
  - attack.t1003.003

```
