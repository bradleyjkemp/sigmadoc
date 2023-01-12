---
title: "Turla Group Commands May 2020"
aliases:
  - "/rule/9e2e51c5-c699-4794-ba5a-29f5da40ac0c"
ruleid: 9e2e51c5-c699-4794-ba5a-29f5da40ac0c

tags:
  - attack.g0010
  - attack.execution
  - attack.t1059.001
  - attack.t1053.005
  - attack.t1027



status: test





date: Fri, 5 Jun 2020 13:18:03 -0400


---

Detects commands used by Turla group as reported by ESET in May 2020

<!--more-->


## Known false-positives

* Unknown



## References

* https://www.welivesecurity.com/wp-content/uploads/2020/05/ESET_Turla_ComRAT.pdf


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_apt_turla_comrat_may20.yml))
```yaml
title: Turla Group Commands May 2020
id: 9e2e51c5-c699-4794-ba5a-29f5da40ac0c
status: test
description: Detects commands used by Turla group as reported by ESET in May 2020
author: Florian Roth
references:
  - https://www.welivesecurity.com/wp-content/uploads/2020/05/ESET_Turla_ComRAT.pdf
date: 2020/05/26
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  selection1:
    CommandLine|contains:
      - 'tracert -h 10 yahoo.com'
      - '.WSqmCons))|iex;'
      - 'Fr`omBa`se6`4Str`ing'
  selection2:
    CommandLine|contains|all:
      - 'net use https://docs.live.net'
      - '@aol.co.uk'
  condition: 1 of selection*
falsepositives:
  - Unknown
level: critical
tags:
  - attack.g0010
  - attack.execution
  - attack.t1059.001
  - attack.t1053.005
  - attack.t1027

```