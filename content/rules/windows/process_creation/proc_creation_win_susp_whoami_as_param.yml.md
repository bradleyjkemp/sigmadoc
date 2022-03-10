---
title: "WhoAmI as Parameter"
aliases:
  - "/rule/e9142d84-fbe0-401d-ac50-3e519fb00c89"


tags:
  - attack.discovery
  - attack.t1033
  - car.2016-03-001



status: experimental





date: Mon, 29 Nov 2021 09:55:56 +0100


---

Detects a suspicious process command line that uses whoami as first parameter (as e.g. used by EfsPotato)

<!--more-->


## Known false-positives

* Unknown



## References

* https://twitter.com/blackarrowsec/status/1463805700602224645?s=12


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_whoami_as_param.yml))
```yaml
title: WhoAmI as Parameter
id: e9142d84-fbe0-401d-ac50-3e519fb00c89
status: experimental
author: Florian Roth
date: 2021/11/29
description: Detects a suspicious process command line that uses whoami as first parameter (as e.g. used by EfsPotato)
references:
    - https://twitter.com/blackarrowsec/status/1463805700602224645?s=12
tags:
    - attack.discovery
    - attack.t1033
    - car.2016-03-001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: '.exe whoami'
    condition: selection
falsepositives:
    - Unknown
level: high

```
