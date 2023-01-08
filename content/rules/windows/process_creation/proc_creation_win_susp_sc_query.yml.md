---
title: "Suspicious Sc Query"
aliases:
  - "/rule/57712d7a-679c-4a41-a913-87e7175ae429"
ruleid: 57712d7a-679c-4a41-a913-87e7175ae429

tags:
  - attack.discovery
  - attack.t1007



status: experimental





date: Mon, 6 Dec 2021 18:56:25 +0100


---

Adversaries may try to get information about registered services

<!--more-->


## Known false-positives

* unknown



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1007/T1007.md#atomic-test-1---system-service-discovery


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_sc_query.yml))
```yaml
title: Suspicious Sc Query
id: 57712d7a-679c-4a41-a913-87e7175ae429
status: experimental
description: Adversaries may try to get information about registered services
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1007/T1007.md#atomic-test-1---system-service-discovery
author: frack113
date: 2021/12/06
logsource:
    category: process_creation
    product: windows
detection:
    sc_query:
        CommandLine|contains: 'sc query'
    condition: sc_query
falsepositives:
    - unknown
level: low
tags:
    - attack.discovery
    - attack.t1007

```
