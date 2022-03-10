---
title: "Suspicious WMIC ActiveScriptEventConsumer Creation"
aliases:
  - "/rule/ebef4391-1a81-4761-a40a-1db446c0e625"


tags:
  - attack.persistence
  - attack.t1546.003



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects WMIC executions in which a event consumer gets created in order to establish persistence

<!--more-->


## Known false-positives

* Legitimate software creating script event consumers



## References

* https://twitter.com/johnlatwc/status/1408062131321270282?s=12
* https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/wp-windows-management-instrumentation.pdf


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_wmic_eventconsumer_create.yml))
```yaml
title: Suspicious WMIC ActiveScriptEventConsumer Creation
id: ebef4391-1a81-4761-a40a-1db446c0e625
status: experimental
description: Detects WMIC executions in which a event consumer gets created in order to establish persistence
references:
    - https://twitter.com/johnlatwc/status/1408062131321270282?s=12
    - https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/wp-windows-management-instrumentation.pdf
author: Florian Roth
date: 2021/06/25
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - 'ActiveScriptEventConsumer'
            - ' CREATE '
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
tags:
    - attack.persistence
    - attack.t1546.003
falsepositives:
    - Legitimate software creating script event consumers
level: high

```
