---
title: "MSExchange Transport Agent Installation"
aliases:
  - "/rule/83809e84-4475-4b69-bc3e-4aad8568612f"
ruleid: 83809e84-4475-4b69-bc3e-4aad8568612f

tags:
  - attack.persistence
  - attack.t1505.002



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects the Installation of a Exchange Transport Agent

<!--more-->


## Known false-positives

* legitimate installations of exchange TransportAgents. AssemblyPath is a good indicator for this.



## References

* https://twitter.com/blueteamsec1/status/1401290874202382336?s=20


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_win_exchange_transportagent.yml))
```yaml
title: MSExchange Transport Agent Installation
id: 83809e84-4475-4b69-bc3e-4aad8568612f
status: experimental
description: Detects the Installation of a Exchange Transport Agent
references:
    - https://twitter.com/blueteamsec1/status/1401290874202382336?s=20
tags:
    - attack.persistence  
    - attack.t1505.002    
author: Tobias Michalski  
date: 2021/06/08
modified: 2021/09/19
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|contains: 'Install-TransportAgent'
    condition: selection
falsepositives:
    - legitimate installations of exchange TransportAgents. AssemblyPath is a good indicator for this.
level: medium
fields:
    - AssemblyPath
```
