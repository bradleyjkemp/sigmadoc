---
title: "Failed MSExchange Transport Agent Installation"
aliases:
  - "/rule/c7d16cae-aaf3-42e5-9c1c-fb8553faa6fa"
ruleid: c7d16cae-aaf3-42e5-9c1c-fb8553faa6fa

tags:
  - attack.persistence
  - attack.t1505.002



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects a failed installation of a Exchange Transport Agent

<!--more-->


## Known false-positives

* legitimate installations of exchange TransportAgents. AssemblyPath is a good indicator for this.



## References

* https://twitter.com/blueteamsec1/status/1401290874202382336?s=20


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/msexchange/win_exchange_transportagent_failed.yml))
```yaml
title: Failed MSExchange Transport Agent Installation
id: c7d16cae-aaf3-42e5-9c1c-fb8553faa6fa
status: experimental
description: Detects a failed installation of a Exchange Transport Agent
references:
    - https://twitter.com/blueteamsec1/status/1401290874202382336?s=20
tags:
    - attack.persistence  
    - attack.t1505.002    
author: Tobias Michalski  
date: 2021/06/08  
logsource:        
    service: msexchange-management
    product: windows
detection:
    selection:
        EventID: 6 
    keywords:
        - 'Install-TransportAgent'
    condition: selection and keywords
fields:
    - AssemblyPath
falsepositives:
    - legitimate installations of exchange TransportAgents. AssemblyPath is a good indicator for this.
level: high

```
