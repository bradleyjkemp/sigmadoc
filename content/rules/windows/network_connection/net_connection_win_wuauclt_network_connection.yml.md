---
title: "Wuauclt Network Connection"
aliases:
  - "/rule/c649a6c7-cd8c-4a78-9c04-000fc76df954"


tags:
  - attack.defense_evasion
  - attack.t1218



status: test





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects the use of the Windows Update Client binary (wuauclt.exe) to proxy execute code and making a network connections. One could easily make the DLL spawn a new process and inject to it to proxy the network connection and bypass this rule.

<!--more-->


## Known false-positives

* Legitimate use of wuauclt.exe over the network.



## References

* https://dtm.uk/wuauclt/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/network_connection/net_connection_win_wuauclt_network_connection.yml))
```yaml
title: Wuauclt Network Connection
id: c649a6c7-cd8c-4a78-9c04-000fc76df954
status: test
description: Detects the use of the Windows Update Client binary (wuauclt.exe) to proxy execute code and making a network connections. One could easily make the DLL spawn a new process and inject to it to proxy the network connection and bypass this rule.
author: Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)
references:
  - https://dtm.uk/wuauclt/
date: 2020/10/12
modified: 2021/11/27
logsource:
  category: network_connection
  product: windows
detection:
  selection:
    Image|contains: wuauclt
  condition: selection
falsepositives:
  - Legitimate use of wuauclt.exe over the network.
level: medium
tags:
  - attack.defense_evasion
  - attack.t1218

```
