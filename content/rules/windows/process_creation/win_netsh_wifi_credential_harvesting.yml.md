---
title: "Harvesting of Wifi Credentials Using netsh.exe"
aliases:
  - "/rule/42b1a5b8-353f-4f10-b256-39de4467faff"

tags:
  - attack.discovery
  - attack.credential_access
  - attack.t1040



status: experimental



level: medium



date: Mon, 20 Apr 2020 16:14:44 +0200


---

Detect the harvesting of wifi credentials using netsh.exe

<!--more-->


## Known false-positives

* Legitimate administrator or user uses netsh.exe wlan functionality for legitimate reason



## References

* https://blog.malwarebytes.com/threat-analysis/2020/04/new-agenttesla-variant-steals-wifi-credentials/


## Raw rule
```yaml
title: Harvesting of Wifi Credentials Using netsh.exe
id: 42b1a5b8-353f-4f10-b256-39de4467faff
status: experimental
description: Detect the harvesting of wifi credentials using netsh.exe
references:
    - https://blog.malwarebytes.com/threat-analysis/2020/04/new-agenttesla-variant-steals-wifi-credentials/
author: Andreas Hunkeler (@Karneades)
date: 2020/04/20
modified: 2020/09/01
tags:
    - attack.discovery
    - attack.credential_access
    - attack.t1040
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine:
            - 'netsh wlan s* p* k*=clear'
    condition: selection
falsepositives:
    - Legitimate administrator or user uses netsh.exe wlan functionality for legitimate reason
level: medium

```
