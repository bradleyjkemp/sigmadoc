---
title: "Suspicious Program Location with Network Connections"
aliases:
  - "/rule/7b434893-c57d-4f41-908d-6a17bf1ae98f"



date: Sun, 19 Mar 2017 15:22:27 +0100


---

Detects programs with network connections running in suspicious files system locations

<!--more-->


## Known false-positives

* unknown



## References

* https://docs.google.com/spreadsheets/d/17pSTDNpa0sf6pHeRhusvWG6rThciE8CsXTSlDUAZDyo


## Raw rule
```yaml
title: Suspicious Program Location with Network Connections
id: 7b434893-c57d-4f41-908d-6a17bf1ae98f
status: experimental
description: Detects programs with network connections running in suspicious files system locations
references:
    - https://docs.google.com/spreadsheets/d/17pSTDNpa0sf6pHeRhusvWG6rThciE8CsXTSlDUAZDyo
author: Florian Roth
date: 2017/03/19
logsource:
    category: network_connection
    product: windows
    definition: 'Use the following config to generate the necessary Event ID 3 Network Connection events'
detection:
    selection:
        Image: 
            # - '*\ProgramData\\*'  # too many false positives, e.g. with Webex for Windows
            - '*\$Recycle.bin'
            - '*\Users\All Users\\*'
            - '*\Users\Default\\*'
            - '*\Users\Public\\*'
            - '*\Users\Contacts\\*'
            - '*\Users\Searches\\*' 
            - 'C:\Perflogs\\*'
            - '*\config\systemprofile\\*'
            - '*\Windows\Fonts\\*'
            - '*\Windows\IME\\*'
            - '*\Windows\addins\\*'
    condition: selection
falsepositives:
    - unknown
level: high

```
