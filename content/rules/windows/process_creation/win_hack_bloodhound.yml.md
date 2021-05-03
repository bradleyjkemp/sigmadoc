---
title: "Bloodhound and Sharphound Hack Tool"
aliases:
  - "/rule/f376c8a7-a2d0-4ddc-aa0c-16c17236d962"

tags:
  - attack.discovery
  - attack.t1087.001
  - attack.t1087.002
  - attack.t1087
  - attack.t1482
  - attack.t1069.001
  - attack.t1069.002
  - attack.t1069
  - attack.execution
  - attack.t1059.001
  - attack.t1086



date: Fri, 20 Dec 2019 14:59:36 +0100


---

Detects command line parameters used by Bloodhound and Sharphound hack tools

<!--more-->


## Known false-positives

* Other programs that use these command line option and accepts an 'All' parameter



## References

* https://github.com/BloodHoundAD/BloodHound
* https://github.com/BloodHoundAD/SharpHound


## Raw rule
```yaml
title: Bloodhound and Sharphound Hack Tool
id: f376c8a7-a2d0-4ddc-aa0c-16c17236d962
description: Detects command line parameters used by Bloodhound and Sharphound hack tools
author: Florian Roth
references:
    - https://github.com/BloodHoundAD/BloodHound
    - https://github.com/BloodHoundAD/SharpHound
date: 2019/12/20
modified: 2019/12/21
tags:
    - attack.discovery
    - attack.t1087.001
    - attack.t1087.002
    - attack.t1087  # an old one
    - attack.t1482
    - attack.t1069.001
    - attack.t1069.002
    - attack.t1069  # an old one
    - attack.execution
    - attack.t1059.001
    - attack.t1086  # an old one
logsource:
    category: process_creation
    product: windows
detection:
    selection1: 
        Image|contains: 
            - '\Bloodhound.exe'
            - '\SharpHound.exe'
    selection2:
        CommandLine|contains: 
            - ' -CollectionMethod All '
            - '.exe -c All -d '
            - 'Invoke-Bloodhound'
            - 'Get-BloodHoundData'
    selection3:
        CommandLine|contains|all: 
            - ' -JsonFolder '
            - ' -ZipFileName '
    selection4:
        CommandLine|contains|all: 
            - ' DCOnly '
            - ' --NoSaveCache '
    condition: 1 of them
falsepositives:
    - Other programs that use these command line option and accepts an 'All' parameter
level: high


```