---
title: "Baby Shark Activity"
aliases:
  - "/rule/2b30fa36-3a18-402f-a22d-bf4ce2189f35"

tags:
  - attack.execution
  - attack.t1059
  - attack.t1086
  - attack.t1059.003
  - attack.t1059.001
  - attack.discovery
  - attack.t1012
  - attack.defense_evasion
  - attack.t1170
  - attack.t1218
  - attack.t1218.005



date: Sun, 24 Feb 2019 14:04:37 +0100


---

Detects activity that could be related to Baby Shark malware

<!--more-->


## Known false-positives

* unknown



## References

* https://unit42.paloaltonetworks.com/new-babyshark-malware-targets-u-s-national-security-think-tanks/


## Raw rule
```yaml
title: Baby Shark Activity
id: 2b30fa36-3a18-402f-a22d-bf4ce2189f35
status: experimental
description: Detects activity that could be related to Baby Shark malware
references:
    - https://unit42.paloaltonetworks.com/new-babyshark-malware-targets-u-s-national-security-think-tanks/
tags:
    - attack.execution
    - attack.t1059 # an old one
    - attack.t1086 # an old one
    - attack.t1059.003
    - attack.t1059.001
    - attack.discovery
    - attack.t1012
    - attack.defense_evasion
    - attack.t1170 # an old one
    - attack.t1218 # an old one
    - attack.t1218.005
logsource:
    category: process_creation
    product: windows
author: Florian Roth
date: 2019/02/24
modified: 2020/08/26
detection:
    selection:
        CommandLine:
            - reg query "HKEY_CURRENT_USER\Software\Microsoft\Terminal Server Client\Default"
            - powershell.exe mshta.exe http*
            - cmd.exe /c taskkill /im cmd.exe
    condition: selection
falsepositives:
    - unknown
level: high

```