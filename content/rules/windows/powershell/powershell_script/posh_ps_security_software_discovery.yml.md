---
title: "Security Software Discovery by Powershell"
aliases:
  - "/rule/904e8e61-8edf-4350-b59c-b905fc8e810c"


tags:
  - attack.discovery
  - attack.t1518.001



status: experimental





date: Thu, 16 Dec 2021 10:32:45 +0100


---

Adversaries may attempt to get a listing of security software, configurations, defensive tools, and sensors that are installed on a system or in a cloud environment.
This may include things such as firewall rules and anti-viru


<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1518.001/T1518.001.md


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/powershell/powershell_script/posh_ps_security_software_discovery.yml))
```yaml
title: Security Software Discovery by Powershell
id: 904e8e61-8edf-4350-b59c-b905fc8e810c
status: experimental
author: frack113
date: 2021/12/16
description: |
    Adversaries may attempt to get a listing of security software, configurations, defensive tools, and sensors that are installed on a system or in a cloud environment.
    This may include things such as firewall rules and anti-viru
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1518.001/T1518.001.md
logsource:
    product: windows
    category: ps_script
    definition: Script block logging must be enabled
detection:
    selection_1:
        ScriptBlockText|contains|all:
            - 'get-process'
            - '.Description'
            - '-like'
    selection_2:
        ScriptBlockText|contains:
            - '"*virus*"'
            - '"*carbonblack*"'
            - '"*defender*"'
            - '"*cylance*"'
    condition: all of selection_*
falsepositives:
    - Unknown
level: low
tags:
    - attack.discovery
    - attack.t1518.001


```
