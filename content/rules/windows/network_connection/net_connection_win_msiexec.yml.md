---
title: "Msiexec Initiated Connection"
aliases:
  - "/rule/8e5e38e4-5350-4c0b-895a-e872ce0dd54f"


tags:
  - attack.defense_evasion
  - attack.t1218.007



status: experimental





date: Sun, 16 Jan 2022 14:47:56 +0100


---

Adversaries may abuse msiexec.exe to proxy execution of malicious payloads.
Msiexec.exe is the command-line utility for the Windows Installer and is thus commonly associated with executing installation packages (.msi)


<!--more-->


## Known false-positives

* Legitimate msiexec over networks



## References

* https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/msiexec
* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.007/T1218.007.md


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/network_connection/net_connection_win_msiexec.yml))
```yaml
title: Msiexec Initiated Connection
id: 8e5e38e4-5350-4c0b-895a-e872ce0dd54f
status: experimental
description: |
  Adversaries may abuse msiexec.exe to proxy execution of malicious payloads.
  Msiexec.exe is the command-line utility for the Windows Installer and is thus commonly associated with executing installation packages (.msi)
author: frack113
references:
    - https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/msiexec
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.007/T1218.007.md
date: 2022/01/16
logsource:
  category: network_connection
  product: windows
detection:
  selection:
    Initiated: 'true'
    Image|endswith: '\msiexec.exe' 
  condition: selection
falsepositives:
  - Legitimate msiexec over networks
level: medium
tags:
    - attack.defense_evasion
    - attack.t1218.007
```
