---
title: "PowerShell ICMP Exfiltration"
aliases:
  - "/rule/4c4af3cd-2115-479c-8193-6b8bfce9001c"
ruleid: 4c4af3cd-2115-479c-8193-6b8bfce9001c

tags:
  - attack.exfiltration
  - attack.t1048.003



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects Exfiltration Over Alternative Protocol - ICMP. Adversaries may steal data by exfiltrating it over an un-encrypted network protocol other than that of the existing command and control channel.

<!--more-->


## Known false-positives

* Legitimate usage of System.Net.NetworkInformation.Ping class



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1048.003/T1048.003.md#atomic-test-2---exfiltration-over-alternative-protocol---icmp


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/powershell/powershell_script/posh_ps_icmp_exfiltration.yml))
```yaml
title: PowerShell ICMP Exfiltration
id: 4c4af3cd-2115-479c-8193-6b8bfce9001c
status: experimental
description: Detects Exfiltration Over Alternative Protocol - ICMP. Adversaries may steal data by exfiltrating it over an un-encrypted network protocol other than that of the existing command and control channel.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1048.003/T1048.003.md#atomic-test-2---exfiltration-over-alternative-protocol---icmp
author: 'Bartlomiej Czyz @bczyz1, oscd.community'
date: 2020/10/10
modified: 2021/10/16
tags:
    - attack.exfiltration
    - attack.t1048.003
logsource:
    product: windows
    category: ps_script
    definition: Script block logging must be enabled
detection:
    selection:
        ScriptBlockText|contains|all:
          - 'New-Object'
          - 'System.Net.NetworkInformation.Ping'
          - '.Send('
    condition: selection
falsepositives:
    - Legitimate usage of System.Net.NetworkInformation.Ping class
level: medium

```