---
title: "Dnscat Execution"
aliases:
  - "/rule/a6d67db4-6220-436d-8afc-f3842fe05d43"


tags:
  - attack.exfiltration
  - attack.t1048
  - attack.execution
  - attack.t1059.001



status: experimental





date: Fri, 25 Oct 2019 04:30:55 +0200


---

Dnscat exfiltration tool execution

<!--more-->


## Known false-positives

* Legitimate usage of PowerShell Dnscat2 — DNS Exfiltration tool (unlikely)




## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/powershell/powershell_script/posh_ps_dnscat_execution.yml))
```yaml
title: Dnscat Execution
id: a6d67db4-6220-436d-8afc-f3842fe05d43
description: Dnscat exfiltration tool execution
status: experimental
author: Daniil Yugoslavskiy, oscd.community
date: 2019/10/24
modified: 2021/10/16
tags:
    - attack.exfiltration
    - attack.t1048
    - attack.execution
    - attack.t1059.001
logsource:
    product: windows
    category: ps_script
    definition: Script block logging must be enabled
detection:
    selection:
        ScriptBlockText|contains: 'Start-Dnscat2'
    condition: selection
falsepositives:
    - Legitimate usage of PowerShell Dnscat2 — DNS Exfiltration tool (unlikely)
level: critical

```
