---
title: "Silence.EDA Detection"
aliases:
  - "/rule/3ceb2083-a27f-449a-be33-14ec1b7cc973"
ruleid: 3ceb2083-a27f-449a-be33-14ec1b7cc973

tags:
  - attack.execution
  - attack.t1059.001
  - attack.command_and_control
  - attack.t1071.004
  - attack.t1572
  - attack.impact
  - attack.t1529
  - attack.g0091
  - attack.s0363



status: test





date: Thu, 28 Nov 2019 21:15:55 +0100


---

Detects Silence empireDNSagent

<!--more-->


## Known false-positives

* Unknown




## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/apt/apt_silence_eda.yml))
```yaml
title: Silence.EDA Detection
id: 3ceb2083-a27f-449a-be33-14ec1b7cc973
status: test
description: Detects Silence empireDNSagent
author: Alina Stepchenkova, Group-IB, oscd.community
date: 2019/11/01
modified: 2021/11/27
logsource:
  product: windows
  service: powershell
detection:
  empire:
    ScriptBlockText|contains|all:               # better to randomise the order
      - 'System.Diagnostics.Process'
      - 'Stop-Computer'
      - 'Restart-Computer'
      - 'Exception in execution'
      - '$cmdargs'
      - 'Close-Dnscat2Tunnel'
  dnscat:
    ScriptBlockText|contains|all:               # better to randomise the order
      - 'set type=$LookupType`nserver'
      - '$Command | nslookup 2>&1 | Out-String'
      - 'New-RandomDNSField'
      - '[Convert]::ToString($SYNOptions, 16)'
      - '$Session.Dead = $True'
      - '$Session["Driver"] -eq'
  condition: empire and dnscat
falsepositives:
  - Unknown
level: critical
tags:
  - attack.execution
  - attack.t1059.001
  - attack.command_and_control
  - attack.t1071.004
  - attack.t1572
  - attack.impact
  - attack.t1529
  - attack.g0091
  - attack.s0363

```
