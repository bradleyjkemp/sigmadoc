---
title: "Harvesting of Wifi Credentials Using netsh.exe"
aliases:
  - "/rule/42b1a5b8-353f-4f10-b256-39de4467faff"
ruleid: 42b1a5b8-353f-4f10-b256-39de4467faff

tags:
  - attack.discovery
  - attack.credential_access
  - attack.t1040



status: test





date: Mon, 20 Apr 2020 16:14:44 +0200


---

Detect the harvesting of wifi credentials using netsh.exe

<!--more-->


## Known false-positives

* Legitimate administrator or user uses netsh.exe wlan functionality for legitimate reason



## References

* https://blog.malwarebytes.com/threat-analysis/2020/04/new-agenttesla-variant-steals-wifi-credentials/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_netsh_wifi_credential_harvesting.yml))
```yaml
title: Harvesting of Wifi Credentials Using netsh.exe
id: 42b1a5b8-353f-4f10-b256-39de4467faff
status: test
description: Detect the harvesting of wifi credentials using netsh.exe
author: Andreas Hunkeler (@Karneades), oscd.community
references:
  - https://blog.malwarebytes.com/threat-analysis/2020/04/new-agenttesla-variant-steals-wifi-credentials/
date: 2020/04/20
modified: 2022/01/07
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\netsh.exe'
    CommandLine|contains|all:
      - 'wlan'
      - ' s'
      - ' p'
      - ' k'
      - '=clear'
  condition: selection
falsepositives:
  - Legitimate administrator or user uses netsh.exe wlan functionality for legitimate reason
level: medium
tags:
  - attack.discovery
  - attack.credential_access
  - attack.t1040

```
