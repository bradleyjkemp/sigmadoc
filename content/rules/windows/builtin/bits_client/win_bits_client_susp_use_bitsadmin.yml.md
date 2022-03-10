---
title: "Suspicious Task Added by Bitsadmin"
aliases:
  - "/rule/1ff315dc-2a3a-4b71-8dde-873818d25d39"


tags:
  - attack.defense_evasion
  - attack.persistence
  - attack.t1197



status: experimental





date: Thu, 3 Mar 2022 06:27:00 +0100


---

Adversaries may abuse BITS jobs to persistently execute or clean up after malicious payloads.
Windows Background Intelligent Transfer Service (BITS) is a low-bandwidth, asynchronous file transfer mechanism exposed through [Component Object Model](https://attack.mitre.org/techniques/T1559/001)


<!--more-->


## Known false-positives

* Administrator PowerShell scripts



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1197/T1197.md


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/bits_client/win_bits_client_susp_use_bitsadmin.yml))
```yaml
title: Suspicious Task Added by Bitsadmin
id: 1ff315dc-2a3a-4b71-8dde-873818d25d39
status: experimental
description: |
  Adversaries may abuse BITS jobs to persistently execute or clean up after malicious payloads.
  Windows Background Intelligent Transfer Service (BITS) is a low-bandwidth, asynchronous file transfer mechanism exposed through [Component Object Model](https://attack.mitre.org/techniques/T1559/001)
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1197/T1197.md
author: frack113
date: 2022/03/01
logsource:
    product: windows
    service: bits-client
detection:
    selection:
        EventID: 3
        processPath|endswith: '\bitsadmin.exe'
    condition: selection
falsepositives:
    - Administrator PowerShell scripts 
level: low
tags:
    - attack.defense_evasion
    - attack.persistence
    - attack.t1197
```
