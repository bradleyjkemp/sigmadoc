---
title: "Suspicious Download File Extension with Bits"
aliases:
  - "/rule/b85e5894-9b19-4d86-8c87-a2f3b81f0521"


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


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/bits_client/win_bits_client_susp_local_file.yml))
```yaml
title: Suspicious Download File Extension with Bits
id: b85e5894-9b19-4d86-8c87-a2f3b81f0521
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
        EventID: 16403
        LocalName|endswith: 
            - '.ps1'
            - '.exe'
    condition: selection
falsepositives:
    - Administrator PowerShell scripts 
level: low
tags:
    - attack.defense_evasion
    - attack.persistence
    - attack.t1197
```
