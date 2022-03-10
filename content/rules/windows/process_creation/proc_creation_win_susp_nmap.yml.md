---
title: "Suspicious Nmap Execution"
aliases:
  - "/rule/f6ecd1cf-19b8-4488-97f6-00f0924991a3"


tags:
  - attack.discovery
  - attack.t1046



status: experimental





date: Fri, 10 Dec 2021 16:31:16 +0100


---

Adversaries may attempt to get a listing of services running on remote hosts, including those that may be vulnerable to remote software exploitation

<!--more-->


## Known false-positives

* Network administator computeur



## References

* https://nmap.org/
* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1046/T1046.md#atomic-test-3---port-scan-nmap-for-windows


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_nmap.yml))
```yaml
title: Suspicious Nmap Execution
id: f6ecd1cf-19b8-4488-97f6-00f0924991a3
status: experimental
description: Adversaries may attempt to get a listing of services running on remote hosts, including those that may be vulnerable to remote software exploitation
author: frack113
references:
    - https://nmap.org/
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1046/T1046.md#atomic-test-3---port-scan-nmap-for-windows
date: 2021/12/10
logsource:
    category: process_creation
    product: windows
detection:
    nmap:
        OriginalFileName: nmap.exe
    condition: nmap 
falsepositives:
    - Network administator computeur
level: high
tags:
    - attack.discovery
    - attack.t1046
```