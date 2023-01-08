---
title: "Suspicious Execution of Adidnsdump"
aliases:
  - "/rule/26d3f0a2-f514-4a3f-a8a7-e7e48a8d9160"
ruleid: 26d3f0a2-f514-4a3f-a8a7-e7e48a8d9160

tags:
  - attack.discovery
  - attack.t1018



status: experimental





date: Sat, 1 Jan 2022 08:42:40 +0100


---

This tool enables enumeration and exporting of all DNS records in the zone for recon purposes of internal networks Python 3 and python.exe must be installed,
Usee to Query/modify DNS records for Active Directory integrated DNS via LDAP


<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1018/T1018.md#atomic-test-9---remote-system-discovery---adidnsdump


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_adidnsdump.yml))
```yaml
title: Suspicious Execution of Adidnsdump 
id: 26d3f0a2-f514-4a3f-a8a7-e7e48a8d9160
status: experimental
description: |
  This tool enables enumeration and exporting of all DNS records in the zone for recon purposes of internal networks Python 3 and python.exe must be installed,
  Usee to Query/modify DNS records for Active Directory integrated DNS via LDAP
author: frack113
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1018/T1018.md#atomic-test-9---remote-system-discovery---adidnsdump
date: 2022/01/01
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: \python.exe
        CommandLine|contains: adidnsdump
    condition: selection
falsepositives:
    - Unknown
level: low
tags:
    - attack.discovery
    - attack.t1018

```
