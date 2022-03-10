---
title: "Unauthorized System Time Modification"
aliases:
  - "/rule/faa031b5-21ed-4e02-8881-2591f98d82ed"


tags:
  - attack.defense_evasion
  - attack.t1070.006



status: test





---

Detect scenarios where a potentially unauthorized application or user is modifying the system time.

<!--more-->


## Known false-positives

* HyperV or other virtualization technologies with binary not listed in filter portion of detection



## References

* Private Cuckoo Sandbox (from many years ago, no longer have hash, NDA as well)
* Live environment caused by malware
* https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4616


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/security/win_susp_time_modification.yml))
```yaml
title: Unauthorized System Time Modification
id: faa031b5-21ed-4e02-8881-2591f98d82ed
status: test
description: Detect scenarios where a potentially unauthorized application or user is modifying the system time.
author: '@neu5ron'
references:
  - Private Cuckoo Sandbox (from many years ago, no longer have hash, NDA as well)
  - Live environment caused by malware
  - https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4616
date: 2019/02/05
modified: 2021/11/27
logsource:
  product: windows
  service: security
  definition: 'Requirements: Audit Policy : System > Audit Security State Change, Group Policy : Computer Configuration\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Audit Policies\System\Audit Security State Change'
detection:
  selection:
    EventID: 4616
  filter1:
    ProcessName: 
        - 'C:\Program Files\VMware\VMware Tools\vmtoolsd.exe'
        - 'C:\Windows\System32\VBoxService.exe'
  filter2:
    ProcessName: 'C:\Windows\System32\svchost.exe'
    SubjectUserSid: 'S-1-5-19'
  condition: selection and not 1 of filter*
falsepositives:
  - HyperV or other virtualization technologies with binary not listed in filter portion of detection
level: medium
tags:
  - attack.defense_evasion
  - attack.t1070.006

```
