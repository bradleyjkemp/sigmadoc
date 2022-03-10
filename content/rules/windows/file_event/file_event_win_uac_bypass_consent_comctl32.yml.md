---
title: "UAC Bypass Using Consent and Comctl32 - File"
aliases:
  - "/rule/62ed5b55-f991-406a-85d9-e8e8fdf18789"


tags:
  - attack.defense_evasion
  - attack.privilege_escalation
  - attack.t1548.002



status: experimental





date: Tue, 31 Aug 2021 12:45:07 +0200


---

Detects the pattern of UAC Bypass using consent.exe and comctl32.dll (UACMe 22)

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/hfiref0x/UACME


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/file_event/file_event_win_uac_bypass_consent_comctl32.yml))
```yaml
title: UAC Bypass Using Consent and Comctl32 - File
id: 62ed5b55-f991-406a-85d9-e8e8fdf18789
description: Detects the pattern of UAC Bypass using consent.exe and comctl32.dll (UACMe 22)
author: Christian Burkard
date: 2021/08/23
status: experimental
references:
    - https://github.com/hfiref0x/UACME
tags:
    - attack.defense_evasion
    - attack.privilege_escalation
    - attack.t1548.002
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|startswith: 'C:\Windows\System32\consent.exe.@'
        TargetFilename|endswith: '\comctl32.dll'
    condition: selection
falsepositives:
    - Unknown
level: high

```
