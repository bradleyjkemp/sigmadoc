---
title: "Winlogon Helper DLL"
aliases:
  - "/rule/851c506b-6b7c-4ce2-8802-c703009d03c0"

tags:
  - attack.persistence
  - attack.t1547.004
  - attack.t1004



date: Thu, 24 Oct 2019 16:33:29 +0300


---

Winlogon.exe is a Windows component responsible for actions at logon/logoff as well as the secure attention sequence (SAS) triggered by Ctrl-Alt-Delete. Registry entries in HKLM\Software[Wow6432Node]Microsoft\Windows NT\CurrentVersion\Winlogon\ and HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ are used to manage additional helper programs and functionalities that support Winlogon. Malicious modifications to these Registry keys may cause Winlogon to load and execute malicious DLLs and/or executables.

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1004/T1004.yaml


## Raw rule
```yaml
title: Winlogon Helper DLL
id: 851c506b-6b7c-4ce2-8802-c703009d03c0
status: experimental
description: Winlogon.exe is a Windows component responsible for actions at logon/logoff as well as the secure attention sequence (SAS) triggered by Ctrl-Alt-Delete. Registry entries in HKLM\Software[Wow6432Node]Microsoft\Windows NT\CurrentVersion\Winlogon\ and HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ are used to manage additional helper programs and functionalities that support Winlogon. Malicious modifications to these Registry keys may cause Winlogon to load and execute malicious DLLs and/or executables.
author: Timur Zinniatullin, oscd.community
date: 2019/10/21
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1004/T1004.yaml
logsource:
    product: windows
    service: powershell
    definition: 'Script block logging must be enabled'
detection:
    selection:
        EventID: 4104
    keyword1:
        - '*Set-ItemProperty*'
        - '*New-Item*'
    keyword2:
        - '*CurrentVersion\Winlogon*'
    condition: selection and ( keyword1 and keyword2 )
falsepositives:
    - Unknown
level: medium
tags:
    - attack.persistence
    - attack.t1547.004
    - attack.t1004  # an old one

```