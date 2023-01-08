---
title: "Winlogon Helper DLL"
aliases:
  - "/rule/851c506b-6b7c-4ce2-8802-c703009d03c0"
ruleid: 851c506b-6b7c-4ce2-8802-c703009d03c0

tags:
  - attack.persistence
  - attack.t1547.004



status: experimental





date: Thu, 24 Oct 2019 16:33:29 +0300


---

Winlogon.exe is a Windows component responsible for actions at logon/logoff as well as the secure attention sequence (SAS) triggered by Ctrl-Alt-Delete. Registry entries in HKLM\Software[Wow6432Node]Microsoft\Windows NT\CurrentVersion\Winlogon\ and HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ are used to manage additional helper programs and functionalities that support Winlogon. Malicious modifications to these Registry keys may cause Winlogon to load and execute malicious DLLs and/or executables.

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1547.004/T1547.004.md


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/powershell/powershell_script/posh_ps_winlogon_helper_dll.yml))
```yaml
title: Winlogon Helper DLL
id: 851c506b-6b7c-4ce2-8802-c703009d03c0
status: experimental
description: Winlogon.exe is a Windows component responsible for actions at logon/logoff as well as the secure attention sequence (SAS) triggered by Ctrl-Alt-Delete. Registry entries in HKLM\Software[Wow6432Node]Microsoft\Windows NT\CurrentVersion\Winlogon\ and HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ are used to manage additional helper programs and functionalities that support Winlogon. Malicious modifications to these Registry keys may cause Winlogon to load and execute malicious DLLs and/or executables.
author: Timur Zinniatullin, oscd.community
date: 2019/10/21
modified: 2021/10/16
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1547.004/T1547.004.md
logsource:
    product: windows
    category: ps_script
    definition: Script block logging must be enabled
detection:
    selection:
        ScriptBlockText|contains: 'CurrentVersion\Winlogon'
    selection2:
        ScriptBlockText|contains:
            - 'Set-ItemProperty'
            - 'New-Item'
    condition: selection and selection2
falsepositives:
    - Unknown
level: medium
tags:
    - attack.persistence
    - attack.t1547.004
```
