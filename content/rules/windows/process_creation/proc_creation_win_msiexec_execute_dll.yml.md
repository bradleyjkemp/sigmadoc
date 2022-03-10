---
title: "Suspicious Msiexec Execute Arbitrary DLL"
aliases:
  - "/rule/6f4191bb-912b-48a8-9ce7-682769541e6d"


tags:
  - attack.defense_evasion
  - attack.t1218.007



status: experimental





date: Sun, 16 Jan 2022 14:47:56 +0100


---

Adversaries may abuse msiexec.exe to proxy execution of malicious payloads.
Msiexec.exe is the command-line utility for the Windows Installer and is thus commonly associated with executing installation packages (.msi)


<!--more-->


## Known false-positives

* Legitimate script



## References

* https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/msiexec
* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.007/T1218.007.md


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_msiexec_execute_dll.yml))
```yaml
title: Suspicious Msiexec Execute Arbitrary DLL
id: 6f4191bb-912b-48a8-9ce7-682769541e6d
status: experimental
description: |
  Adversaries may abuse msiexec.exe to proxy execution of malicious payloads.
  Msiexec.exe is the command-line utility for the Windows Installer and is thus commonly associated with executing installation packages (.msi)
author: frack113
date: 2022/01/16
modified: 2022/02/15
references:
    - https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/msiexec
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.007/T1218.007.md
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\msiexec.exe'
        CommandLine|contains|all:
            - ' /y'
            #- '.dll'
    filter_apple:
        CommandLine|contains:
            - '\MsiExec.exe" /Y "C:\Program Files\Bonjour\mdnsNSP.dll'
            - '\MsiExec.exe" /Y "C:\Program Files (x86)\Bonjour\mdnsNSP.dll'
            - '\MsiExec.exe" /Y "C:\Program Files (x86)\Apple Software Update\ScriptingObjectModel.dll'
            - '\MsiExec.exe" /Y "C:\Program Files (x86)\Apple Software Update\SoftwareUpdateAdmin.dll'
    condition: selection and not 1 of filter_*
falsepositives:
    - Legitimate script
level: medium
tags:
    - attack.defense_evasion
    - attack.t1218.007

```
