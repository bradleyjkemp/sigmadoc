---
title: "Enumerate Credentials from Windows Credential Manager With PowerShell"
aliases:
  - "/rule/603c6630-5225-49c1-8047-26c964553e0e"


tags:
  - attack.credential_access
  - attack.t1555



status: experimental





date: Mon, 20 Dec 2021 10:43:32 +0100


---

Adversaries may search for common password storage locations to obtain user credentials.
Passwords are stored in several places on a system, depending on the operating system or application holding the credentials.


<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1555/T1555.md


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/powershell/powershell_script/posh_ps_enumerate_password_windows_credential_manager.yml))
```yaml
title: Enumerate Credentials from Windows Credential Manager With PowerShell
id: 603c6630-5225-49c1-8047-26c964553e0e
status: experimental
author: frack113
date: 2021/12/20
description: |
  Adversaries may search for common password storage locations to obtain user credentials.
  Passwords are stored in several places on a system, depending on the operating system or application holding the credentials.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1555/T1555.md
logsource:
    product: windows
    category: ps_script
    definition: Script block logging must be enabled
detection:
    selection_cmd:
        ScriptBlockText|contains|all: 
            - vaultcmd
            - '/listcreds:'
    selection_option:
        ScriptBlockText|contains:
            - 'Windows Credentials'
            - 'Web Credentials'
    condition: all of selection_*
falsepositives:
    - Unknown
level: medium
tags:
    - attack.credential_access
    - attack.t1555
```
