---
title: "Suspicious ADSI-Cache Usage By Unknown Tool"
aliases:
  - "/rule/75bf09fa-1dd7-4d18-9af9-dd9e492562eb"

tags:
  - attack.t1071
  - attack.t1001.003
  - attack.command_and_control



date: Thu, 26 Mar 2020 15:13:36 +0100


---

Detects the usage of ADSI (LDAP) operations by tools. This may also detect tools like LDAPFragger.

<!--more-->


## Known false-positives

* Other legimate tools, which do ADSI (LDAP) operations, e.g. any remoting activity by MMC, Powershell, Windows etc.



## References

* https://medium.com/@ivecodoe/detecting-ldapfragger-a-newly-released-cobalt-strike-beacon-using-ldap-for-c2-communication-c274a7f00961
* https://blog.fox-it.com/2020/03/19/ldapfragger-command-and-control-over-ldap-attributes/
* https://github.com/fox-it/LDAPFragger


## Raw rule
```yaml
title: Suspicious ADSI-Cache Usage By Unknown Tool
id: 75bf09fa-1dd7-4d18-9af9-dd9e492562eb
description: Detects the usage of ADSI (LDAP) operations by tools. This may also detect tools like LDAPFragger.
status: experimental
date: 2019/03/24
modified: 2020/08/23
author: xknow @xknow_infosec
references:
    - https://medium.com/@ivecodoe/detecting-ldapfragger-a-newly-released-cobalt-strike-beacon-using-ldap-for-c2-communication-c274a7f00961
    - https://blog.fox-it.com/2020/03/19/ldapfragger-command-and-control-over-ldap-attributes/
    - https://github.com/fox-it/LDAPFragger
tags:
    - attack.t1071          # an old one
    - attack.t1001.003
    - attack.command_and_control
logsource:
    product: windows
    category: file_event
detection:
    selection_1:
        TargetFilename: '*\Local\Microsoft\Windows\SchCache\\*.sch'
    selection_2:
        Image:
            - 'C:\windows\system32\svchost.exe'
            - 'C:\windows\system32\dllhost.exe'
            - 'C:\windows\system32\mmc.exe'
            - 'C:\windows\system32\WindowsPowerShell\v1.0\powershell.exe'
            - 'C:\Windows\CCM\CcmExec.exe'
    condition: selection_1 and not selection_2
falsepositives:
    - Other legimate tools, which do ADSI (LDAP) operations, e.g. any remoting activity by MMC, Powershell, Windows etc.
level: high

```