---
title: "Suspicious ADSI-Cache Usage By Unknown Tool"
aliases:
  - "/rule/75bf09fa-1dd7-4d18-9af9-dd9e492562eb"
ruleid: 75bf09fa-1dd7-4d18-9af9-dd9e492562eb

tags:
  - attack.t1001.003
  - attack.command_and_control



status: test





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


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/file_event/file_event_win_susp_adsi_cache_usage.yml))
```yaml
title: Suspicious ADSI-Cache Usage By Unknown Tool
id: 75bf09fa-1dd7-4d18-9af9-dd9e492562eb
status: test
description: Detects the usage of ADSI (LDAP) operations by tools. This may also detect tools like LDAPFragger.
author: xknow @xknow_infosec
references:
  - https://medium.com/@ivecodoe/detecting-ldapfragger-a-newly-released-cobalt-strike-beacon-using-ldap-for-c2-communication-c274a7f00961
  - https://blog.fox-it.com/2020/03/19/ldapfragger-command-and-control-over-ldap-attributes/
  - https://github.com/fox-it/LDAPFragger
date: 2019/03/24
modified: 2022/02/21
logsource:
  product: windows
  category: file_event
detection:
  selection:
    TargetFilename|contains: '\Local\Microsoft\Windows\SchCache\'
    TargetFilename|endswith: '.sch'
  filter:
    Image:
      - 'C:\windows\system32\svchost.exe'
      - 'C:\windows\system32\dllhost.exe'
      - 'C:\windows\system32\mmc.exe'
      - 'C:\windows\system32\WindowsPowerShell\v1.0\powershell.exe'
      - 'C:\Windows\CCM\CcmExec.exe'
      - 'C:\Program Files\Cylance\Desktop\CylanceSvc.exe'
      - 'C:\Windows\System32\wbem\WmiPrvSE.exe'
  condition: selection and not filter
falsepositives:
  - Other legimate tools, which do ADSI (LDAP) operations, e.g. any remoting activity by MMC, Powershell, Windows etc.
level: high
tags:
  - attack.t1001.003
  - attack.command_and_control

```
