---
title: "Manipulation of User Computer or Group Security Principals Across AD"
aliases:
  - "/rule/b29a93fb-087c-4b5b-a84d-ee3309e69d08"


tags:
  - attack.persistence
  - attack.t1136.002



status: experimental





date: Wed, 29 Dec 2021 17:47:43 +0100


---

Adversaries may create a domain account to maintain access to victim systems.
Domain accounts are those managed by Active Directory Domain Services where access and permissions are configured across systems and services that are part of that domain..


<!--more-->


## Known false-positives

* legitimate administrative script



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1136.002/T1136.002.md#atomic-test-3---create-a-new-domain-account-using-powershell
* https://docs.microsoft.com/en-us/dotnet/api/system.directoryservices.accountmanagement?view=dotnet-plat-ext-6.0


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/powershell/powershell_script/posh_ps_directoryservices_accountmanagement.yml))
```yaml
title: Manipulation of User Computer or Group Security Principals Across AD
id: b29a93fb-087c-4b5b-a84d-ee3309e69d08
status: experimental
description: |
  Adversaries may create a domain account to maintain access to victim systems.
  Domain accounts are those managed by Active Directory Domain Services where access and permissions are configured across systems and services that are part of that domain..
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1136.002/T1136.002.md#atomic-test-3---create-a-new-domain-account-using-powershell
    - https://docs.microsoft.com/en-us/dotnet/api/system.directoryservices.accountmanagement?view=dotnet-plat-ext-6.0
author: frack113
date: 2021/12/28
logsource:
    product: windows
    category: ps_script
detection:
    selection:
        ScriptBlockText|contains: System.DirectoryServices.AccountManagement
    condition: selection
falsepositives:
    - legitimate administrative script
level: medium
tags:
    - attack.persistence
    - attack.t1136.002

```
