---
title: "Service Registry Permissions Weakness Check"
aliases:
  - "/rule/95afc12e-3cbb-40c3-9340-84a032e596a3"


tags:
  - attack.persistence
  - attack.t1574.011



status: experimental





date: Thu, 30 Dec 2021 11:58:10 +0100


---

Adversaries may execute their own malicious payloads by hijacking the Registry entries used by services.
Adversaries may use flaws in the permissions for registry to redirect from the originally specified executable to one that they control, in order to launch their own code at Service start.
Windows stores local service configuration information in the Registry under HKLM\SYSTEM\CurrentControlSet\Services


<!--more-->


## Known false-positives

* legitimate administrative script



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1574.011/T1574.011.md#atomic-test-1---service-registry-permissions-weakness
* https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.security/get-acl?view=powershell-7.2


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/powershell/powershell_script/posh_ps_get_acl_service.yml))
```yaml
title: Service Registry Permissions Weakness Check 
id: 95afc12e-3cbb-40c3-9340-84a032e596a3
status: experimental
description: |
  Adversaries may execute their own malicious payloads by hijacking the Registry entries used by services.
  Adversaries may use flaws in the permissions for registry to redirect from the originally specified executable to one that they control, in order to launch their own code at Service start.
  Windows stores local service configuration information in the Registry under HKLM\SYSTEM\CurrentControlSet\Services
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1574.011/T1574.011.md#atomic-test-1---service-registry-permissions-weakness
    - https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.security/get-acl?view=powershell-7.2
author: frack113
date: 2021/12/30
logsource:
    product: windows
    category: ps_script
detection:
    selection:
        ScriptBlockText|contains|all:
            - 'get-acl'
            - 'REGISTRY::HKLM\SYSTEM\CurrentControlSet\Services\'
    condition: selection
falsepositives:
  - legitimate administrative script
level: medium
tags:
  - attack.persistence
  - attack.t1574.011

```
