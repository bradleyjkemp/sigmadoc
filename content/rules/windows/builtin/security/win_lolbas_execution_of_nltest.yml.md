---
title: "Correct Execution of Nltest.exe"
aliases:
  - "/rule/eeb66bbb-3dde-4582-815a-584aee9fe6d1"
ruleid: eeb66bbb-3dde-4582-815a-584aee9fe6d1

tags:
  - attack.discovery
  - attack.t1482
  - attack.t1018
  - attack.t1016



status: experimental





date: Wed, 29 Sep 2021 14:33:36 -0700


---

The attacker might use LOLBAS nltest.exe for discovery of domain controllers, domain trusts, parent domain and the current user permissions.

<!--more-->


## Known false-positives

* Red team activity
* rare legitimate use by an administrator



## References

* https://jpcertcc.github.io/ToolAnalysisResultSheet/details/nltest.htm
* https://attack.mitre.org/software/S0359/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/security/win_lolbas_execution_of_nltest.yml))
```yaml
title: Correct Execution of Nltest.exe
id: eeb66bbb-3dde-4582-815a-584aee9fe6d1
status: experimental
author: Arun Chauhan
date: 2021/10/04
description: The attacker might use LOLBAS nltest.exe for discovery of domain controllers, domain trusts, parent domain and the current user permissions.
references:
  - https://jpcertcc.github.io/ToolAnalysisResultSheet/details/nltest.htm
  - https://attack.mitre.org/software/S0359/
tags: 
  - attack.discovery
  - attack.t1482 # enumerate trusted domains by using commands such as nltest /domain_trusts
  - attack.t1018 # enumerate remote domain controllers using options such as /dclist and /dsgetdc
  - attack.t1016 # enumerate the parent domain of a local machine using /parentdomain
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4689
    ProcessName|endswith: nltest.exe
    Status: '0x0'
  condition: selection
fields:
  - 'SubjectUserName'
  - 'SubjectDomainName'
falsepositives:
  - Red team activity
  - rare legitimate use by an administrator
level: high

```
