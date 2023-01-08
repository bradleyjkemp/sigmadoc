---
title: "PowerShell Scripts Installed as Services"
aliases:
  - "/rule/a2e5019d-a658-4c6a-92bf-7197b54e2cae"
ruleid: a2e5019d-a658-4c6a-92bf-7197b54e2cae

tags:
  - attack.execution
  - attack.t1569.002



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects powershell script installed as a Service

<!--more-->


## Known false-positives

* Unknown



## References

* https://speakerdeck.com/heirhabarov/hunting-for-powershell-abuse


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/system/win_powershell_script_installed_as_service.yml))
```yaml
title: PowerShell Scripts Installed as Services
id: a2e5019d-a658-4c6a-92bf-7197b54e2cae
description: Detects powershell script installed as a Service
status: experimental
author: oscd.community, Natalia Shornikova
date: 2020/10/06
modified: 2021/11/30
references:
    - https://speakerdeck.com/heirhabarov/hunting-for-powershell-abuse
tags:
    - attack.execution
    - attack.t1569.002
logsource:
    product: windows
    service: system
detection:
    service_creation:
        Provider_Name: 'Service Control Manager'
        EventID: 7045
        ImagePath|contains: 
          - 'powershell'
          - 'pwsh'
    condition: service_creation
falsepositives:
    - Unknown
level: high

```
