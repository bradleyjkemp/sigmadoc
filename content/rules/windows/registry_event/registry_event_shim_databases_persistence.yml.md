---
title: "Registry Key Creation or Modification for Shim DataBase"
aliases:
  - "/rule/dfb5b4e8-91d0-4291-b40a-e3b0d3942c45"


tags:
  - attack.persistence
  - attack.t1546.011



status: experimental





date: Thu, 30 Dec 2021 11:58:10 +0100


---

Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by application shims.
The Microsoft Windows Application Compatibility Infrastructure/Framework (Application Shim) was created to allow for backward compatibility of software as the operating system codebase changes over time


<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1546.011/T1546.011.md#atomic-test-3---registry-key-creation-andor-modification-events-for-sdb
* https://www.fireeye.com/blog/threat-research/2017/05/fin7-shim-databases-persistence.html


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/registry_event/registry_event_shim_databases_persistence.yml))
```yaml
title: Registry Key Creation or Modification for Shim DataBase
id: dfb5b4e8-91d0-4291-b40a-e3b0d3942c45
description: |
  Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by application shims.
  The Microsoft Windows Application Compatibility Infrastructure/Framework (Application Shim) was created to allow for backward compatibility of software as the operating system codebase changes over time
author: frack113
date: 2021/12/30
status: experimental
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1546.011/T1546.011.md#atomic-test-3---registry-key-creation-andor-modification-events-for-sdb
    - https://www.fireeye.com/blog/threat-research/2017/05/fin7-shim-databases-persistence.html
logsource:
    category: registry_event
    product: windows
detection:
    selection:
        TargetObject|startswith:
            - 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB\'
            - 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom\'
        EventType: SetValue
    filter:
        Details: ''
    condition: selection and not filter
falsepositives:
    - Unknown
level: medium
tags:
  - attack.persistence
  - attack.t1546.011
```
