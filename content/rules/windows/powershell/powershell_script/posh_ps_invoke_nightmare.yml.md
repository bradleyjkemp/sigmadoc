---
title: "PrintNightmare Powershell Exploitation"
aliases:
  - "/rule/6d3f1399-a81c-4409-aff3-1ecfe9330baf"
ruleid: 6d3f1399-a81c-4409-aff3-1ecfe9330baf

tags:
  - attack.privilege_escalation
  - attack.t1548



status: test





date: Mon, 16 Aug 2021 09:10:05 +0200


---

Detects Commandlet name for PrintNightmare exploitation.

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/calebstewart/CVE-2021-1675


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/powershell/powershell_script/posh_ps_invoke_nightmare.yml))
```yaml
title: PrintNightmare Powershell Exploitation
id: 6d3f1399-a81c-4409-aff3-1ecfe9330baf
status: test
description: Detects Commandlet name for PrintNightmare exploitation.
date: 2021/08/09
modified: 2021/10/16
references:
    - https://github.com/calebstewart/CVE-2021-1675
author: Max Altgelt, Tobias Michalski
logsource:
    product: windows
    category: ps_script
    definition: Script Block Logging must be enable
detection:
  selection:
      ScriptBlockText|contains: Invoke-Nightmare
  condition: selection
falsepositives:
    - Unknown
level: high
tags:
    - attack.privilege_escalation
    - attack.t1548

```
