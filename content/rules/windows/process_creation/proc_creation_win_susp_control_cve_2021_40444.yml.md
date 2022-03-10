---
title: "CVE-2021-40444 Process Pattern"
aliases:
  - "/rule/894397c6-da03-425c-a589-3d09e7d1f750"


tags:
  - attack.execution
  - attack.t1059



status: test





date: Wed, 8 Sep 2021 16:49:49 +0200


---

Detects a suspicious process pattern found in CVE-2021-40444 exploitation

<!--more-->


## Known false-positives

* Unknown



## References

* https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-40444
* https://twitter.com/neonprimetime/status/1435584010202255375
* https://www.joesandbox.com/analysis/476188/1/iochtml


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_control_cve_2021_40444.yml))
```yaml
title: CVE-2021-40444 Process Pattern
id: 894397c6-da03-425c-a589-3d09e7d1f750
description: Detects a suspicious process pattern found in CVE-2021-40444 exploitation
status: test
references:
    - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-40444
    - https://twitter.com/neonprimetime/status/1435584010202255375
    - https://www.joesandbox.com/analysis/476188/1/iochtml
author: '@neonprimetime, Florian Roth'
date: 2021/09/08
modified: 2022/03/03
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\control.exe'
        ParentImage|endswith:
            - '\winword.exe'
            - '\powerpnt.exe'
            - '\excel.exe'
    filter:
        CommandLine|endswith:
            - '\control.exe input.dll'
            - '\control.exe" input.dll'
    condition: selection and not filter
falsepositives:
    - Unknown
level: critical
tags:
    - attack.execution
    - attack.t1059

```
