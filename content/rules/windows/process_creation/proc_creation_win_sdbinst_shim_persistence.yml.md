---
title: "Possible Shim Database Persistence via sdbinst.exe"
aliases:
  - "/rule/517490a7-115a-48c6-8862-1a481504d5a8"


tags:
  - attack.persistence
  - attack.privilege_escalation
  - attack.t1546.011



status: experimental





date: Wed, 16 Jan 2019 23:36:31 +0100


---

Detects installation of a new shim using sdbinst.exe. A shim can be used to load malicious DLLs into applications.

<!--more-->


## Known false-positives

* Unknown



## References

* https://www.fireeye.com/blog/threat-research/2017/05/fin7-shim-databases-persistence.html


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_sdbinst_shim_persistence.yml))
```yaml
title: Possible Shim Database Persistence via sdbinst.exe
id: 517490a7-115a-48c6-8862-1a481504d5a8
status: experimental
description: Detects installation of a new shim using sdbinst.exe. A shim can be used to load malicious DLLs into applications.
references:
    - https://www.fireeye.com/blog/threat-research/2017/05/fin7-shim-databases-persistence.html
tags:
    - attack.persistence
    - attack.privilege_escalation
    - attack.t1546.011
author: Markus Neis
date: 2019/01/16
modified: 2021/08/14
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\sdbinst.exe'
        CommandLine|contains: '.sdb'
    filter:
        CommandLine|contains:
            - 'iisexpressshim.sdb' # normal behaviour for IIS Express (e.g. https://www.hybrid-analysis.com/sample/15d4ff941f77f7bdfc9dfb2399b7b952a0a2c860976ef3e835998ff4796e5e91?environmentId=120)
    condition: selection and not filter
falsepositives:
    - Unknown
level: high

```
