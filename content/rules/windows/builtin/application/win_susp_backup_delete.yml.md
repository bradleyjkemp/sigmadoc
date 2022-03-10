---
title: "Backup Catalog Deleted"
aliases:
  - "/rule/9703792d-fd9a-456d-a672-ff92efe4806a"


tags:
  - attack.defense_evasion
  - attack.t1070.004



status: experimental





date: Fri, 12 May 2017 23:00:56 +0200


---

Detects backup catalog deletions

<!--more-->


## Known false-positives

* Unknown



## References

* https://technet.microsoft.com/en-us/library/cc742154(v=ws.11).aspx
* https://www.hybrid-analysis.com/sample/ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa?environmentId=100


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/application/win_susp_backup_delete.yml))
```yaml
title: Backup Catalog Deleted
id: 9703792d-fd9a-456d-a672-ff92efe4806a
status: experimental
description: Detects backup catalog deletions
references:
    - https://technet.microsoft.com/en-us/library/cc742154(v=ws.11).aspx
    - https://www.hybrid-analysis.com/sample/ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa?environmentId=100
author: Florian Roth (rule), Tom U. @c_APT_ure (collection)
date: 2017/05/12
modified: 2021/10/13
tags:
    - attack.defense_evasion
    - attack.t1070.004
logsource:
    product: windows
    service: application
detection:
    selection:
        EventID: 524
        Provider_Name: Microsoft-Windows-Backup
    condition: selection
falsepositives:
    - Unknown
level: medium

```