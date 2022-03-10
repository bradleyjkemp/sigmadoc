---
title: "DevInit Lolbin Download"
aliases:
  - "/rule/90d50722-0483-4065-8e35-57efaadd354d"


tags:
  - attack.execution
  - attack.defense_evasion
  - attack.t1218



status: experimental





date: Tue, 11 Jan 2022 10:46:39 +0100


---

Detects a certain command line flag combination used by devinit.exe lolbin to download arbitrary MSI packages on a Windows system

<!--more-->


## Known false-positives

* Unknown



## References

* https://twitter.com/mrd0x/status/1460815932402679809


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_devinit_lolbin.yml))
```yaml
title: DevInit Lolbin Download
id: 90d50722-0483-4065-8e35-57efaadd354d
status: experimental
description: Detects a certain command line flag combination used by devinit.exe lolbin to download arbitrary MSI packages on a Windows system
references:
    - https://twitter.com/mrd0x/status/1460815932402679809
tags:
    - attack.execution
    - attack.defense_evasion
    - attack.t1218
author: Florian Roth
date: 2022/01/11
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all: 
            - ' -t msi-install '
            - ' -i http'
    condition: selection
falsepositives:
    - Unknown
level: high
```
