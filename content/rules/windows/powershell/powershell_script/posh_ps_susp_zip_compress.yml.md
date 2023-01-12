---
title: "Zip A Folder With PowerShell For Staging In Temp"
aliases:
  - "/rule/b7a3c9a3-09ea-4934-8864-6a32cacd98d9"
ruleid: b7a3c9a3-09ea-4934-8864-6a32cacd98d9

tags:
  - attack.collection
  - attack.t1074.001



status: experimental





date: Tue, 20 Jul 2021 13:13:53 +0200


---

Use living off the land tools to zip a file and stage it in the Windows temporary folder for later exfiltration

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1074.001/T1074.001.md


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/powershell/powershell_script/posh_ps_susp_zip_compress.yml))
```yaml
title: Zip A Folder With PowerShell For Staging In Temp
id: b7a3c9a3-09ea-4934-8864-6a32cacd98d9
status: experimental
author: frack113
date: 2021/07/20
modified: 2021/10/16
description: Use living off the land tools to zip a file and stage it in the Windows temporary folder for later exfiltration
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1074.001/T1074.001.md
tags:
    - attack.collection
    - attack.t1074.001
logsource:
    product: windows
    category: ps_script
    definition: Script Block Logging must be enable
detection:
    selection_4104:
        ScriptBlockText|contains|all:
            - 'Compress-Archive '
            - ' -Path '
            - ' -DestinationPath '
            - '$env:TEMP\'
    condition: selection_4104
falsepositives:
    - Unknown
level: medium

```