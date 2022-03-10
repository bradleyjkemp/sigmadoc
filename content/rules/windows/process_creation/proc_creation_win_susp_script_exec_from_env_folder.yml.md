---
title: "Script Interpreter Execution From Suspicious Folder"
aliases:
  - "/rule/1228c958-e64e-4e71-92ad-7d429f4138ba"


tags:
  - attack.execution
  - attack.t1059



status: experimental





date: Tue, 8 Feb 2022 16:15:46 +0100


---

Detects a suspicious script executions in temporary folders or folders accessible by environment variables

<!--more-->


## Known false-positives

* Unknown



## References

* https://www.virustotal.com/gui/file/91ba814a86ddedc7a9d546e26f912c541205b47a853d227756ab1334ade92c3f


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_script_exec_from_env_folder.yml))
```yaml
title: Script Interpreter Execution From Suspicious Folder
id: 1228c958-e64e-4e71-92ad-7d429f4138ba
description: Detects a suspicious script executions in temporary folders or folders accessible by environment variables
status: experimental
references:
    - https://www.virustotal.com/gui/file/91ba814a86ddedc7a9d546e26f912c541205b47a853d227756ab1334ade92c3f
author: Florian Roth
date: 2022/02/08
tags:
    - attack.execution
    - attack.t1059
logsource:
    category: process_creation
    product: windows
detection:
    selection_image:
        Image|endswith:
            - '\powershell.exe'
            - '\mshta.exe'
            - '\wscript.exe'
            - '\cscript.exe'
            - '\cmd.exe'
    selection_flags:
        CommandLine|contains:
            - ' -w hidden '
            - ' -ep bypass '
            - '/e:vbscript '
            - '/e:javascript '
    selection_original:
        OriginalFileName:
            - 'powershell.exe'
            - 'mshta.exe'
            - 'wscript.exe'
            - 'cscript.exe'
            - 'cmd.exe'
    folders:
        Image|contains: 
            - '\Windows\Temp'
            - '\Temporary Internet'
            - '\AppData\Local\Temp'
            - '\AppData\Roaming\Temp'
            - 'C:\Users\Public\'
            - 'C:\Perflogs\'
    condition: 1 of selection* and folders
falsepositives:
    - Unknown
level: high

```
