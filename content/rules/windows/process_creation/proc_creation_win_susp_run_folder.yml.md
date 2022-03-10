---
title: "Process Start From Suspicious Folder"
aliases:
  - "/rule/dca91cfd-d7ab-4c66-8da7-ee57d487b35b"


tags:
  - attack.execution
  - attack.t1204



status: experimental





date: Fri, 11 Feb 2022 21:37:11 +0100


---

Detects process start from rare or uncommon folders like temporary folder or folders that usually don't contain executable files

<!--more-->


## Known false-positives

* unknown



## References

* Malware sandbox results


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_run_folder.yml))
```yaml
title: Process Start From Suspicious Folder
id: dca91cfd-d7ab-4c66-8da7-ee57d487b35b
status: experimental
description: Detects process start from rare or uncommon folders like temporary folder or folders that usually don't contain executable files
references:
    - Malware sandbox results
author: frack113
date: 2022/02/11
modified: 2022/02/18
logsource:
    category: process_creation
    product: windows
detection:
    image:
        Image|contains:
            - '\Desktop\'
            - '\Temp\'
            - '\Temporary Internet'
    filter_parent:
        ParentImage: 
            - 'C:\Windows\System32\cleanmgr.exe'
            - 'C:\Program Files (x86)\Microsoft Visual Studio\Installer\resources\app\ServiceHub\Services\Microsoft.VisualStudio.Setup.Service\BackgroundDownload.exe'
    condition: image and not filter_parent
falsepositives:
    - unknown
level: low
tags:
    - attack.execution
    - attack.t1204

```
