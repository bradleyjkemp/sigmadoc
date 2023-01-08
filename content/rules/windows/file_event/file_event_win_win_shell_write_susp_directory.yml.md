---
title: "Windows Shell File Write to Suspicious Folder"
aliases:
  - "/rule/1277f594-a7d1-4f28-a2d3-73af5cbeab43"
ruleid: 1277f594-a7d1-4f28-a2d3-73af5cbeab43



status: experimental





date: Sat, 20 Nov 2021 15:37:10 +0100


---

Detects a Windows executable that writes files to suspicious folders

<!--more-->


## Known false-positives

* Unknown



## References

* No references


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/file_event/file_event_win_win_shell_write_susp_directory.yml))
```yaml
title: Windows Shell File Write to Suspicious Folder
id: 1277f594-a7d1-4f28-a2d3-73af5cbeab43
status: experimental
description: Detects a Windows executable that writes files to suspicious folders
references:
    - No references
author: Florian Roth
date: 2021/11/20
modified: 2021/11/24
logsource:
    category: file_event
    product: windows
detection:
    selection_shells:
        Image|endswith:
            - '\cmd.exe'
            - '\powershell.exe'
            - '\wscript.exe'
            - '\cscript.exe'
            - '\sh.exe'
            - '\bash.exe'
            - '\msbuild.exe'  # https://github.com/elastic/detection-rules/blob/main/rules/windows/defense_evasion_execution_msbuild_started_by_office_app.toml
            - '\certutil.exe'
        TargetFilename|contains: 
            - 'C:\Users\Public'
            - 'C:\PerfLogs'
    selection_program:
        Image|endswith:
            - '\schtasks.exe'
            - '\wmic.exe'  # https://app.any.run/tasks/c903e9c8-0350-440c-8688-3881b556b8e0/
            - '\mshta.exe'
            # - '\rundll32.exe'
            - '\forfiles.exe'
            - '\scriptrunner.exe'
            - '\certutil.exe'
        TargetFilename|contains: 
            - 'C:\Users\Public'
            - 'C:\PerfLogs'
            - '\AppData\'
            - 'C:\Windows\Temp'
    condition: 1 of selection*
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Unknown
level: high

```
