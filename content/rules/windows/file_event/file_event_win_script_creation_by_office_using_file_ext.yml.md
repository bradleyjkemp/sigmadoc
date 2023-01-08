---
title: "Created Files by Office Applications"
aliases:
  - "/rule/c7a74c80-ba5a-486e-9974-ab9e682bc5e4"
ruleid: c7a74c80-ba5a-486e-9974-ab9e682bc5e4

tags:
  - attack.t1204.002
  - attack.t1047
  - attack.t1218.010
  - attack.execution
  - attack.defense_evasion



status: experimental





date: Mon, 30 Aug 2021 21:48:03 -0600


---

This rule will monitor executable and script file creation by office applications. Please add more file extensions or magic bytes to the logic of your choice.

<!--more-->


## Known false-positives

* Unknown



## References

* https://thedfirreport.com/2021/03/29/sodinokibi-aka-revil-ransomware/
* https://github.com/vadim-hunter/Detection-Ideas-Rules/blob/main/Threat%20Intelligence/The%20DFIR%20Report/20210329_Sodinokibi_(aka_REvil)_Ransomware.yaml


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/file_event/file_event_win_script_creation_by_office_using_file_ext.yml))
```yaml
title: Created Files by Office Applications
id: c7a74c80-ba5a-486e-9974-ab9e682bc5e4
description: This rule will monitor executable and script file creation by office applications. Please add more file extensions or magic bytes to the logic of your choice.  
references:
    - https://thedfirreport.com/2021/03/29/sodinokibi-aka-revil-ransomware/
    - https://github.com/vadim-hunter/Detection-Ideas-Rules/blob/main/Threat%20Intelligence/The%20DFIR%20Report/20210329_Sodinokibi_(aka_REvil)_Ransomware.yaml
author: 'Vadim Khrykov (ThreatIntel), Cyb3rEng (Rule)'
tags:
    - attack.t1204.002
    - attack.t1047
    - attack.t1218.010
    - attack.execution
    - attack.defense_evasion
status: experimental
date: 2021/08/23
modified: 2022/03/02
logsource:
    product: windows
    category: file_event
detection:
    #useful_information: Please add more file extensions to the logic of your choice. 
    selection1:
        Image|endswith:
            - 'winword.exe'
            - 'excel.exe'
            - 'powerpnt.exe'
    selection2:
        TargetFilename|endswith:
            - '.exe'
            - '.dll'
            - '.ocx'
            - '.com'
            - '.ps1'
            - '.vbs'
            - '.sys'
            - '.bat'
            - '.scr'
            - '.proj'
    filter_webservicecache: # matches e.g. directory with name *.microsoft.com
        TargetFilename|contains|all:
            - 'C:\Users\'
            - '\AppData\Local\Microsoft\Office\'
            - '\WebServiceCache\AllUsers'
        TargetFilename|endswith: '.com'
    filter_webex:
        Image|endswith: 'winword.exe'
        TargetFilename|contains: '\AppData\Local\Temp\webexdelta\'
        TargetFilename|endswith:
            - '.dll'
            - '.exe'
    filter_localassembly:
        TargetFilename|contains: '\AppData\Local\assembly\tmp\'
        TargetFilename|endswith: '.dll'
    condition: selection1 and selection2 and not 1 of filter_*
falsepositives:
    - Unknown
level: high

```
