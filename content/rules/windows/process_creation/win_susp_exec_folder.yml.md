---
title: "Executables Started in Suspicious Folder"
aliases:
  - "/rule/7a38aa19-86a9-4af7-ac51-6bfe4e59f254"

tags:
  - attack.defense_evasion
  - attack.t1036



date: Wed, 16 Jan 2019 23:36:31 +0100


---

Detects process starts of binaries from a suspicious folder

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/mbevilacqua/appcompatprocessor/blob/master/AppCompatSearch.txt
* https://www.secureworks.com/research/bronze-butler-targets-japanese-businesses
* https://www.crowdstrike.com/resources/reports/2019-crowdstrike-global-threat-report/
* https://github.com/ThreatHuntingProject/ThreatHunting/blob/master/hunts/suspicious_process_creation_via_windows_event_logs.md


## Raw rule
```yaml
title: Executables Started in Suspicious Folder
id: 7a38aa19-86a9-4af7-ac51-6bfe4e59f254
status: experimental
description: Detects process starts of binaries from a suspicious folder
author: Florian Roth
date: 2017/10/14
modified: 2019/02/21
references:
    - https://github.com/mbevilacqua/appcompatprocessor/blob/master/AppCompatSearch.txt
    - https://www.secureworks.com/research/bronze-butler-targets-japanese-businesses
    - https://www.crowdstrike.com/resources/reports/2019-crowdstrike-global-threat-report/
    - https://github.com/ThreatHuntingProject/ThreatHunting/blob/master/hunts/suspicious_process_creation_via_windows_event_logs.md
tags:
    - attack.defense_evasion
    - attack.t1036
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image:
            - C:\PerfLogs\\*
            - C:\$Recycle.bin\\*
            - C:\Intel\Logs\\*
            - C:\Users\Default\\*
            - C:\Users\Public\\*
            - C:\Users\NetworkService\\*
            - C:\Windows\Fonts\\*
            - C:\Windows\Debug\\*
            - C:\Windows\Media\\*
            - C:\Windows\Help\\*
            - C:\Windows\addins\\*
            - C:\Windows\repair\\*
            - C:\Windows\security\\*
            - '*\RSA\MachineKeys\\*'
            - C:\Windows\system32\config\systemprofile\\*
            - C:\Windows\Tasks\\*
            - C:\Windows\System32\Tasks\\*
    condition: selection
falsepositives:
    - Unknown
level: high

```