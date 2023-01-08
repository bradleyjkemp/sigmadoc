---
title: "Suspicious Desktopimgdownldr Target File"
aliases:
  - "/rule/fc4f4817-0c53-4683-a4ee-b17a64bc1039"
ruleid: fc4f4817-0c53-4683-a4ee-b17a64bc1039

tags:
  - attack.defense_evasion
  - attack.t1105



status: test





date: Fri, 3 Jul 2020 09:45:48 +0200


---

Detects a suspicious Microsoft desktopimgdownldr file creation that stores a file to a suspicious location or contains a file with a suspicious extension

<!--more-->


## Known false-positives

* False positives depend on scripts and administrative tools used in the monitored environment



## References

* https://labs.sentinelone.com/living-off-windows-land-a-new-native-file-downldr/
* https://twitter.com/SBousseaden/status/1278977301745741825


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/file_event/file_event_win_susp_desktopimgdownldr_file.yml))
```yaml
title: Suspicious Desktopimgdownldr Target File
id: fc4f4817-0c53-4683-a4ee-b17a64bc1039
status: test
description: Detects a suspicious Microsoft desktopimgdownldr file creation that stores a file to a suspicious location or contains a file with a suspicious extension
author: Florian Roth
references:
  - https://labs.sentinelone.com/living-off-windows-land-a-new-native-file-downldr/
  - https://twitter.com/SBousseaden/status/1278977301745741825
date: 2020/07/03
modified: 2021/11/27
logsource:
  product: windows
  category: file_event
detection:
  selection:
    Image|endswith: svchost.exe
    TargetFilename|contains: '\Personalization\LockScreenImage\'
  filter1:
    TargetFilename|contains: 'C:\Windows\'
  filter2:
    TargetFilename|contains:
      - '.jpg'
      - '.jpeg'
      - '.png'
  condition: selection and not filter1 and not filter2
fields:
  - CommandLine
  - ParentCommandLine
falsepositives:
  - False positives depend on scripts and administrative tools used in the monitored environment
level: high
tags:
  - attack.defense_evasion
  - attack.t1105

```
