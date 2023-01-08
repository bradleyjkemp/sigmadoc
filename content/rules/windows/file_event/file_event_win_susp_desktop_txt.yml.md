---
title: "Suspicious Creation TXT File in User Desktop"
aliases:
  - "/rule/caf02a0a-1e1c-4552-9b48-5e070bd88d11"
ruleid: caf02a0a-1e1c-4552-9b48-5e070bd88d11

tags:
  - attack.impact
  - attack.t1486



status: experimental





date: Sun, 26 Dec 2021 12:09:42 +0100


---

Ransomware create txt file in the user Desktop

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1486/T1486.md#atomic-test-5---purelocker-ransom-note


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/file_event/file_event_win_susp_desktop_txt.yml))
```yaml
title: Suspicious Creation TXT File in User Desktop
id: caf02a0a-1e1c-4552-9b48-5e070bd88d11
status: experimental
description: Ransomware create txt file in the user Desktop
author: frack113
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1486/T1486.md#atomic-test-5---purelocker-ransom-note
date: 2021/12/26
logsource:
  product: windows
  category: file_event
detection:
  selection:
    Image|endswith: \cmd.exe 
    TargetFilename|contains|all:
        - \Users\
        - \Desktop\
    TargetFilename|endswith: .txt
  condition: selection
falsepositives:
  - Unknown
level: high
tags:
  - attack.impact
  - attack.t1486

```
