---
title: "Write Protect For Storage Disabled"
aliases:
  - "/rule/75f7a0e2-7154-4c4d-9eae-5cdb4e0a5c13"
ruleid: 75f7a0e2-7154-4c4d-9eae-5cdb4e0a5c13

tags:
  - attack.defense_evasion
  - attack.t1562



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Looks for changes to registry to disable any write-protect property for storage devices. This could be a precursor to a ransomware attack and has been an observed technique used by cypherpunk group.

<!--more-->


## Known false-positives

* none observed




## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_write_protect_for_storage_disabled.yml))
```yaml
title: Write Protect For Storage Disabled
id: 75f7a0e2-7154-4c4d-9eae-5cdb4e0a5c13
description: Looks for changes to registry to disable any write-protect property for storage devices. This could be a precursor to a ransomware attack and has been an observed technique used by cypherpunk group.
status: experimental
author: Sreeman
date: 2021/06/11
modified: 2022/03/07
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|contains|all:
            - 'reg add'
            - 'hklm\system\currentcontrolset\control'
            - 'write protection'
            - '0'
        CommandLine|contains:   
            - 'storage'
            - 'storagedevicepolicies'
    condition: selection
falsepositives:
    - none observed
level: medium
tags:
    - attack.defense_evasion
    - attack.t1562

```
