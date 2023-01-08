---
title: "Rar with Password or Compression Level"
aliases:
  - "/rule/faa48cae-6b25-4f00-a094-08947fef582f"
ruleid: faa48cae-6b25-4f00-a094-08947fef582f

tags:
  - attack.collection
  - attack.t1560.001



status: experimental





date: Wed, 1 Jul 2020 09:04:26 +0200


---

Detects the use of rar.exe, on the command line, to create an archive with password protection or with a specific compression level. This is pretty indicative of malicious actions.

<!--more-->


## Known false-positives

* Legitimate use of Winrar command line version
* Other command line tools, that use these flags



## References

* https://labs.sentinelone.com/the-anatomy-of-an-apt-attack-and-cobaltstrike-beacons-encoded-configuration/
* https://ss64.com/bash/rar.html
* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1560.001/T1560.001.md


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_rar_flags.yml))
```yaml
title: Rar with Password or Compression Level 
id: faa48cae-6b25-4f00-a094-08947fef582f
status: experimental
description: Detects the use of rar.exe, on the command line, to create an archive with password protection or with a specific compression level. This is pretty indicative of malicious actions.
references:
    - https://labs.sentinelone.com/the-anatomy-of-an-apt-attack-and-cobaltstrike-beacons-encoded-configuration/
    - https://ss64.com/bash/rar.html
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1560.001/T1560.001.md
author: '@ROxPinTeddy'
date: 2020/05/12
modified: 2021/07/27
tags:
    - attack.collection
    - attack.t1560.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_password:
       CommandLine|contains:
               - ' -hp'
    selection_other:
       CommandLine|contains:
               - ' -m'
               - ' a '
    condition: selection_password and selection_other
falsepositives:
    - Legitimate use of Winrar command line version
    - Other command line tools, that use these flags
level: medium
```
