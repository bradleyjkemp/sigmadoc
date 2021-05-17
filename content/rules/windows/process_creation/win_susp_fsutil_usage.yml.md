---
title: "Fsutil Suspicious Invocation"
aliases:
  - "/rule/add64136-62e5-48ea-807e-88638d02df1e"

tags:
  - attack.defense_evasion
  - attack.t1070





level: high



date: Fri, 6 Sep 2019 10:57:03 -0400


---

Detects suspicious parameters of fsutil (deleting USN journal, configuring it with small size..). Might be used by ransomwares during the attack (seen by NotPetya and others)

<!--more-->


## Known false-positives

* Admin activity
* Scripts and administrative tools used in the monitored environment



## References

* https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-usn
* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070/T1070.yaml
* https://eqllib.readthedocs.io/en/latest/analytics/c91f422a-5214-4b17-8664-c5fcf115c0a2.html


## Raw rule
```yaml
title: Fsutil Suspicious Invocation
id: add64136-62e5-48ea-807e-88638d02df1e
description: Detects suspicious parameters of fsutil (deleting USN journal, configuring it with small size..). Might be used by ransomwares during the attack (seen by NotPetya and others)
author: Ecco, E.M. Anhaus, oscd.community
date: 2019/09/26
modified: 2019/11/11
level: high
references:
    - https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-usn
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070/T1070.yaml
    - https://eqllib.readthedocs.io/en/latest/analytics/c91f422a-5214-4b17-8664-c5fcf115c0a2.html
tags:
    - attack.defense_evasion
    - attack.t1070
logsource:
    category: process_creation
    product: windows
detection:
    binary_1:
        Image|endswith: '\fsutil.exe'
    binary_2:
        OriginalFileName: 'fsutil.exe'
    selection:
        CommandLine|contains:
            - 'deletejournal'  # usn deletejournal ==> generally ransomware or attacker
            - 'createjournal'  # usn createjournal ==> can modify config to set it to a tiny size
    condition: (1 of binary_*) and selection
falsepositives:
    - Admin activity
    - Scripts and administrative tools used in the monitored environment

```
