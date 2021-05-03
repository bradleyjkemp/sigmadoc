---
title: "Suspicious Eventlog Clear or Configuration Using Wevtutil"
aliases:
  - "/rule/cc36992a-4671-4f21-a91d-6c2b72a2edf5"

tags:
  - attack.defense_evasion
  - attack.t1070.001
  - attack.t1070
  - car.2016-04-002



date: Fri, 6 Sep 2019 10:57:03 -0400


---

Detects clearing or configuration of eventlogs uwing wevtutil, powershell and wmic. Might be used by ransomwares during the attack (seen by NotPetya and others)

<!--more-->


## Known false-positives

* Admin activity
* Scripts and administrative tools used in the monitored environment



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070/T1070.yaml
* https://eqllib.readthedocs.io/en/latest/analytics/5b223758-07d6-4100-9e11-238cfdd0fe97.html


## Raw rule
```yaml
title: Suspicious Eventlog Clear or Configuration Using Wevtutil
id: cc36992a-4671-4f21-a91d-6c2b72a2edf5
description: Detects clearing or configuration of eventlogs uwing wevtutil, powershell and wmic. Might be used by ransomwares during the attack (seen by NotPetya and others)
author: Ecco, Daniil Yugoslavskiy, oscd.community
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070/T1070.yaml
    - https://eqllib.readthedocs.io/en/latest/analytics/5b223758-07d6-4100-9e11-238cfdd0fe97.html
date: 2019/09/26
modified: 2019/11/11
tags:
    - attack.defense_evasion
    - attack.t1070.001
    - attack.t1070      # an old one
    - car.2016-04-002
level: high
logsource:
    category: process_creation
    product: windows
detection:
    selection_wevtutil_binary:
        Image|endswith: '\wevtutil.exe'
    selection_wevtutil_command:
        CommandLine|contains:
            - 'clear-log' # clears specified log
            - ' cl '        # short version of 'clear-log'
            - 'set-log'   # modifies config of specified log. could be uset to set it to a tiny size
            - ' sl '        # short version of 'set-log'
    selection_other_ps:
        Image|endswith: '\powershell.exe'
        CommandLine|contains:
            - 'Clear-EventLog'
            - 'Remove-EventLog'
            - 'Limit-EventLog'
    selection_other_wmic:
        Image|endswith: '\wmic.exe'
        CommandLine|contains: ' ClearEventLog '
    condition: 1 of selection_other_* or (selection_wevtutil_binary and selection_wevtutil_command)
falsepositives:
    - Admin activity
    - Scripts and administrative tools used in the monitored environment

```