---
title: "Windows Crypto Mining Indicators"
aliases:
  - "/rule/66c3b204-9f88-4d0a-a7f7-8a57d521ca55"
ruleid: 66c3b204-9f88-4d0a-a7f7-8a57d521ca55

tags:
  - attack.impact
  - attack.t1496



status: stable





date: Tue, 26 Oct 2021 08:52:07 +0200


---

Detects command line parameters or strings often used by crypto miners

<!--more-->


## Known false-positives

* Legitimate use of crypto miners



## References

* https://www.poolwatch.io/coin/monero


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_crypto_mining_monero.yml))
```yaml
title: Windows Crypto Mining Indicators
id: 66c3b204-9f88-4d0a-a7f7-8a57d521ca55
description: Detects command line parameters or strings often used by crypto miners
status: stable
references:
    - https://www.poolwatch.io/coin/monero
author: Florian Roth
date: 2021/10/26
logsource:
    category: process_creation
    product: windows
detection:
    selection:
         CommandLine|contains:
            - ' --cpu-priority='
            - '--donate-level=0'
            - ' -o pool.'
            - ' --nicehash'
            - ' --algo=rx/0 '
            - 'stratum+tcp://'
            - 'stratum+udp://'
            # base64 encoded: --donate-level=
            - 'LS1kb25hdGUtbGV2ZWw9'
            - '0tZG9uYXRlLWxldmVsP'
            - 'tLWRvbmF0ZS1sZXZlbD'
            # base64 encoded: stratum+tcp:// and stratum+udp:// 
            - 'c3RyYXR1bSt0Y3A6Ly'
            - 'N0cmF0dW0rdGNwOi8v'
            - 'zdHJhdHVtK3RjcDovL'
            - 'c3RyYXR1bSt1ZHA6Ly'
            - 'N0cmF0dW0rdWRwOi8v'
            - 'zdHJhdHVtK3VkcDovL'
    condition: selection
falsepositives:
    - Legitimate use of crypto miners
level: high
tags:
    - attack.impact
    - attack.t1496
```
