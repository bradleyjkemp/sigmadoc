---
title: "Linux Crypto Mining Indicators"
aliases:
  - "/rule/9069ea3c-b213-4c52-be13-86506a227ab1"




status: experimental





date: Tue, 26 Oct 2021 08:52:07 +0200


---

Detects command line parameters or strings often used by crypto miners

<!--more-->


## Known false-positives

* Legitimate use of crypto miners



## References

* https://www.poolwatch.io/coin/monero


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/linux/process_creation/proc_creation_lnx_crypto_mining.yml))
```yaml
title: Linux Crypto Mining Indicators
id: 9069ea3c-b213-4c52-be13-86506a227ab1
status: experimental
description: Detects command line parameters or strings often used by crypto miners
references:
   - https://www.poolwatch.io/coin/monero
date: 2021/10/26
author: Florian Roth
logsource:
   product: linux
   category: process_creation
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
        # Sub process started by xmrig - the most popular Monero crypto miner - unknown if this causes any false positives
        - 'sh -c /sbin/modprobe msr allow_writes=on'
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

```
