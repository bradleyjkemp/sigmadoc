---
title: "Windows Crypto Mining Pool Connections"
aliases:
  - "/rule/fa5b1358-b040-4403-9868-15f7d9ab6329"
ruleid: fa5b1358-b040-4403-9868-15f7d9ab6329

tags:
  - attack.impact
  - attack.t1496



status: stable





date: Tue, 26 Oct 2021 08:52:07 +0200


---

Detects process connections to a Monero crypto mining pool

<!--more-->


## Known false-positives

* Legitimate use of crypto miners



## References

* https://www.poolwatch.io/coin/monero


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/network_connection/net_connection_win_crypto_mining.yml))
```yaml
title: Windows Crypto Mining Pool Connections
id: fa5b1358-b040-4403-9868-15f7d9ab6329
status: stable
description: Detects process connections to a Monero crypto mining pool
references:
   - https://www.poolwatch.io/coin/monero
date: 2021/10/26
author: Florian Roth
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        DestinationHostname: 
            - 'pool.minexmr.com'
            - 'fr.minexmr.com'
            - 'de.minexmr.com'
            - 'sg.minexmr.com'
            - 'ca.minexmr.com'
            - 'us-west.minexmr.com'
            - 'pool.supportxmr.com'
            - 'mine.c3pool.com'
            - 'xmr-eu1.nanopool.org'
            - 'xmr-eu2.nanopool.org'
            - 'xmr-us-east1.nanopool.org'
            - 'xmr-us-west1.nanopool.org'
            - 'xmr-asia1.nanopool.org'
            - 'xmr-jp1.nanopool.org'
            - 'xmr-au1.nanopool.org'
            - 'xmr.2miners.com'
            - 'xmr.hashcity.org'
            - 'xmr.f2pool.com'
            - 'xmrpool.eu'
            - 'pool.hashvault.pro'
            - 'moneroocean.stream'
            - 'monerocean.stream'
    condition: selection
falsepositives:
    - Legitimate use of crypto miners
level: high
tags:
    - attack.impact
    - attack.t1496
```
