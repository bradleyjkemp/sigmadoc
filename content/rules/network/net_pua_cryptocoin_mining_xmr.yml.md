---
title: "Monero Crypto Coin Mining Pool Lookup"
aliases:
  - "/rule/b593fd50-7335-4682-a36c-4edcb68e4641"


tags:
  - attack.impact
  - attack.t1496
  - attack.t1567



status: stable





date: Sun, 24 Oct 2021 15:44:44 +0200


---

Detects suspicious DNS queries to Monero mining pools

<!--more-->


## Known false-positives

* Legitimate crypto coin mining



## References

* https://www.nextron-systems.com/2021/10/24/monero-mining-pool-fqdns/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/network/net_pua_cryptocoin_mining_xmr.yml))
```yaml
title: Monero Crypto Coin Mining Pool Lookup
id: b593fd50-7335-4682-a36c-4edcb68e4641
status: stable
description: Detects suspicious DNS queries to Monero mining pools
author: Florian Roth
date: 2021/10/24
references:
    - https://www.nextron-systems.com/2021/10/24/monero-mining-pool-fqdns/
logsource:
    category: dns
detection:
    selection:
        query|contains:
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
    condition: selection
falsepositives:
    - Legitimate crypto coin mining
tags:
    - attack.impact
    - attack.t1496
    - attack.t1567
level: high

```
