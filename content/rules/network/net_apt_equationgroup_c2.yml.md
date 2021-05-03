---
title: "Equation Group C2 Communication"
aliases:
  - "/rule/881834a4-6659-4773-821e-1c151789d873"

tags:
  - attack.command_and_control
  - attack.g0020



date: Sat, 15 Apr 2017 11:32:56 +0200


---

Detects communication to C2 servers mentioned in the operational notes of the ShadowBroker leak of EquationGroup C2 tools

<!--more-->


## Known false-positives

* Unknown



## References

* https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation
* https://medium.com/@msuiche/the-nsa-compromised-swift-network-50ec3000b195


## Raw rule
```yaml
title: Equation Group C2 Communication
id: 881834a4-6659-4773-821e-1c151789d873
description: Detects communication to C2 servers mentioned in the operational notes of the ShadowBroker leak of EquationGroup C2 tools
author: Florian Roth
date: 2017/04/15
references:
    - https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation
    - https://medium.com/@msuiche/the-nsa-compromised-swift-network-50ec3000b195
logsource:
    category: firewall
detection:
    outgoing:
        dst_ip:
            - '69.42.98.86'
            - '89.185.234.145'
    incoming:
        src_ip:
            - '69.42.98.86'
            - '89.185.234.145'
    condition: 1 of them
falsepositives:
    - Unknown
level: high
tags:
    - attack.command_and_control
    - attack.g0020
```