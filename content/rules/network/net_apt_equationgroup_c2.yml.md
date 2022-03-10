---
title: "Equation Group C2 Communication"
aliases:
  - "/rule/881834a4-6659-4773-821e-1c151789d873"


tags:
  - attack.command_and_control
  - attack.g0020
  - attack.t1041



status: test





date: Sat, 15 Apr 2017 11:32:56 +0200


---

Detects communication to C2 servers mentioned in the operational notes of the ShadowBroker leak of EquationGroup C2 tools

<!--more-->


## Known false-positives

* Unknown



## References

* https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation
* https://medium.com/@msuiche/the-nsa-compromised-swift-network-50ec3000b195


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/network/net_apt_equationgroup_c2.yml))
```yaml
title: Equation Group C2 Communication
id: 881834a4-6659-4773-821e-1c151789d873
status: test
description: Detects communication to C2 servers mentioned in the operational notes of the ShadowBroker leak of EquationGroup C2 tools
author: Florian Roth
references:
  - https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation
  - https://medium.com/@msuiche/the-nsa-compromised-swift-network-50ec3000b195
date: 2017/04/15
modified: 2021/11/27
logsource:
  category: firewall
detection:
  select_outgoing:
    dst_ip:
      - '69.42.98.86'
      - '89.185.234.145'
  select_incoming:
    src_ip:
      - '69.42.98.86'
      - '89.185.234.145'
  condition: 1 of select*
falsepositives:
  - Unknown
level: high
tags:
  - attack.command_and_control
  - attack.g0020
  - attack.t1041

```