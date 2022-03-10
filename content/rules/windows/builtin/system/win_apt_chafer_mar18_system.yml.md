---
title: "Chafer Activity"
aliases:
  - "/rule/53ba33fd-3a50-4468-a5ef-c583635cfa92"


tags:
  - attack.persistence
  - attack.g0049
  - attack.t1053.005
  - attack.s0111
  - attack.t1543.003
  - attack.defense_evasion
  - attack.t1112
  - attack.command_and_control
  - attack.t1071.004



status: experimental





date: Sun, 19 Sep 2021 11:48:20 +0200


---

Detects Chafer activity attributed to OilRig as reported in Nyotron report in March 2018

<!--more-->


## Known false-positives

* Unknown



## References

* https://nyotron.com/nyotron-discovers-next-generation-oilrig-attacks/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/system/win_apt_chafer_mar18_system.yml))
```yaml
title: Chafer Activity
id: 53ba33fd-3a50-4468-a5ef-c583635cfa92
description: Detects Chafer activity attributed to OilRig as reported in Nyotron report in March 2018
status: experimental
references:
    - https://nyotron.com/nyotron-discovers-next-generation-oilrig-attacks/
tags:
    - attack.persistence
    - attack.g0049
    - attack.t1053.005
    - attack.s0111
    - attack.t1543.003
    - attack.defense_evasion
    - attack.t1112
    - attack.command_and_control
    - attack.t1071.004
date: 2018/03/23
modified: 2021/11/30
author: Florian Roth, Markus Neis, Jonhnathan Ribeiro, Daniil Yugoslavskiy, oscd.community
logsource:
    product: windows
    service: system
detection:
    selection_service:
        Provider_Name: 'Service Control Manager'
        EventID: 7045
        ServiceName:
            - 'SC Scheduled Scan'
            - 'UpdatMachine'
    condition: selection_service
falsepositives:
    - Unknown
level: critical
```
