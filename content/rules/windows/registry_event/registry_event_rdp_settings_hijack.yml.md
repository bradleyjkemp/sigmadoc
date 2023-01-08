---
title: "RDP Sensitive Settings Changed"
aliases:
  - "/rule/171b67e1-74b4-460e-8d55-b331f3e32d67"
ruleid: 171b67e1-74b4-460e-8d55-b331f3e32d67

tags:
  - attack.defense_evasion
  - attack.t1112



status: test





date: Wed, 3 Apr 2019 14:16:25 +0200


---

Detects changes to RDP terminal service sensitive settings

<!--more-->


## Known false-positives

* unknown



## References

* https://blog.menasec.net/2019/02/threat-hunting-rdp-hijacking-via.html
* https://knowledge.insourcess.com/Supporting_Technologies/Wonderware/Tech_Notes/TN_WW213_How_to_shadow_an_established_RDP_Session_on_Windows_10_Pro
* https://twitter.com/SagieSec/status/1469001618863624194?t=HRf0eA0W1YYzkTSHb-Ky1A&s=03
* http://etutorials.org/Microsoft+Products/microsoft+windows+server+2003+terminal+services/Chapter+6+Registry/Registry+Keys+for+Terminal+Services/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/registry_event/registry_event_rdp_settings_hijack.yml))
```yaml
title: RDP Sensitive Settings Changed
id: 171b67e1-74b4-460e-8d55-b331f3e32d67
status: test
description: Detects changes to RDP terminal service sensitive settings
author: Samir Bousseaden, David ANDRE
references:
  - https://blog.menasec.net/2019/02/threat-hunting-rdp-hijacking-via.html
  - https://knowledge.insourcess.com/Supporting_Technologies/Wonderware/Tech_Notes/TN_WW213_How_to_shadow_an_established_RDP_Session_on_Windows_10_Pro
  - https://twitter.com/SagieSec/status/1469001618863624194?t=HRf0eA0W1YYzkTSHb-Ky1A&s=03
  - http://etutorials.org/Microsoft+Products/microsoft+windows+server+2003+terminal+services/Chapter+6+Registry/Registry+Keys+for+Terminal+Services/
date: 2019/04/03
modified: 2021/12/31
logsource:
  category: registry_event
  product: windows
detection:
  selection_reg:
    TargetObject|contains:
      - '\services\TermService\Parameters\ServiceDll'
      - '\Control\Terminal Server\fSingleSessionPerUser'
      - '\Control\Terminal Server\fDenyTSConnections'
      - '\Policies\Microsoft\Windows NT\Terminal Services\Shadow'
      - '\Control\Terminal Server\WinStations\RDP-Tcp\InitialProgram'
  condition: selection_reg
falsepositives:
  - unknown
level: high
tags:
  - attack.defense_evasion
  - attack.t1112

```
