---
title: "Sysmon Channel Reference Deletion"
aliases:
  - "/rule/18beca67-ab3e-4ee3-ba7a-a46ca8d7d0cc"
ruleid: 18beca67-ab3e-4ee3-ba7a-a46ca8d7d0cc

tags:
  - attack.defense_evasion
  - attack.t1112



status: test





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Potential threat actor tampering with Sysmon manifest and eventually disabling it

<!--more-->


## Known false-positives

* unknown



## References

* https://twitter.com/Flangvik/status/1283054508084473861
* https://twitter.com/SecurityJosh/status/1283027365770276866
* https://securityjosh.github.io/2020/04/23/Mute-Sysmon.html
* https://gist.github.com/Cyb3rWard0g/cf08c38c61f7e46e8404b38201ca01c8


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/security/win_sysmon_channel_reference_deletion.yml))
```yaml
title: Sysmon Channel Reference Deletion
id: 18beca67-ab3e-4ee3-ba7a-a46ca8d7d0cc
status: test
description: Potential threat actor tampering with Sysmon manifest and eventually disabling it
author: Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)
references:
  - https://twitter.com/Flangvik/status/1283054508084473861
  - https://twitter.com/SecurityJosh/status/1283027365770276866
  - https://securityjosh.github.io/2020/04/23/Mute-Sysmon.html
  - https://gist.github.com/Cyb3rWard0g/cf08c38c61f7e46e8404b38201ca01c8
date: 2020/07/14
modified: 2021/11/27
logsource:
  product: windows
  service: security
detection:
  selection1:
    EventID: 4657
    ObjectName|contains:
      - 'WINEVT\Publishers\{5770385f-c22a-43e0-bf4c-06f5698ffbd9}'
      - 'WINEVT\Channels\Microsoft-Windows-Sysmon/Operational'
    ObjectValueName: 'Enabled'
    NewValue: '0'
  selection2:
    EventID: 4663
    ObjectName|contains:
      - 'WINEVT\Publishers\{5770385f-c22a-43e0-bf4c-06f5698ffbd9}'
      - 'WINEVT\Channels\Microsoft-Windows-Sysmon/Operational'
    AccessMask: 0x10000
  condition: selection1 or selection2
falsepositives:
  - unknown
level: critical
tags:
  - attack.defense_evasion
  - attack.t1112

```
