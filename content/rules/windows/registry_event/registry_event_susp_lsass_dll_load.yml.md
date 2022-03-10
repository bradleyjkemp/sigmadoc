---
title: "DLL Load via LSASS"
aliases:
  - "/rule/b3503044-60ce-4bf4-bbcb-e3db98788823"


tags:
  - attack.execution
  - attack.persistence
  - attack.t1547.008



status: test





date: Wed, 16 Oct 2019 13:18:31 +0200


---

Detects a method to load DLL via LSASS process using an undocumented Registry key

<!--more-->


## Known false-positives

* Unknown



## References

* https://blog.xpnsec.com/exploring-mimikatz-part-1/
* https://twitter.com/SBousseaden/status/1183745981189427200


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/registry_event/registry_event_susp_lsass_dll_load.yml))
```yaml
title: DLL Load via LSASS
id: b3503044-60ce-4bf4-bbcb-e3db98788823
status: test
description: Detects a method to load DLL via LSASS process using an undocumented Registry key
author: Florian Roth
references:
  - https://blog.xpnsec.com/exploring-mimikatz-part-1/
  - https://twitter.com/SBousseaden/status/1183745981189427200
date: 2019/10/16
modified: 2021/11/27
logsource:
  category: registry_event
  product: windows
detection:
  selection:
    TargetObject|contains:
      - '\CurrentControlSet\Services\NTDS\DirectoryServiceExtPt'
      - '\CurrentControlSet\Services\NTDS\LsaDbExtPt'
  condition: selection
falsepositives:
  - Unknown
level: high
tags:
  - attack.execution
  - attack.persistence
  - attack.t1547.008

```
