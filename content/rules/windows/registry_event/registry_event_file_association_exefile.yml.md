---
title: "New File Association Using Exefile"
aliases:
  - "/rule/44a22d59-b175-4f13-8c16-cbaef5b581ff"
ruleid: 44a22d59-b175-4f13-8c16-cbaef5b581ff

tags:
  - attack.defense_evasion



status: experimental





date: Fri, 19 Nov 2021 17:23:03 +0100


---

Detects the abuse of the exefile handler in new file association. Used for bypass of security products.

<!--more-->


## Known false-positives

* Unknown



## References

* https://twitter.com/mrd0x/status/1461041276514623491


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/registry_event/registry_event_file_association_exefile.yml))
```yaml
title: New File Association Using Exefile
id: 44a22d59-b175-4f13-8c16-cbaef5b581ff
description: Detects the abuse of the exefile handler in new file association. Used for bypass of security products.
author: Andreas Hunkeler (@Karneades)
date: 2021/11/19
status: experimental
references:
    - https://twitter.com/mrd0x/status/1461041276514623491
tags:
    - attack.defense_evasion
logsource:
    category: registry_event
    product: windows
detection:
    selection:
        TargetObject|contains: 'Classes\.'
        Details: 'exefile'
        EventType: SetValue
    condition: selection
falsepositives:
    - Unknown
level: high

```