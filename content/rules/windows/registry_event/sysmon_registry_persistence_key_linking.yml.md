---
title: "Windows Registry Persistence COM Key Linking"
aliases:
  - "/rule/9b0f8a61-91b2-464f-aceb-0527e0a45020"

tags:
  - attack.persistence
  - attack.t1122



status: experimental



level: medium



date: Fri, 25 Oct 2019 18:01:36 +0300


---

Detects COM object hijacking via TreatAs subkey

<!--more-->


## Known false-positives

* Maybe some system utilities in rare cases use linking keys for backward compability



## References

* https://bohops.com/2018/08/18/abusing-the-com-registry-structure-part-2-loading-techniques-for-evasion-and-persistence/


## Raw rule
```yaml
title: Windows Registry Persistence COM Key Linking
id: 9b0f8a61-91b2-464f-aceb-0527e0a45020
status: experimental
description: Detects COM object hijacking via TreatAs subkey
references:
    - https://bohops.com/2018/08/18/abusing-the-com-registry-structure-part-2-loading-techniques-for-evasion-and-persistence/
author: Kutepov Anton, oscd.community
date: 2019/10/23
modified: 2019/11/07
tags:
    - attack.persistence
    - attack.t1122
logsource:
    category: registry_event
    product: windows
detection:
    selection:
        EventType: 'CreateKey'  # don't want DeleteKey events
        TargetObject: 'HKU\\*_Classes\CLSID\\*\TreatAs'
    condition: selection
falsepositives:
    - Maybe some system utilities in rare cases use linking keys for backward compability
level: medium

```
