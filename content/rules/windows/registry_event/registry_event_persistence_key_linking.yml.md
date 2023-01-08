---
title: "Windows Registry Persistence COM Key Linking"
aliases:
  - "/rule/9b0f8a61-91b2-464f-aceb-0527e0a45020"
ruleid: 9b0f8a61-91b2-464f-aceb-0527e0a45020

tags:
  - attack.persistence
  - attack.t1546.015



status: experimental





date: Fri, 25 Oct 2019 18:01:36 +0300


---

Detects COM object hijacking via TreatAs subkey

<!--more-->


## Known false-positives

* Maybe some system utilities in rare cases use linking keys for backward compatibility



## References

* https://bohops.com/2018/08/18/abusing-the-com-registry-structure-part-2-loading-techniques-for-evasion-and-persistence/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/registry_event/registry_event_persistence_key_linking.yml))
```yaml
title: Windows Registry Persistence COM Key Linking
id: 9b0f8a61-91b2-464f-aceb-0527e0a45020
status: experimental
description: Detects COM object hijacking via TreatAs subkey
references:
    - https://bohops.com/2018/08/18/abusing-the-com-registry-structure-part-2-loading-techniques-for-evasion-and-persistence/
author: Kutepov Anton, oscd.community
date: 2019/10/23
modified: 2021/09/17
logsource:
    category: registry_event
    product: windows
detection:
    selection:
        EventType: 'CreateKey'  # don't want DeleteKey events
        TargetObject|contains|all: 
            - 'HKU\'
            - 'Classes\CLSID\'
            - '\TreatAs'
    condition: selection
falsepositives:
    - Maybe some system utilities in rare cases use linking keys for backward compatibility
level: medium
tags:
    - attack.persistence
    - attack.t1546.015
```
