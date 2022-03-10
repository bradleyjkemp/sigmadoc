---
title: "OceanLotus Registry Activity"
aliases:
  - "/rule/4ac5fc44-a601-4c06-955b-309df8c4e9d4"


tags:
  - attack.defense_evasion
  - attack.t1112



status: experimental





date: Sun, 14 Apr 2019 12:01:52 -0500


---

Detects registry keys created in OceanLotus (also known as APT32) attacks

<!--more-->


## Known false-positives

* Unknown



## References

* https://www.welivesecurity.com/2019/03/20/fake-or-fake-keeping-up-with-oceanlotus-decoys/
* https://github.com/eset/malware-ioc/tree/master/oceanlotus


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/registry_event/registry_event_apt_oceanlotus_registry.yml))
```yaml
title: OceanLotus Registry Activity
id: 4ac5fc44-a601-4c06-955b-309df8c4e9d4
status: experimental
description: Detects registry keys created in OceanLotus (also known as APT32) attacks
references:
    - https://www.welivesecurity.com/2019/03/20/fake-or-fake-keeping-up-with-oceanlotus-decoys/
    - https://github.com/eset/malware-ioc/tree/master/oceanlotus
tags:
    - attack.defense_evasion
    - attack.t1112
author: megan201296, Jonhnathan Ribeiro
date: 2019/04/14
modified: 2021/09/17
logsource:
    category: registry_event
    product: windows
detection:
    ioc_1:       
        TargetObject: 'HKCU\SOFTWARE\Classes\CLSID\{E08A0F4B-1F65-4D4D-9A09-BD4625B9C5A1}\Model'
    ioc_2:
        TargetObject|startswith:
            - HKCU\SOFTWARE\App\
            - HKLM\SOFTWARE\App\
        TargetObject|contains:
            - AppXbf13d4ea2945444d8b13e2121cb6b663\
            - AppX70162486c7554f7f80f481985d67586d\
            - AppX37cc7fdccd644b4f85f4b22d5a3f105a\
        TargetObject|endswith:
            - Application
            - DefaultIcon
    selection2:
        TargetObject|startswith:
            - 'HKCU\'
        TargetObject|contains:
            # HKCU\SOFTWARE\Classes\AppXc52346ec40fb4061ad96be0e6cb7d16a\
            - 'Classes\AppXc52346ec40fb4061ad96be0e6cb7d16a\'
            # HKCU\SOFTWARE\Classes\AppX3bbba44c6cae4d9695755183472171e2\
            - 'Classes\AppX3bbba44c6cae4d9695755183472171e2\'
            # HKCU\SOFTWARE\Classes\CLSID\{E3517E26-8E93-458D-A6DF-8030BC80528B}\
            - 'Classes\CLSID\{E3517E26-8E93-458D-A6DF-8030BC80528B}\'
            - 'Classes\CLSID\{E08A0F4B-1F65-4D4D-9A09-BD4625B9C5A1}\Model'
    condition: ioc_1 or ioc_2 or selection2
falsepositives:
    - Unknown
level: critical

```