---
title: "IIS Native-Code Module Command Line Installation"
aliases:
  - "/rule/9465ddf4-f9e4-4ebd-8d98-702df3a93239"


tags:
  - attack.persistence
  - attack.t1505.003



status: test





date: Wed, 16 Jan 2019 23:36:31 +0100


---

Detects suspicious IIS native-code module installations via command line

<!--more-->


## Known false-positives

* Unknown as it may vary from organisation to arganisation how admins use to install IIS modules



## References

* https://researchcenter.paloaltonetworks.com/2018/01/unit42-oilrig-uses-rgdoor-iis-backdoor-targets-middle-east/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_iss_module_install.yml))
```yaml
title: IIS Native-Code Module Command Line Installation
id: 9465ddf4-f9e4-4ebd-8d98-702df3a93239
status: test
description: Detects suspicious IIS native-code module installations via command line
author: Florian Roth
references:
  - https://researchcenter.paloaltonetworks.com/2018/01/unit42-oilrig-uses-rgdoor-iis-backdoor-targets-middle-east/
date: 2012/12/11
modified: 2022/01/07
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\appcmd.exe'
    CommandLine|contains|all:
      - 'install'
      - 'module'
      - '/name:'
  condition: selection
falsepositives:
  - Unknown as it may vary from organisation to arganisation how admins use to install IIS modules
level: medium
tags:
  - attack.persistence
  - attack.t1505.003

```
