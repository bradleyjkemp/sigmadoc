---
title: "Linux Doas Conf File Creation"
aliases:
  - "/rule/00eee2a5-fdb0-4746-a21d-e43fbdea5681"


tags:
  - attack.privilege_escalation
  - attack.t1548



status: stable





date: Thu, 20 Jan 2022 09:50:41 +0700


---

Detects the creation of doas.conf file in linux host platform.

<!--more-->


## Known false-positives

* Unlikely



## References

* https://research.splunk.com/endpoint/linux_doas_conf_file_creation/
* https://www.makeuseof.com/how-to-install-and-use-doas/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/linux/file_create/lnx_doas_conf_creation.yml))
```yaml
title: Linux Doas Conf File Creation
id: 00eee2a5-fdb0-4746-a21d-e43fbdea5681
status: stable
description: Detects the creation of doas.conf file in linux host platform.
references:
    - https://research.splunk.com/endpoint/linux_doas_conf_file_creation/
    - https://www.makeuseof.com/how-to-install-and-use-doas/
author: Sittikorn S, Teoderick Contreras
date: 2022/01/20
tags:
    - attack.privilege_escalation
    - attack.t1548
logsource:
    product: linux
    category: file_create
detection:
    selection:
        TargetFilename|endswith: '/etc/doas.conf'
    condition: selection
falsepositives:
    - Unlikely
level: medium

```
