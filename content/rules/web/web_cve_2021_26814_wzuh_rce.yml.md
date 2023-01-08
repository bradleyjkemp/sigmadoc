---
title: "Exploitation of CVE-2021-26814 in Wazuh"
aliases:
  - "/rule/b9888738-29ed-4c54-96a4-f38c57b84bb3"
ruleid: b9888738-29ed-4c54-96a4-f38c57b84bb3

tags:
  - attack.initial_access
  - attack.t1190
  - cve.2021.21978
  - cve.2021.26814



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects the exploitation of the Wazuh RCE vulnerability described in CVE-2021-26814

<!--more-->


## Known false-positives

* None



## References

* https://github.com/WickdDavid/CVE-2021-26814/blob/main/PoC.py


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/web/web_cve_2021_26814_wzuh_rce.yml))
```yaml
title: Exploitation of CVE-2021-26814 in Wazuh
id: b9888738-29ed-4c54-96a4-f38c57b84bb3
status: experimental
description: Detects the exploitation of the Wazuh RCE vulnerability described in CVE-2021-26814
author: Florian Roth
date: 2021/05/22
references:
    - https://github.com/WickdDavid/CVE-2021-26814/blob/main/PoC.py
logsource:
    category: webserver
detection:
    selection:
        c-uri|contains: '/manager/files?path=etc/lists/../../../../..'
    condition: selection
fields:
    - c-ip
    - c-dns
falsepositives:
    - None
level: high
tags:
    - attack.initial_access
    - attack.t1190
    - cve.2021.21978
    - cve.2021.26814
```
