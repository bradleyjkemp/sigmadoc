---
title: "Cisco ASA FTD Exploit CVE-2020-3452"
aliases:
  - "/rule/aba47adc-4847-4970-95c1-61dce62a8b29"
ruleid: aba47adc-4847-4970-95c1-61dce62a8b29

tags:
  - attack.t1190
  - attack.initial_access
  - cve.2020.3452



status: experimental





date: Thu, 7 Jan 2021 12:27:31 +0100


---

Detects exploitation attempts on Cisco ASA FTD systems exploiting CVE-2020-3452 with a status code of 200 (sccessful exploitation)

<!--more-->


## Known false-positives

* Unknown



## References

* https://twitter.com/aboul3la/status/1286012324722155525
* https://github.com/darklotuskdb/CISCO-CVE-2020-3452-Scanner-Exploiter


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/web/web_cve_2020_3452_cisco_asa_ftd.yml))
```yaml
title: Cisco ASA FTD Exploit CVE-2020-3452
id: aba47adc-4847-4970-95c1-61dce62a8b29
status: experimental
description: Detects exploitation attempts on Cisco ASA FTD systems exploiting CVE-2020-3452 with a status code of 200 (sccessful exploitation)
author: Florian Roth
date: 2021/01/07
references:
    - https://twitter.com/aboul3la/status/1286012324722155525
    - https://github.com/darklotuskdb/CISCO-CVE-2020-3452-Scanner-Exploiter
logsource:
    category: webserver
detection:
    selection_endpoint:
        c-uri|contains:
            - '+CSCOT+/translation-table'
            - '+CSCOT+/oem-customization'
    selection_path_select:
        c-uri|contains:
            - '&textdomain=/'
            - '&textdomain=%'
            - '&name=/'
            - '&name=%'
    select_status_code:
        sc-status: 200
    condition: selection_endpoint and selection_path_select and select_status_code
fields:
    - c-ip
    - c-dns
falsepositives:
    - Unknown
level: high
tags:
    - attack.t1190
    - attack.initial_access
    - cve.2020.3452
```
