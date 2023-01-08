---
title: "ADSelfService Exploitation"
aliases:
  - "/rule/6702b13c-e421-44cc-ab33-42cc25570f11"
ruleid: 6702b13c-e421-44cc-ab33-42cc25570f11



status: experimental





date: Mon, 20 Sep 2021 12:26:46 +0200


---

Detects suspicious access to URLs that was noticed in cases in which attackers exploitated the ADSelfService vulnerability CVE-2021-40539

<!--more-->


## Known false-positives

* Unknown



## References

* https://us-cert.cisa.gov/ncas/alerts/aa21-259a


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/web/web_cve_2021_40539_adselfservice.yml))
```yaml
title: ADSelfService Exploitation
id: 6702b13c-e421-44cc-ab33-42cc25570f11
status: experimental
description: Detects suspicious access to URLs that was noticed in cases in which attackers exploitated the ADSelfService vulnerability CVE-2021-40539
author: Tobias Michalski, Max Altgelt
references:
    - https://us-cert.cisa.gov/ncas/alerts/aa21-259a
date: 2021/09/20
logsource:
    category: webserver
detection:
    selection:
        c-uri|contains:
            - '/help/admin-guide/Reports/ReportGenerate.jsp'
            - '/ServletApi/../RestApi/LogonCustomization'
            - '/ServletApi/../RestAPI/Connection'
    condition: selection
falsepositives:
    - Unknown
level: high

```
