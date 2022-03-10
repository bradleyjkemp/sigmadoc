---
title: "Sitecore Pre-Auth RCE CVE-2021-42237"
aliases:
  - "/rule/20c6ed1c-f7f0-4ea3-aa65-4f198e6acb0f"


tags:
  - attack.initial_access
  - attack.t1190



status: experimental





date: Wed, 17 Nov 2021 19:01:35 +0100


---

Detects exploitation attempts of Sitecore Experience Platform Pre-Auth RCE CVE-2021-42237 found in Report.ashx

<!--more-->


## Known false-positives

* Vulnerability Scanning/Pentesting



## References

* https://blog.assetnote.io/2021/11/02/sitecore-rce/
* https://support.sitecore.com/kb?id=kb_article_view&sysparm_article=KB1000776


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/web/web_cve_2021_42237_sitecore_report_ashx.yml))
```yaml
title: Sitecore Pre-Auth RCE CVE-2021-42237
id: 20c6ed1c-f7f0-4ea3-aa65-4f198e6acb0f
status: experimental
description: Detects exploitation attempts of Sitecore Experience Platform Pre-Auth RCE CVE-2021-42237 found in Report.ashx
author: Florian Roth
date: 2021/11/17
references:
    - https://blog.assetnote.io/2021/11/02/sitecore-rce/
    - https://support.sitecore.com/kb?id=kb_article_view&sysparm_article=KB1000776
tags:
    - attack.initial_access
    - attack.t1190
logsource:
    category: webserver
detection:
    selection:
        cs-method: 'POST'
        c-uri|contains: '/sitecore/shell/ClientBin/Reporting/Report.ashx'
        sc-status: 200
    condition: selection
falsepositives:
    - Vulnerability Scanning/Pentesting
level: high

```
