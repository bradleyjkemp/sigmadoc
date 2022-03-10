---
title: "CVE-2020-10148 SolarWinds Orion API Auth Bypass"
aliases:
  - "/rule/5a35116f-43bc-4901-b62d-ef131f42a9af"


tags:
  - attack.initial_access
  - attack.t1190



status: test





date: Sun, 27 Dec 2020 17:34:49 +0545


---

Detects CVE-2020-10148 SolarWinds Orion API authentication bypass attempts

<!--more-->


## Known false-positives

* Unknown



## References

* https://kb.cert.org/vuls/id/843464


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/web/web_solarwinds_cve_2020_10148.yml))
```yaml
title: CVE-2020-10148 SolarWinds Orion API Auth Bypass
id: 5a35116f-43bc-4901-b62d-ef131f42a9af
status: test
description: Detects CVE-2020-10148 SolarWinds Orion API authentication bypass attempts
author: Bhabesh Raj
references:
  - https://kb.cert.org/vuls/id/843464
date: 2020/12/27
modified: 2022/01/07
logsource:
  category: webserver
detection:
  selection:
    c-uri|contains:
      - 'WebResource.axd'
      - 'ScriptResource.axd'
      - 'i18n.ashx'
      - 'Skipi18n'
  valid_request_1:
    c-uri|contains: 'Orion/Skipi18n/Profiler/'
  valid_request_2:
    c-uri|contains:
      - 'css.i18n.ashx'
      - 'js.i18n.ashx'
  condition: selection and not valid_request_1 and not valid_request_2
falsepositives:
  - Unknown
level: critical
tags:
  - attack.initial_access
  - attack.t1190

```