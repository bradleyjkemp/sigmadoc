---
title: "Confluence Exploitation CVE-2019-3398"
aliases:
  - "/rule/e9bc39ae-978a-4e49-91ab-5bd481fc668b"


tags:
  - attack.initial_access
  - attack.t1190



status: test





date: Fri, 5 Jun 2020 13:18:03 -0400


---

Detects the exploitation of the Confluence vulnerability described in CVE-2019-3398

<!--more-->


## Known false-positives

* Unknown



## References

* https://devcentral.f5.com/s/articles/confluence-arbitrary-file-write-via-path-traversal-cve-2019-3398-34181


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/web/web_cve_2019_3398_confluence.yml))
```yaml
title: Confluence Exploitation CVE-2019-3398
id: e9bc39ae-978a-4e49-91ab-5bd481fc668b
status: test
description: Detects the exploitation of the Confluence vulnerability described in CVE-2019-3398
author: Florian Roth
references:
  - https://devcentral.f5.com/s/articles/confluence-arbitrary-file-write-via-path-traversal-cve-2019-3398-34181
date: 2020/05/26
modified: 2021/11/27
logsource:
  category: webserver
detection:
  selection:
    cs-method: 'POST'
    c-uri|contains|all:
      - '/upload.action'
      - 'filename=../../../../'
  condition: selection
fields:
  - c-ip
  - c-dns
falsepositives:
  - Unknown
level: critical
tags:
  - attack.initial_access
  - attack.t1190

```