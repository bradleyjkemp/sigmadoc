---
title: "CVE-2021-33766 Exchange ProxyToken Exploitation"
aliases:
  - "/rule/56973b50-3382-4b56-bdf5-f51a3183797a"
ruleid: 56973b50-3382-4b56-bdf5-f51a3183797a

tags:
  - attack.initial_access
  - attack.t1190



status: experimental





date: Mon, 30 Aug 2021 15:47:53 +0200


---

Detects the exploitation of Microsoft Exchange ProxyToken vulnerability as described in CVE-2021-33766

<!--more-->


## Known false-positives

* Unknown



## References

* https://www.zerodayinitiative.com/blog/2021/8/30/proxytoken-an-authentication-bypass-in-microsoft-exchange-server


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/web/web_cve_2021_33766_msexchange_proxytoken.yml))
```yaml
title: CVE-2021-33766 Exchange ProxyToken Exploitation
id: 56973b50-3382-4b56-bdf5-f51a3183797a
status: experimental
description: Detects the exploitation of Microsoft Exchange ProxyToken vulnerability as described in CVE-2021-33766 
author: Florian Roth, Max Altgelt, Christian Burkard
date: 2021/08/30
references:
    - https://www.zerodayinitiative.com/blog/2021/8/30/proxytoken-an-authentication-bypass-in-microsoft-exchange-server
tags:
    - attack.initial_access
    - attack.t1190
logsource:
    category: webserver
detection:
    selection1:
        cs-method: 'POST'
        c-uri|contains|all:
            - '/ecp/'
            - '/RulesEditor/InboxRules.svc/NewObject'
        sc-status: 500
    selection2:
        c-uri|contains|all: 
            - 'SecurityToken='
            - '/ecp/'
        sc-status: 500
    condition: selection1 or selection2
fields:
    - c-ip
    - c-dns
falsepositives:
    - Unknown
level: critical

```
