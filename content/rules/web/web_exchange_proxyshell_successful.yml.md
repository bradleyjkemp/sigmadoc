---
title: "Successful Exchange ProxyShell Attack"
aliases:
  - "/rule/992be1eb-e5da-437e-9a54-6d13b57bb4d8"
ruleid: 992be1eb-e5da-437e-9a54-6d13b57bb4d8

tags:
  - attack.initial_access



status: experimental





date: Mon, 9 Aug 2021 17:57:34 +0200


---

Detects URP patterns and status codes that indicate a successful ProxyShell exploitation attack against Exchange servers

<!--more-->


## Known false-positives

* Unknown



## References

* https://youtu.be/5mqid-7zp8k?t=2231
* https://blog.orange.tw/2021/08/proxylogon-a-new-attack-surface-on-ms-exchange-part-1.html
* https://peterjson.medium.com/reproducing-the-proxyshell-pwn2own-exploit-49743a4ea9a1


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/web/web_exchange_proxyshell_successful.yml))
```yaml
title: Successful Exchange ProxyShell Attack
id: 992be1eb-e5da-437e-9a54-6d13b57bb4d8
status: experimental
description: Detects URP patterns and status codes that indicate a successful ProxyShell exploitation attack against Exchange servers
references:
    - https://youtu.be/5mqid-7zp8k?t=2231
    - https://blog.orange.tw/2021/08/proxylogon-a-new-attack-surface-on-ms-exchange-part-1.html
    - https://peterjson.medium.com/reproducing-the-proxyshell-pwn2own-exploit-49743a4ea9a1
author: Florian Roth, Rich Warren
date: 2021/08/09
tags:
    - attack.initial_access
logsource:
    category: webserver
detection:
    selection_auto:
        c-uri|contains: '/autodiscover.json'
    selection_uri:
        c-uri|contains:
            - '/powershell'
            - '/mapi/nspi'
            - '/EWS'
            - 'X-Rps-CAT'
    selection_success:
        sc-status: 
            - 200
            - 301
    condition: selection_auto and selection_uri and selection_success
falsepositives:
    - Unknown
level: critical
```
