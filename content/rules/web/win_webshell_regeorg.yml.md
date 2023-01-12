---
title: "Webshell ReGeorg Detection Via Web Logs"
aliases:
  - "/rule/2ea44a60-cfda-11ea-87d0-0242ac130003"
ruleid: 2ea44a60-cfda-11ea-87d0-0242ac130003

tags:
  - attack.persistence
  - attack.t1505.003



status: experimental





date: Mon, 3 Aug 2020 12:20:04 +0100


---

Certain strings in the uri_query field when combined with null referer and null user agent can indicate activity associated with the webshell ReGeorg.

<!--more-->


## Known false-positives

* web applications that use the same URL parameters as ReGeorg



## References

* https://community.rsa.com/community/products/netwitness/blog/2019/02/19/web-shells-and-netwitness-part-3
* https://github.com/sensepost/reGeorg


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/web/win_webshell_regeorg.yml))
```yaml
title: Webshell ReGeorg Detection Via Web Logs
id: 2ea44a60-cfda-11ea-87d0-0242ac130003
status: experimental
description: Certain strings in the uri_query field when combined with null referer and null user agent can indicate activity associated with the webshell ReGeorg.
author: Cian Heasley
date: 2020/08/04
modified: 2021/11/23
references:
    - https://community.rsa.com/community/products/netwitness/blog/2019/02/19/web-shells-and-netwitness-part-3
    - https://github.com/sensepost/reGeorg
logsource:
    category: webserver
detection:
    selection:
        cs-uri-query|contains:
            - 'cmd=read'
            - 'connect&target'
            - 'cmd=connect'
            - 'cmd=disconnect'
            - 'cmd=forward'
    filter:
        cs-referer: null
        cs-User-Agent: null
        cs-method: POST
    condition: selection and filter
fields:
    - cs-uri-query
    - cs-referer
    - cs-method
    - cs-User-Agent
falsepositives:
    - web applications that use the same URL parameters as ReGeorg
level: high
tags:
    - attack.persistence
    - attack.t1505.003

```