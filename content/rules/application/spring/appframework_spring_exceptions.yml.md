---
title: "Spring Framework Exceptions"
aliases:
  - "/rule/ae48ab93-45f7-4051-9dfe-5d30a3f78e33"
ruleid: ae48ab93-45f7-4051-9dfe-5d30a3f78e33

tags:
  - attack.initial_access
  - attack.t1190



status: stable





date: Sun, 6 Aug 2017 23:21:53 +0200


---

Detects suspicious Spring framework exceptions that could indicate exploitation attempts

<!--more-->


## Known false-positives

* Application bugs
* Penetration testing



## References

* https://docs.spring.io/spring-security/site/docs/current/apidocs/overview-tree.html


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/application/spring/appframework_spring_exceptions.yml))
```yaml
title: Spring Framework Exceptions
id: ae48ab93-45f7-4051-9dfe-5d30a3f78e33
status: stable
description: Detects suspicious Spring framework exceptions that could indicate exploitation attempts
author: Thomas Patzke
date: 2017/08/06
modified: 2020/09/01
references:
    - https://docs.spring.io/spring-security/site/docs/current/apidocs/overview-tree.html
logsource:
    category: application
    product: spring
detection:
    keywords:
        - AccessDeniedException
        - CsrfException
        - InvalidCsrfTokenException
        - MissingCsrfTokenException
        - CookieTheftException
        - InvalidCookieException
        - RequestRejectedException
    condition: keywords
falsepositives:
    - Application bugs
    - Penetration testing
level: medium
tags:
    - attack.initial_access
    - attack.t1190
```
