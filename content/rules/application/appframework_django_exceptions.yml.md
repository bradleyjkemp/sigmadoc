---
title: "Django Framework Exceptions"
aliases:
  - "/rule/fd435618-981e-4a7c-81f8-f78ce480d616"

tags:
  - attack.initial_access
  - attack.t1190



status: stable



level: medium



date: Sat, 5 Aug 2017 00:56:05 +0200


---

Detects suspicious Django web application framework exceptions that could indicate exploitation attempts

<!--more-->


## Known false-positives

* Application bugs
* Penetration testing



## References

* https://docs.djangoproject.com/en/1.11/ref/exceptions/
* https://docs.djangoproject.com/en/1.11/topics/logging/#django-security


## Raw rule
```yaml
title: Django Framework Exceptions
id: fd435618-981e-4a7c-81f8-f78ce480d616
status: stable
description: Detects suspicious Django web application framework exceptions that could indicate exploitation attempts
author: Thomas Patzke
date: 2017/08/05
modified: 2020/09/01
references:
    - https://docs.djangoproject.com/en/1.11/ref/exceptions/
    - https://docs.djangoproject.com/en/1.11/topics/logging/#django-security
logsource:
    category: application
    product: django
detection:
    keywords:
        - SuspiciousOperation
        # Subclasses of SuspiciousOperation
        - DisallowedHost
        - DisallowedModelAdminLookup
        - DisallowedModelAdminToField
        - DisallowedRedirect
        - InvalidSessionKey
        - RequestDataTooBig
        - SuspiciousFileOperation
        - SuspiciousMultipartForm
        - SuspiciousSession
        - TooManyFieldsSent
        # Further security-related exceptions
        - PermissionDenied
    condition: keywords
falsepositives:
    - Application bugs
    - Penetration testing
level: medium
tags:
    - attack.initial_access
    - attack.t1190
```
