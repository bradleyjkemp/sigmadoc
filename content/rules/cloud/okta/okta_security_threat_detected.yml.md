---
title: "Okta Security Threat Detected"
aliases:
  - "/rule/5c82f0b9-3c6d-477f-a318-0e14a1df73e0"




status: experimental





date: Sun, 12 Sep 2021 20:33:27 -0500


---

Detects when an security threat is detected in Okta.

<!--more-->


## Known false-positives

* None



## References

* https://okta.github.io/okta-help/en/prod/Content/Topics/Security/threat-insight/configure-threatinsight-system-log.htm
* https://developer.okta.com/docs/reference/api/system-log/
* https://developer.okta.com/docs/reference/api/event-types/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/cloud/okta/okta_security_threat_detected.yml))
```yaml
title: Okta Security Threat Detected
id: 5c82f0b9-3c6d-477f-a318-0e14a1df73e0
description: Detects when an security threat is detected in Okta.
author: Austin Songer @austinsonger
status: experimental
date: 2021/09/12
modified: 2021/09/22
references:
    - https://okta.github.io/okta-help/en/prod/Content/Topics/Security/threat-insight/configure-threatinsight-system-log.htm
    - https://developer.okta.com/docs/reference/api/system-log/
    - https://developer.okta.com/docs/reference/api/event-types/
logsource:
  product: okta
  service: okta
detection:
    selection:
        eventtype: security.threat.detected
    condition: selection
level: medium
falsepositives:
 - None

```
