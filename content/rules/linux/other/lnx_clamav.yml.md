---
title: "Relevant ClamAV Message"
aliases:
  - "/rule/36aa86ca-fd9d-4456-814e-d3b1b8e1e0bb"
ruleid: 36aa86ca-fd9d-4456-814e-d3b1b8e1e0bb

tags:
  - attack.resource_development
  - attack.t1588.001



status: stable





date: Wed, 1 Mar 2017 10:00:03 +0100


---

Detects relevant ClamAV messages

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/ossec/ossec-hids/blob/master/etc/rules/clam_av_rules.xml


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/linux/other/lnx_clamav.yml))
```yaml
title: Relevant ClamAV Message
id: 36aa86ca-fd9d-4456-814e-d3b1b8e1e0bb
status: stable
description: Detects relevant ClamAV messages
author: Florian Roth
date: 2017/03/01
references:
    - https://github.com/ossec/ossec-hids/blob/master/etc/rules/clam_av_rules.xml
logsource:
    product: linux
    service: clamav
detection:
    keywords:
        - 'Trojan*FOUND'
        - 'VirTool*FOUND'
        - 'Webshell*FOUND'
        - 'Rootkit*FOUND'
        - 'Htran*FOUND'
    condition: keywords
falsepositives:
    - Unknown
level: high
tags:
    - attack.resource_development
    - attack.t1588.001
```
