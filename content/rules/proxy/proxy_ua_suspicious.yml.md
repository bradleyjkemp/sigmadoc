---
title: "Suspicious User Agent"
aliases:
  - "/rule/7195a772-4b3f-43a4-a210-6a003d65caa1"


tags:
  - attack.command_and_control
  - attack.t1071.001



status: experimental





date: Sat, 8 Jul 2017 09:59:05 -0600


---

Detects suspicious malformed user agent strings in proxy logs

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/fastly/waf_testbed/blob/master/templates/default/scanners-user-agents.data.erb


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/proxy/proxy_ua_suspicious.yml))
```yaml
title: Suspicious User Agent
id: 7195a772-4b3f-43a4-a210-6a003d65caa1
status: experimental
description: Detects suspicious malformed user agent strings in proxy logs
author: Florian Roth
date: 2017/07/08
modified: 2021/08/09
references:
    - https://github.com/fastly/waf_testbed/blob/master/templates/default/scanners-user-agents.data.erb
logsource:
    category: proxy
detection:
    selection1:
      c-useragent|startswith:
        - 'user-agent'  # User-Agent: User-Agent:
        - 'Mozilla/3.0 '
        - 'Mozilla/2.0 '
        - 'Mozilla/1.0 '
        - 'Mozilla '  # missing slash
        - ' Mozilla/'  # leading space
        - 'Mozila/'  # single 'l'
        - 'Mozilla/4.0 (compatible; MSIE 6.0; MS Web Services Client Protocol'  # https://twitter.com/NtSetDefault/status/1303643299509567488
    selection2:
      c-useragent|contains:
        - ' (compatible;MSIE '  # typical typo - missing space
        - '.0;Windows NT '  # typical typo - missing space
    selection3:
      c-useragent:
        - '_'
        - 'CertUtil URL Agent'  # https://twitter.com/stvemillertime/status/985150675527974912
        - 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:60.0)'  # CobaltStrike Beacon https://unit42.paloaltonetworks.com/tracking-oceanlotus-new-downloader-kerrdown/
        - 'Mozilla/5.0 (Windows NT 6.3; WOW64; rv:28.0) Gecko/20100101 Firefox/28.0'  # used by APT28 malware https://threatvector.cylance.com/en_us/home/inside-the-apt28-dll-backdoor-blitz.html
        - 'HTTPS'  # https://twitter.com/stvemillertime/status/1204437531632250880
    falsepositives:
        c-useragent: 'Mozilla/3.0 * Acrobat *'  # Acrobat with linked content
    condition: ( selection1 or selection2 or selection3 ) and not falsepositives
fields:
    - ClientIP
    - c-uri
    - c-useragent
falsepositives:
    - Unknown
level: high
tags:
    - attack.command_and_control
    - attack.t1071.001
```