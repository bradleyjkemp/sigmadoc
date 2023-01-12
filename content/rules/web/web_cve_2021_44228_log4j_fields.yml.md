---
title: "Log4j RCE CVE-2021-44228 in Fields"
aliases:
  - "/rule/9be472ed-893c-4ec0-94da-312d2765f654"
ruleid: 9be472ed-893c-4ec0-94da-312d2765f654

tags:
  - attack.initial_access
  - attack.t1190



status: experimental





date: Fri, 10 Dec 2021 16:01:43 +0100


---

Detects exploitation attempt against log4j RCE vulnerability reported as CVE-2021-44228 in different header fields found in web server logs (Log4Shell)

<!--more-->


## Known false-positives

* Vulnerability scanning



## References

* https://www.lunasec.io/docs/blog/log4j-zero-day/
* https://news.ycombinator.com/item?id=29504755
* https://github.com/tangxiaofeng7/apache-log4j-poc
* https://gist.github.com/Neo23x0/e4c8b03ff8cdf1fa63b7d15db6e3860b
* https://github.com/YfryTchsGD/Log4jAttackSurface
* https://twitter.com/shutingrz/status/1469255861394866177?s=21


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/web/web_cve_2021_44228_log4j_fields.yml))
```yaml
title: Log4j RCE CVE-2021-44228 in Fields
id: 9be472ed-893c-4ec0-94da-312d2765f654
status: experimental
description: Detects exploitation attempt against log4j RCE vulnerability reported as CVE-2021-44228 in different header fields found in web server logs (Log4Shell)
author: Florian Roth
date: 2021/12/10
modified: 2022/02/06
references:
   - https://www.lunasec.io/docs/blog/log4j-zero-day/
   - https://news.ycombinator.com/item?id=29504755
   - https://github.com/tangxiaofeng7/apache-log4j-poc
   - https://gist.github.com/Neo23x0/e4c8b03ff8cdf1fa63b7d15db6e3860b
   - https://github.com/YfryTchsGD/Log4jAttackSurface
   - https://twitter.com/shutingrz/status/1469255861394866177?s=21
tags:
   - attack.initial_access
   - attack.t1190
logsource:
   category: webserver
detection:
   selection1:
      cs-User-Agent|contains:
         - '${jndi:ldap:/'
         - '${jndi:rmi:/'
         - '${jndi:ldaps:/'
         - '${jndi:dns:/'
         - '/$%7bjndi:'
         - '%24%7bjndi:'
         - '$%7Bjndi:'
         - '%2524%257Bjndi'
         - '%2F%252524%25257Bjndi%3A'
         - '${jndi:${lower:'
         - '${::-j}${'
         - '${jndi:nis'
         - '${jndi:nds'
         - '${jndi:corba'
         - '${jndi:iiop'
         - 'Reference Class Name: foo'
         - '${${env:BARFOO:-j}'
         - '${::-l}${::-d}${::-a}${::-p}'
         - '${base64:JHtqbmRp'
         - '${${env:ENV_NAME:-j}ndi${env:ENV_NAME:-:}$'
         - '${${lower:j}ndi:'
         - '${${upper:j}ndi:'
         - '${${::-j}${::-n}${::-d}${::-i}:'
   selection2:         
      user-agent|contains:
         - '${jndi:ldap:/'
         - '${jndi:rmi:/'
         - '${jndi:ldaps:/'
         - '${jndi:dns:/'
         - '/$%7bjndi:'
         - '%24%7bjndi:'
         - '$%7Bjndi:'
         - '%2524%257Bjndi'
         - '%2F%252524%25257Bjndi%3A'
         - '${jndi:${lower:'
         - '${::-j}${'
         - '${jndi:nis'
         - '${jndi:nds'
         - '${jndi:corba'
         - '${jndi:iiop'
         - 'Reference Class Name: foo'
         - '${${env:BARFOO:-j}'
         - '${::-l}${::-d}${::-a}${::-p}'
         - '${base64:JHtqbmRp'
         - '${${env:ENV_NAME:-j}ndi${env:ENV_NAME:-:}$'
         - '${${lower:j}ndi:'
         - '${${upper:j}ndi:'
         - '${${::-j}${::-n}${::-d}${::-i}:'
   selection3:
      cs-uri|contains:
         - '${jndi:ldap:/'
         - '${jndi:rmi:/'
         - '${jndi:ldaps:/'
         - '${jndi:dns:/'
         - '/$%7bjndi:'
         - '%24%7bjndi:'
         - '$%7Bjndi:'
         - '%2524%257Bjndi'
         - '%2F%252524%25257Bjndi%3A'
         - '${jndi:${lower:'
         - '${::-j}${'
         - '${jndi:nis'
         - '${jndi:nds'
         - '${jndi:corba'
         - '${jndi:iiop'
         - 'Reference Class Name: foo'
         - '${${env:BARFOO:-j}'
         - '${::-l}${::-d}${::-a}${::-p}'
         - '${base64:JHtqbmRp'
         - '${${env:ENV_NAME:-j}ndi${env:ENV_NAME:-:}$'
         - '${${lower:j}ndi:'
         - '${${upper:j}ndi:'
         - '${${::-j}${::-n}${::-d}${::-i}:'
   selection4:
      cs-referer|contains:
         - '${jndi:ldap:/'
         - '${jndi:rmi:/'
         - '${jndi:ldaps:/'
         - '${jndi:dns:/'
         - '/$%7bjndi:'
         - '%24%7bjndi:'
         - '$%7Bjndi:'
         - '%2524%257Bjndi'
         - '%2F%252524%25257Bjndi%3A'
         - '${jndi:${lower:'
         - '${::-j}${'
         - '${jndi:nis'
         - '${jndi:nds'
         - '${jndi:corba'
         - '${jndi:iiop'
         - 'Reference Class Name: foo'
         - '${${env:BARFOO:-j}'
         - '${::-l}${::-d}${::-a}${::-p}'
         - '${base64:JHtqbmRp'
         - '${${env:ENV_NAME:-j}ndi${env:ENV_NAME:-:}$'
         - '${${lower:j}ndi:'
         - '${${upper:j}ndi:'
         - '${${::-j}${::-n}${::-d}${::-i}:'
   condition: 1 of selection*
falsepositives:
    - Vulnerability scanning
level: high

```