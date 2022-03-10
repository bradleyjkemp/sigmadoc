---
title: "Linux Webshell Indicators"
aliases:
  - "/rule/818f7b24-0fba-4c49-a073-8b755573b9c7"


tags:
  - attack.persistence
  - attack.t1505.003



status: experimental





date: Fri, 15 Oct 2021 14:39:32 +0200


---

Detects suspicious sub processes of web server processes

<!--more-->


## Known false-positives

* Web applications that invoke Linux command line tools



## References

* https://www.acunetix.com/blog/articles/web-shells-101-using-php-introduction-web-shells-part-2/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/linux/process_creation/proc_creation_lnx_webshell_detection.yml))
```yaml
title: Linux Webshell Indicators
id: 818f7b24-0fba-4c49-a073-8b755573b9c7
status: experimental
description: Detects suspicious sub processes of web server processes
references:
   - https://www.acunetix.com/blog/articles/web-shells-101-using-php-introduction-web-shells-part-2/
date: 2021/10/15
author: Florian Roth
tags:
    - attack.persistence
    - attack.t1505.003
logsource:
   product: linux
   category: process_creation
detection:
   selection_general:
      ParentImage|endswith:
         - '/httpd'
         - '/lighttpd'
         - '/nginx'
         - '/apache2'
         - '/node'
   selection_tomcat:
      ParentCommandLine|contains|all:
         - '/bin/java'
         - 'tomcat'
   selection_websphere:  # ? just guessing 
      ParentCommandLine|contains|all:
         - '/bin/java'
         - 'websphere'
   selection_sub_processes:
      Image|endswith: 
         - '/whoami'
         - '/ifconfig'
         - '/usr/bin/ip'
         - '/bin/uname'
   condition: selection_sub_processes and ( selection_general or selection_tomcat )
falsepositives:
   - Web applications that invoke Linux command line tools 
level: critical


```
