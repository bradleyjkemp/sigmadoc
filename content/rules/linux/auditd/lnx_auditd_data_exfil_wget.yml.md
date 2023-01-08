---
title: "Data Exfiltration with Wget"
aliases:
  - "/rule/cb39d16b-b3b6-4a7a-8222-1cf24b686ffc"
ruleid: cb39d16b-b3b6-4a7a-8222-1cf24b686ffc

tags:
  - attack.exfiltration
  - attack.t1048.003



status: experimental





date: Thu, 18 Nov 2021 18:03:17 +0100


---

Detects attempts to post the file with the usage of wget utility. The adversary can bypass the permission restriction with the misconfigured sudo permission for wget utility which could allow them to read files like /etc/shadow.

<!--more-->


## Known false-positives

* legitimate usage of wget utility to post a file



## References

* https://attack.mitre.org/tactics/TA0010/
* https://linux.die.net/man/1/wget
* https://gtfobins.github.io/gtfobins/wget/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/linux/auditd/lnx_auditd_data_exfil_wget.yml))
```yaml
title: Data Exfiltration with Wget
id: cb39d16b-b3b6-4a7a-8222-1cf24b686ffc
description: Detects attempts to post the file with the usage of wget utility. The adversary can bypass the permission restriction with the misconfigured sudo permission for wget utility which could allow them to read files like /etc/shadow.
author: 'Pawel Mazur'
status: experimental
date: 2021/11/18
references:
   - https://attack.mitre.org/tactics/TA0010/
   - https://linux.die.net/man/1/wget
   - https://gtfobins.github.io/gtfobins/wget/
logsource:
   product: linux
   service: auditd
detection:
   wget:
       type: EXECVE
       a0: wget
       a1|startswith: '--post-file='
   condition: wget
tags:
   - attack.exfiltration
   - attack.t1048.003
falsepositives:
   - legitimate usage of wget utility to post a file
level: medium
```
