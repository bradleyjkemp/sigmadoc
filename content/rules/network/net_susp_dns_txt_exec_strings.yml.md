---
title: "DNS TXT Answer with Possible Execution Strings"
aliases:
  - "/rule/8ae51330-899c-4641-8125-e39f2e07da72"


tags:
  - attack.command_and_control
  - attack.t1071.004



status: test





date: Wed, 8 Aug 2018 15:51:56 +0200


---

Detects strings used in command execution in DNS TXT Answer

<!--more-->


## Known false-positives

* Unknown



## References

* https://twitter.com/stvemillertime/status/1024707932447854592
* https://github.com/samratashok/nishang/blob/master/Backdoors/DNS_TXT_Pwnage.ps1


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/network/net_susp_dns_txt_exec_strings.yml))
```yaml
title: DNS TXT Answer with Possible Execution Strings
id: 8ae51330-899c-4641-8125-e39f2e07da72
status: test
description: Detects strings used in command execution in DNS TXT Answer
author: Markus Neis
references:
  - https://twitter.com/stvemillertime/status/1024707932447854592
  - https://github.com/samratashok/nishang/blob/master/Backdoors/DNS_TXT_Pwnage.ps1
date: 2018/08/08
modified: 2021/11/27
logsource:
  category: dns
detection:
  selection:
    record_type: 'TXT'
    answer|contains:
      - 'IEX'
      - 'Invoke-Expression'
      - 'cmd.exe'
  condition: selection
falsepositives:
  - Unknown
level: high
tags:
  - attack.command_and_control
  - attack.t1071.004

```
