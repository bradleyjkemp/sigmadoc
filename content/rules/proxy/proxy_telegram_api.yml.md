---
title: "Telegram API Access"
aliases:
  - "/rule/b494b165-6634-483d-8c47-2026a6c52372"


tags:
  - attack.defense_evasion
  - attack.command_and_control
  - attack.t1071.001
  - attack.t1102.002



status: test





date: Tue, 5 Jun 2018 16:25:43 +0200


---

Detects suspicious requests to Telegram API without the usual Telegram User-Agent

<!--more-->


## Known false-positives

* Legitimate use of Telegram bots in the company



## References

* https://researchcenter.paloaltonetworks.com/2018/03/unit42-telerat-another-android-trojan-leveraging-telegrams-bot-api-to-target-iranian-users/
* https://blog.malwarebytes.com/threat-analysis/2016/11/telecrypt-the-ransomware-abusing-telegram-api-defeated/
* https://www.welivesecurity.com/2016/12/13/rise-telebots-analyzing-disruptive-killdisk-attacks/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/proxy/proxy_telegram_api.yml))
```yaml
title: Telegram API Access
id: b494b165-6634-483d-8c47-2026a6c52372
status: test
description: Detects suspicious requests to Telegram API without the usual Telegram User-Agent
author: Florian Roth
references:
  - https://researchcenter.paloaltonetworks.com/2018/03/unit42-telerat-another-android-trojan-leveraging-telegrams-bot-api-to-target-iranian-users/
  - https://blog.malwarebytes.com/threat-analysis/2016/11/telecrypt-the-ransomware-abusing-telegram-api-defeated/
  - https://www.welivesecurity.com/2016/12/13/rise-telebots-analyzing-disruptive-killdisk-attacks/
date: 2018/06/05
modified: 2021/11/27
logsource:
  category: proxy
detection:
  selection:
    r-dns:
      - 'api.telegram.org'        # Often used by Bots
  filter:
    c-useragent|contains:
            # Used https://core.telegram.org/bots/samples for this list
      - 'Telegram'
      - 'Bot'
  condition: selection and not filter
fields:
  - ClientIP
  - c-uri
  - c-useragent
falsepositives:
  - Legitimate use of Telegram bots in the company
level: medium
tags:
  - attack.defense_evasion
  - attack.command_and_control
  - attack.t1071.001
  - attack.t1102.002

```
