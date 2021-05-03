---
title: "Telegram Bot API Request"
aliases:
  - "/rule/c64c5175-5189-431b-a55e-6d9882158251"

tags:
  - attack.command_and_control
  - attack.t1102
  - attack.t1102.002



date: Tue, 5 Jun 2018 16:25:43 +0200


---

Detects suspicious DNS queries to api.telegram.org used by Telegram Bots of any kind

<!--more-->


## Known false-positives

* Legitimate use of Telegram bots in the company



## References

* https://core.telegram.org/bots/faq
* https://researchcenter.paloaltonetworks.com/2018/03/unit42-telerat-another-android-trojan-leveraging-telegrams-bot-api-to-target-iranian-users/
* https://blog.malwarebytes.com/threat-analysis/2016/11/telecrypt-the-ransomware-abusing-telegram-api-defeated/
* https://www.welivesecurity.com/2016/12/13/rise-telebots-analyzing-disruptive-killdisk-attacks/


## Raw rule
```yaml
title: Telegram Bot API Request
id: c64c5175-5189-431b-a55e-6d9882158251
status: experimental
description: Detects suspicious DNS queries to api.telegram.org used by Telegram Bots of any kind
author: Florian Roth
date: 2018/06/05
modified: 2020/08/27
references:
    - https://core.telegram.org/bots/faq
    - https://researchcenter.paloaltonetworks.com/2018/03/unit42-telerat-another-android-trojan-leveraging-telegrams-bot-api-to-target-iranian-users/
    - https://blog.malwarebytes.com/threat-analysis/2016/11/telecrypt-the-ransomware-abusing-telegram-api-defeated/
    - https://www.welivesecurity.com/2016/12/13/rise-telebots-analyzing-disruptive-killdisk-attacks/
logsource:
    category: dns
detection:
    selection:
        query:
            - 'api.telegram.org'   # Telegram Bot API Request https://core.telegram.org/bots/faq
    condition: selection
falsepositives:
    - Legitimate use of Telegram bots in the company
level: medium
tags:
    - attack.command_and_control
    - attack.t1102 # an old one
    - attack.t1102.002
```
