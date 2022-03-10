---
title: "Powershell Exfiltration Over SMTP"
aliases:
  - "/rule/9a7afa56-4762-43eb-807d-c3dc9ffe211b"


tags:
  - attack.exfiltration
  - attack.t1048.003



status: experimental





date: Sat, 8 Jan 2022 09:17:56 +0100


---

Adversaries may steal data by exfiltrating it over an un-encrypted network protocol other than that of the existing command and control channel.
The data may also be sent to an alternate network location from the main command and control server. 


<!--more-->


## Known false-positives

* legitim script



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1048.003/T1048.003.md#atomic-test-5---exfiltration-over-alternative-protocol---smtp
* https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/send-mailmessage?view=powershell-7.2
* https://www.ietf.org/rfc/rfc2821.txt


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/powershell/powershell_script/posh_ps_send_mailmessage.yml))
```yaml
title: Powershell Exfiltration Over SMTP
id: 9a7afa56-4762-43eb-807d-c3dc9ffe211b
status: experimental
description: |
  Adversaries may steal data by exfiltrating it over an un-encrypted network protocol other than that of the existing command and control channel.
  The data may also be sent to an alternate network location from the main command and control server. 
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1048.003/T1048.003.md#atomic-test-5---exfiltration-over-alternative-protocol---smtp
    - https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/send-mailmessage?view=powershell-7.2
    - https://www.ietf.org/rfc/rfc2821.txt
author: frack113
date: 2022/01/07
logsource:
    product: windows
    category: ps_script
    definition: 'Script block logging must be enabled'
detection:
    selection_cmdlet:
        ScriptBlockText|contains: Send-MailMessage
    condition: selection_cmdlet
falsepositives:
    - legitim script
level: medium
tags:
    - attack.exfiltration
    - attack.t1048.003

```
