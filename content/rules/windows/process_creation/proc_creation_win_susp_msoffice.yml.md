---
title: "Malicious Payload Download via Office Binaries"
aliases:
  - "/rule/0c79148b-118e-472b-bdb7-9b57b444cc19"
ruleid: 0c79148b-118e-472b-bdb7-9b57b444cc19

tags:
  - attack.command_and_control
  - attack.t1105



status: test





date: Sat, 26 Oct 2019 07:48:38 +0200


---

Downloads payload from remote server

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OtherMSBinaries/Powerpnt.yml
* https://medium.com/@reegun/unsanitized-file-validation-leads-to-malicious-payload-download-via-office-binaries-202d02db7191
* Reegun J (OCBC Bank)


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_msoffice.yml))
```yaml
title: Malicious Payload Download via Office Binaries
id: 0c79148b-118e-472b-bdb7-9b57b444cc19
status: test
description: Downloads payload from remote server
author: Beyu Denis, oscd.community
references:
  - https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OtherMSBinaries/Powerpnt.yml
  - https://medium.com/@reegun/unsanitized-file-validation-leads-to-malicious-payload-download-via-office-binaries-202d02db7191
  - Reegun J (OCBC Bank)
date: 2019/10/26
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith:
      - '\powerpnt.exe'
      - '\winword.exe'
      - '\excel.exe'
    CommandLine|contains: 'http'
  condition: selection
falsepositives:
  - Unknown
level: high
tags:
  - attack.command_and_control
  - attack.t1105

```
