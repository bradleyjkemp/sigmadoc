---
title: "Successful IIS Shortname Fuzzing Scan"
aliases:
  - "/rule/7cb02516-6d95-4ffc-8eee-162075e111ac"


tags:
  - attack.initial_access
  - attack.t1190



status: experimental





date: Wed, 6 Oct 2021 17:46:15 +0200


---

When IIS uses an old .Net Framework it's possible to enumeration folder with the symbol ~.

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/projectdiscovery/nuclei-templates/blob/master/fuzzing/iis-shortname.yaml
* https://www.exploit-db.com/exploits/19525
* https://github.com/lijiejie/IIS_shortname_Scanner


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/web/web_iis_tilt_shortname_scan.yml))
```yaml
title: Successful IIS Shortname Fuzzing Scan
id: 7cb02516-6d95-4ffc-8eee-162075e111ac
status: experimental
author: frack113
description: When IIS uses an old .Net Framework it's possible to enumeration folder with the symbol ~.
references:
    - https://github.com/projectdiscovery/nuclei-templates/blob/master/fuzzing/iis-shortname.yaml
    - https://www.exploit-db.com/exploits/19525
    - https://github.com/lijiejie/IIS_shortname_Scanner
date: 2021/10/06
tags:
    - attack.initial_access
    - attack.t1190
logsource:
    category: webserver
detection:
    selection:
        c-uri|contains: '~1'
        c-uri|endswith: 'a.aspx'
        cs-method:
            - GET
            - OPTIONS
        #only succes
        sc-status:
            - 200
            - 301
    condition: selection
falsepositives:
    - Unknown
level: medium
```
