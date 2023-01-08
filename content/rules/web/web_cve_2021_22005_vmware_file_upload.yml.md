---
title: "VMware vCenter Server File Upload CVE-2021-22005"
aliases:
  - "/rule/b014ea07-8ea0-4859-b517-50a4e5b7ecec"
ruleid: b014ea07-8ea0-4859-b517-50a4e5b7ecec

tags:
  - attack.initial_access
  - attack.t1190



status: experimental





date: Fri, 24 Sep 2021 21:21:09 +0700


---

Detects exploitation attempts using file upload vulnerability CVE-2021-22005 in the VMWare vCenter Server.

<!--more-->


## Known false-positives

* Vulnerability Scanning/Pentesting



## References

* https://kb.vmware.com/s/article/85717
* https://www.tenable.com/blog/cve-2021-22005-critical-file-upload-vulnerability-in-vmware-vcenter-server


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/web/web_cve_2021_22005_vmware_file_upload.yml))
```yaml
title: VMware vCenter Server File Upload CVE-2021-22005
id: b014ea07-8ea0-4859-b517-50a4e5b7ecec
status: experimental
description: Detects exploitation attempts using file upload vulnerability CVE-2021-22005 in the VMWare vCenter Server.
author: Sittikorn S
date: 2021/09/24
references:
    - https://kb.vmware.com/s/article/85717
    - https://www.tenable.com/blog/cve-2021-22005-critical-file-upload-vulnerability-in-vmware-vcenter-server
tags:
    - attack.initial_access
    - attack.t1190
logsource:
    category: webserver
detection:
    selection:
        cs-method: 'POST'
        c-uri|contains: '/analytics/telemetry/ph/api/hyper/send?'
    condition: selection
falsepositives:
    - Vulnerability Scanning/Pentesting
level: high

```
