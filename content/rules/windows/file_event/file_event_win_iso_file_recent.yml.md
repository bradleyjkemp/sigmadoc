---
title: "ISO or Image Mount Indicator in Recent Files"
aliases:
  - "/rule/4358e5a5-7542-4dcb-b9f3-87667371839b"




status: experimental





date: Fri, 11 Feb 2022 12:37:35 +0100


---

Detects the creation of recent element file that points to an .ISO, .IMG, .VHD or .VHDX file as often used in phishing attacks. This can be a false positive on server systems but on workstations users should rarely mount .iso or .img files.

<!--more-->


## Known false-positives

* Cases in which a user mounts an image file for legitimate reasons



## References

* https://www.microsoft.com/security/blog/2021/05/27/new-sophisticated-email-based-attack-from-nobelium/
* https://www.trendmicro.com/vinfo/us/security/news/cybercrime-and-digital-threats/malicious-spam-campaign-uses-iso-image-files-to-deliver-lokibot-and-nanocore
* https://blog.emsisoft.com/en/32373/beware-new-wave-of-malware-spreads-via-iso-file-email-attachments/
* https://insights.sei.cmu.edu/blog/the-dangers-of-vhd-and-vhdx-files/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/file_event/file_event_win_iso_file_recent.yml))
```yaml
title: ISO or Image Mount Indicator in Recent Files
id: 4358e5a5-7542-4dcb-b9f3-87667371839b
description: Detects the creation of recent element file that points to an .ISO, .IMG, .VHD or .VHDX file as often used in phishing attacks. This can be a false positive on server systems but on workstations users should rarely mount .iso or .img files.
status: experimental
author: Florian Roth
references:
    - https://www.microsoft.com/security/blog/2021/05/27/new-sophisticated-email-based-attack-from-nobelium/
    - https://www.trendmicro.com/vinfo/us/security/news/cybercrime-and-digital-threats/malicious-spam-campaign-uses-iso-image-files-to-deliver-lokibot-and-nanocore
    - https://blog.emsisoft.com/en/32373/beware-new-wave-of-malware-spreads-via-iso-file-email-attachments/
    - https://insights.sei.cmu.edu/blog/the-dangers-of-vhd-and-vhdx-files/
date: 2022/02/11
logsource:
    product: windows
    category: file_event
detection:
    selection:
        TargetFilename|endswith: 
            - '.iso.lnk'
            - '.img.lnk'
            - '.vhd.lnk'
            - '.vhdx.lnk'
        TargetFilename|contains:
            - '\Microsoft\Windows\Recent\'
    condition: selection
falsepositives:
    - Cases in which a user mounts an image file for legitimate reasons
level: medium

```