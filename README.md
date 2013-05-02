IP-reputation-snort-rule-generator
==================================

A tool to generate Snort rules based on public IP/domain reputation data

Released as open source by NCC Group Plc - http://www.nccgroup.com/

Developed by Will Alexander, will dot alexander at nccgroup dot com

http://www.github.com/nccgroup/IP-repuatation-snort-rule-generator

Released under AGPL see LICENSE for more information

Usage
=====

./tepig.pl [ [--file=LOCAL_FILE] | [--url=URL] ] [--csv=FIELD_NUM] [--sid=INITIAL_SID] | --help

LOCAL_FILE is a file stored localy that contains a list of malicious domains, IP addresses and/or URLs. If omitted then it assumed that a URL is provided.
URL is a URL that contains a list of malicious domains, IP addresses or URLs. The default is https://zeustracker.abuse.ch/blocklist.php?download=domainblocklist.
FIELD_NUM is the field number (indexing from 0) that contains the information of interest. If omitted then the file is treated as a simple list.
INITIAL_SID is the SID that will be applied to the first rule. Every subsequent rule will increment the SID value. The default is 9000000.

Examples
========

Malicious IP address
====================

./tepig.pl --url=https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist

https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist is a plain text file containing a list of known bad IP addresses. At the time of writing, the first entry is 108.161.130.191. The first rule output would be:

alert ip any any <> 108.161.130.191 any (msg:"Traffic to known bad IP (108.161.130.191)"; reference:"url,https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist"; sid:9000000; rev:0;)

This rule looks for any traffic going to or coming from the bad IP address.

Malicious Domain
================

./tepig.pl --url=http://doc.emergingthreats.net/pub/Main/RussianBusinessNetwork/Storm_2_domain_objects_3-11-2011.txt

http://doc.emergingthreats.net/pub/Main/RussianBusinessNetwork/Storm_2_domain_objects_3-11-2011.txt is a plain text file containing a list of known bad domain names. At the time of writing the first entry is *.bethira.com. The first rule output would be:

alert udp any any -> any 53 (msg:"Suspicious DNS lookup for *.bethira.com"; reference:"url,http://doc.emergingthreats.net/pub/Main/RussianBusinessNetwork/Storm_2_domain_objects_3-11-2011.txt"; content:\"|01 00 00 01 00 00 00 00 00 00|\"; depth: 10; offset: 2; content:"|07|bethira|03|com"; nocase; distance:0; sid:9000000; rev:0;)

This rule looks for any DNS lookup for the bad domain.
