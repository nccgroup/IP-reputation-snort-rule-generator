#!/usr/bin/perl

# A tool to generate Snort rules based on public IP/domain reputation data
# 
# Released as open source by NCC Group Plc - http://www.nccgroup.com/
# 
# Developed by Will Alexander, will dot alexander at nccgroup dot com
# 
# https://github.com/nccgroup/IP-reputation-snort-rule-generator
# 
# Released under AGPL see LICENSE for more information


use LWP::Simple;
use Getopt::Long;

my $url = 'https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist';
my $file = undef;
my $ref = "";
my $sid = 9000000;
my $csv = undef;
my $ids = 'snort';
my $help = undef;
my $domain_regex = "[A-Za-z0-9][-A-Za-z0-9]{0,253}[A-Za-z0-9]+(?:\\.[A-Za-z0-9][-A-Za-z0-9]{0,253}[A-Za-z0-9]+)+";
my $ip_regex = "(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)";

GetOptions(  "url=s"		=> \$url,
		"file=s"	=> \$file,
		"sid=i"		=> \$sid,
		"csv=i"		=> \$csv,
		"ids=s"		=> \$ids,
		"help"		=> \$help);

if(defined $help) {
	print "tepig.pl [ [--file=<LOCAL_FILE>] | [--url]=<URL>] ] [--csv=<FIELD_NUM>] [--sid=<INITIAL_SID>] [--ids=[snort|cisco]] | --help\n";
	print "\t<LOCAL_FILE> is a file stored localy that contains a list of malicious domains, IP addresses and/or URLs. If omitted then it assumed that a URL is provided.\n";
	print "\t<URL> is a URL that contains a list of malicious domains, IP addresses or URLs. The default is https://zeustracker.abuse.ch/blocklist.php?download=domainblocklist.\n";
	print "\t<FIELD_NUM> is the field number (indexing from 0) that contains the information of interest. If omitted then the file is treated as a simple list.\n";
	print "\t<INITIAL_SID> is the SID that will be applied to the first rule. Every subsequent rule will increment the SID value. The default is 9000000 for Snort and 60000 for Cisco.\n";
	exit;
}

my @lines;

if (lc($ids) eq "cisco" && $sid == 9000000) {
	$sid = 60000;
}

if ($file) {
	open(MYINPUTFILE, "<$file");
	@lines = <MYINPUTFILE>;
}
else {
	my $content = get $url;
	die "Couldn't get $url" unless defined $content;
	@lines = split(/\r?\n/, $content);
	$ref = "reference:\"url,$url\";";
}


foreach $line (@lines) {
	if(defined $csv) {
		my @fields = split(/,/, $line, $csv+2);
		if(scalar @fields > $csv) {
			$line = @fields[$csv];
			$line =~ s/"//g;
		};
	}
	if ($line =~ m/($ip_regex)/) {
		my $ip = $1;
		if(lc($ids) ne "cisco") { 
	        	print "alert ip any any <> $ip any (msg:\"Traffic to known bad IP ($ip)\"; $ref sid:$sid; rev:0;)\n";
		} else {
			print "signatures $sid 0\n";
			print "alert-severity high\n";
			print "sig-fidelity-rating 100\n";
			print "sig-description\n";
			print "sig-name Traffic to known bad IP - $ip\n";
			print "sig-string-info $ref\n";
			print "exit\n";
			print "engine atomic-ip\n";
			print "event-action produce-alert|produce-verbose-alert|log-attacker-packets\n";
			print "fragment-status any\n";
			print "specify-l4-protocol no\n";
			print "specify-ip-addr-options yes\n";
			print "ip-addr-options ip-addr\n";
			print "specify-src-ip-addr yes\n";
			print "src-ip-addr 0.0.0.0-255.255.255.255\n";
			print "exit\n";
			print "specify-dst-ip-addr yes\n";
			print "dst-ip-addr $ip\n";
			print "exit\n";
			print "exit\n";
			print "exit\n";
			print "exit\n";
			print "event-counter\n";
			print "event-count 1\n";
			print "exit\n";
			print "status\n";
			print "enabled true\n";
			print "retired false\n";
			print "exit\n";
			print "exit\n";
		}
		$sid++;
	} elsif ($line =~ m/(?:\*\.)?($domain_regex)/) {
		my $domainname = $1;
		my @domains = split(/\./, $domainname);
		my $dnslookup = "";
		foreach $domain (@domains) {
			$dnslookup .= sprintf("|%.2x|", length($domain));
			$dnslookup .= "$domain";
		}
		if(lc($ids) ne "cisco") { 
			print "alert udp any any -> any 53 (msg:\"Suspicious DNS lookup for $domainname\"; $ref content:\"|01 00 00 01 00 00 00 00 00 00|\"; depth: 10; offset: 2; content:\"";
			print "$dnslookup";
			print "\"; nocase; distance:0; sid:$sid; rev:0;)\n";
		} else {
			print "signatures $sid 0\n";
			print "sig-description\n";
			print "sig-name Suspicious DNS lookup for $domainname\n";
			print "sig-string-info $ref\n";
			print "no sig-comment\n";
			print "exit\n";
			print "engine string-udp\n";
			print "regex-string \\x01\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00.*$dnslookup\n";
			print "service-ports 53\n";
			print "specify-exact-match-offset yes\n";
			print "exact-match-offset 2\n";
			print "exit\n";
			print "exit\n";
			print "status\n";
			print "enabled true\n";
			print "retired false\n";
			print "exit\n";
			print "exit\n";
		}
		$sid++;
	}
}
