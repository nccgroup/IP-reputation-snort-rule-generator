#!/usr/bin/perl

use LWP::Simple;
use Getopt::Long;

my $url = 'https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist';
my $file = undef;
my $ref = "";
my $sid = 9000000;
my $csv = undef;
my $help = undef;
my $domain_regex = "[A-Za-z0-9][-A-Za-z0-9]{0,253}[A-Za-z0-9]+(?:\\.[A-Za-z0-9][-A-Za-z0-9]{0,253}[A-Za-z0-9]+)+";
my $ip_regex = "(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)";

GetOptions(  "url=s"		=> \$url,
		"file=s"	=> \$file,
		"sid=i"		=> \$sid,
		"csv=i"		=> \$csv,
		"help"		=> \$help);

if(defined $help) {
	print "tepig.pl [ [--file=<LOCAL_FILE>] | [--url]=<URL>] ] [--csv=<FIELD_NUM>] [--sid=<INITIAL_SID>] | --help\n";
	print "\t<LOCAL_FILE> is a file stored localy that contains a list of malicious domains, IP addresses and/or URLs. If omitted then it assumed that a URL is provided.\n";
	print "\t<URL> is a URL that contains a list of malicious domains, IP addresses or URLs. The default is https://zeustracker.abuse.ch/blocklist.php?download=domainblocklist.\n";
	print "\t<FIELD_NUM> is the field number (indexing from 0) that contains the information of interest. If omitted then the file is treated as a simple list.\n";
	print "\t<INITIAL_SID> is the SID that will be applied to the first rule. Every subsequent rule will increment the SID value. The default is 9000000.\n";
	exit;
}

my @lines;

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
        print "alert ip any any <> $ip any (msg:\"Traffic to known bad IP ($ip)\"; $ref sid:$sid; rev:0;)\n";
		$sid++;
	} elsif ($line =~ m/(?:\*\.)?($domain_regex)/) {
		my $domainname = $1;
		print "alert udp any any -> any 53 (msg:\"Suspicious DNS lookup for $domainname\"; $ref content:\"|01 00 00 01 00 00 00 00 00 00|\"; depth: 10; offset: 2; content:\"";
		my @domains = split(/\./, $domainname);
		foreach $domain (@domains) {
			printf "|%.2x|", length($domain);
			print "$domain";
		}
		print "\"; nocase; distance:0; sid:$sid; rev:0;)\n";
		$sid++;
	}
}
