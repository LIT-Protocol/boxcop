use strict;
use warnings;
$| = 1;
my $mode = $ARGV[0] // 'normal';
$SIG{TERM} = 'IGNORE' if $mode eq 'stubborn';
while (my $line = <STDIN>) {
    my ($id) = $line =~ /"id"\s*:\s*"([A-Za-z0-9_-]+)"/;
    my ($op) = $line =~ /"op"\s*:\s*"([a-z_]+)"/;
    exit 0 if $mode eq 'eof';
    sleep 30 if $mode eq 'silent' || $mode eq 'stubborn';
    if ($mode eq 'malformed') { print "not-json\n"; next; }
    if ($mode eq 'oversized') { print 'x' x 262145; next; }
    if ($mode eq 'wrongid') { $id = 'other'; }
    if ($mode eq 'stderr') { print STDERR 'PRIVATE_MARKER' x 50000; }
    if ($op eq 'status') {
        select(undef, undef, undef, 0.5) if $mode eq 'slowstart';
        my $ready = $mode eq 'notready' ? 'false' : 'true';
        my $reply = qq({"version":1,"id":"$id","ok":true,"result":{"ready":$ready,"protocol":1,"engine":"rules","network_listener":false}}\n);
        if ($mode eq 'partial') { for (split //, $reply) { print $_; } }
        else { print $reply; }
        exit 0 if $mode eq 'readyexit';
    } elsif ($op eq 'security_events') {
        sleep 30 if $mode eq 'slow';
        print qq({"version":1,"id":"$id","ok":true,"result":{"events":[]}}\n);
    } elsif ($op eq 'shutdown') {
        print qq({"version":1,"id":"$id","ok":true,"result":{"stopped":true}}\n);
        exit 0;
    } else {
        print qq({"version":1,"id":"$id","ok":false,"error":{"code":"invalid_request","message":"PRIVATE_MARKER"}}\n);
    }
}
