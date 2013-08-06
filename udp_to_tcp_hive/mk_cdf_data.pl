#!/usr/bin/perl
use strict;
use warnings;

my $ac_tcpconn=0;
my $ac_query=0;
my $rank=0;
while(<>)
{
    chomp;
    my ($src, $tcpconn, $count)=split;
    next unless defined $src && $tcpconn && $count;
    $rank+=1;
    $ac_tcpconn+=$tcpconn;
    $ac_query+=$count;
    printf "%s\t%d\t%d\t%d\n", $src, $rank, $ac_tcpconn, $ac_query;

}
