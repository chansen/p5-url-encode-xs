#!/usr/bin/perl

use strict;
use warnings;

use Benchmark       qw[];
use CGI::Deurl::XS  qw[parse_query_string];
use URL::Encode::XS qw[url_params_mixed];

my $s = join '&', map { "$_=%41+%42" } 'A'..'Z', 'A'..'F';

Benchmark::cmpthese( -10, {
    'url_params_mixed' => sub {
        my $hash = url_params_mixed($s);
    },
    'parse_query_string' => sub {
        my $hash = parse_query_string($s);
    },
});


