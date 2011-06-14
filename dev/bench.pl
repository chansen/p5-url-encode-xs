#!/usr/bin/perl

use strict;
use warnings;

use Benchmark       qw[];
use URL::Encode::XS qw[];
use URL::Encode::PP qw[];

{
    my $s = join '', 'A'..'F', map { sprintf "%%.2X", $_ } 'A'..'F';

    print "Benchmarking url_decode() PP vs XS:\n\n";

    Benchmark::cmpthese( -10, {
        'XS' => sub {
            my $v = URL::Encode::XS::url_decode($s);
        },
        'PP' => sub {
            my $v = URL::Encode::PP::url_decode($s);
        },
    });
}

{
    my $s = join '', 'A'..'F', map { chr } 0x20..0x29;

    print "\nBenchmarking url_encode() PP vs XS:\n\n";

    Benchmark::cmpthese( -10, {
        'XS' => sub {
            my $v = URL::Encode::XS::url_encode($s);
        },
        'PP' => sub {
            my $v = URL::Encode::PP::url_encode($s);
        },
    });
}

{
    my $s = join '&', map { "$_=%41+%42" } 'A'..'Z', 'A'..'F';

    print "\nBenchmarking url_params_mixed() PP vs XS:\n\n";

    Benchmark::cmpthese( -10, {
        'XS' => sub {
            my $v = URL::Encode::XS::url_params_mixed($s);
        },
        'PP' => sub {
            my $v = URL::Encode::PP::url_params_mixed($s);
        },
    });
}

eval {
    require CGI::Deurl::XS;

    my $s = join '&', map { "$_=%41+%42" } 'A'..'Z', 'A'..'F';

    print "\nBenchmarking URL::Encode::XS vs CGI::Deurl::XS\n\n";

    Benchmark::cmpthese( -10, {
        'url_params_mixed' => sub {
            my $hash = URL::Encode::XS::url_params_mixed($s);
        },
        'parse_query_string' => sub {
            my $hash = CGI::Deurl::XS::parse_query_string($s);
        },
    });
};

