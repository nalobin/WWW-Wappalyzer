package WWW::Wappalyzer;

use 5.006;
use strict;
use warnings;

use base qw ( Exporter );
our @EXPORT_OK = qw( detect get_categories_names add_categories_file add_techs_file );

use lib::abs;
use JSON qw();
use Regexp::Parser;

my %_categories;
my @_techs_file_list = ( glob lib::abs::path( './wappalyzer_src/technologies' ) . '/*.json'  );
my @_cats_file_list = ( lib::abs::path( './wappalyzer_src/categories.json' ) );

# List of multi per-page application categories names
my %MULTIPLE_APP_CATS = map { $_ => 1 } (
    'Widgets',
    'Analytics',
    'JavaScript frameworks',
    'JavaScript libraries',
    'UI frameworks',
    'Video players',
    'Font scripts',
    'Miscellaneous',
    'Advertising',
    'Payment processors',
    'JavaScript graphics',
    'Marketing automation',
    'Web server extensions',
    'WordPress plugins',
);

=head1 NAME

WWW::Wappalyzer - Perl port of Wappalyzer (https://wappalyzer.com)

=head1 DESCRIPTION

Uncovers the technologies used on websites: detects content management systems, web shops,
web servers, JavaScript frameworks, analytics tools and many more.

Supports only `scriptSrc`, `scripts`, `html`, `meta`, `headers` and `url` patterns of
Wappalyzer specification. Lacks 'version', 'implies', 'excludes' support in favour of speed.

Categories: L<https://github.com/wappalyzer/wappalyzer/blob/master/src/categories.json>
Technologies: L<https://github.com/wappalyzer/wappalyzer/tree/master/src/technologies>
More info on Wappalyzer:  L<https://github.com/wappalyzer/wappalyzer>

=cut

our $VERSION = '2.00';

=head1 SYNOPSIS

    use WWW::Wappalyzer;
    use LWP::UserAgent;
    use List::Util 'pairmap';

    my $response = LWP::UserAgent->new->get( 'http://www.drupal.org' );
    my %detected = WWW::Wappalyzer::detect(
        html    => $response->decoded_content,
        headers => { pairmap { $a => [ $response->headers->header($a) ] } $response->headers->flatten },
    );

    # %detected = (
    #   'Font scripts'    => [ 'Google Font API' ],
    #   'Caching'         => [ 'Varnish' ],
    #   'CDN'             => [ 'Fastly' ],
    #   'CMS'             => [ 'Drupal' ],
    #   'Video players'   => [ 'YouTube' ],
    #   'Tag managers'    => [ 'Google Tag Manager' ],
    #   'Reverse proxies' => [ 'Nginx' ],
    #   'Web servers'     => [ 'Nginx' ],
    # );

=head1 EXPORT

None by default.

=head1 SUBROUTINES/METHODS

=head2 detect

    my %detected = detect( %params )

Tries to detect CMS, framework, etc for given html code, http headers, URL.

Available parameters:

    html    - HTML code of web page.

    headers - Hash ref to http headers list. The value may be a plain string or an array ref
              of strings for a multi-valued field.

    url     - URL of web page.

    cats    - Array ref to a list of trying categories names, defaults to all.
              Less categories - less CPU usage.

Returns the hash of detected applications by category:

    (
        CMS  => [ 'Joomla' ],
        'Javascript frameworks' => [ 'jQuery', 'jQuery UI' ],
    )

=cut

sub detect {
    my %params = @_;

    return () unless $params{html} || $params{headers} || $params{url};
    
    # search will be case insensitive
    if ( $params{html} ) {
        $params{html} = lc $params{html};
    }

    if ( $params{url} ) {
        $params{url} = lc $params{url};
    }

    my $headers_ref;
    if ( $params{headers} ) {
        die 'Bad headers param'  unless ref $params{headers} eq 'HASH';

        # Make all headers lowercase and array ref valued
        $headers_ref = {};
        while ( my ( $header, $header_vals_ref ) = each %{ $params{headers} } ) {
            unless ( ref $header_vals_ref ) {
                $header_vals_ref = [ $header_vals_ref ];
            }
            elsif ( ref $header_vals_ref ne 'ARRAY' ) {
                next;
            }

            $headers_ref->{ lc $header } = [ map { lc } @$header_vals_ref ];
        }
    }

    # Lazy load and process techs from JSON file
    _load_categories_and_techs()  unless scalar keys %_categories;

    my @cats = $params{cats} && ( ref( $params{cats} ) || '' ) eq 'ARRAY'
        ? @{ $params{cats} } : get_categories_names();

    my %detected;
    my %tried_multi_cat_apps;
    for my $cat ( @cats ) {
        my $apps_ref = $_categories{ $cat } or die "Unknown category name $cat";

        APP:
        for my $app_ref ( @$apps_ref ) {

            my $detected;

            # Some speed optimizations
            if ( @cats > 1 && $app_ref->{multi_cat}
                && exists $tried_multi_cat_apps{ $app_ref->{name} }
            ) {
                $detected = $tried_multi_cat_apps{ $app_ref->{name} };
            }
            else {
                # Try regexes...
                my $confidence = 0;

                if ( defined $headers_ref && exists $app_ref->{headers_rules} ) {
                    my %headers_rules = %{ $app_ref->{headers_rules} };

                    HEADER_RULE:
                    while ( my ( $header, $rule ) = each %headers_rules ) {
                        my $header_vals_ref = $headers_ref->{ $header } or next;

                        for my $header_val ( @$header_vals_ref ) {
                            if ( $header_val =~ m/$rule->{re}/ ) {
                                $confidence += $rule->{confidence};
                                if ( $confidence >= 100 ) {
                                    $detected = 1;
                                    last HEADER_RULE;
                                }
                            }
                        }
                    }
                }

                unless ( $detected ) {
                    # try from most to least relevant method
                    RULES:
                    for my $rule_type ( qw( html url ) ) {
                        my $rule_name = $rule_type. '_rules';
                        if ( defined $params{ $rule_type } && exists $app_ref->{ $rule_name } ) {
                            for my $rule ( @{ $app_ref->{ $rule_name } } ) {
                                if ( $params{ $rule_type } =~ m/$rule->{re}/ ) {
                                    $confidence += $rule->{confidence};
                                    if ( $confidence >= 100 ) {
                                        $detected = 1;
                                        last RULES;
                                    }
                                }
                            }
                        }
                    }
                }

                # Some speed optimizations
                if ( @cats > 1 && $app_ref->{multi_cat} ) {
                    $tried_multi_cat_apps{ $app_ref->{name} } = $detected;
                }
            }

            next unless $detected;

            # Detected!
            push @{ $detected{ $cat } }, $app_ref->{name};

            last APP unless $MULTIPLE_APP_CATS{ $cat };
        }
    }

    return %detected;
}

=head2 get_categories_names

    my @cats = get_categories_names()

Returns the array of all application categories names.

=cut

sub get_categories_names {
    # Lazy load and process categories from JSON files
    _load_categories_and_techs() unless scalar keys %_categories;

    return keys %_categories;
}

# Loads and processes categories and techs from JSON files
sub _load_categories_and_techs {
    my $cats_ref = {};

    for my $cats_file ( @_cats_file_list ) {
       $cats_ref = { %$cats_ref, %{ _load_json( $cats_file ) } };
    }

    for my $techs_file ( @_techs_file_list ) {
        my $apps_ref = _load_json( $techs_file );

        # Process apps
        while ( my ( $app, $app_ref ) = each %$apps_ref ) {

            my $new_app_ref = _process_app_techs( $app, $app_ref ) or next;

            my @cats = @{ $app_ref->{cats} } or next;

            $new_app_ref->{multi_cat} = 1 if @cats > 1;

            for my $cat_id ( @cats ) {
                my $cat = $cats_ref->{ $cat_id } or die "Bad categorie id $cat_id in app $app";

                push @{ $_categories{ $cat->{name} } }, $new_app_ref;
            }
        }
    }
}

# Loads JSON file
sub _load_json {
    my ( $file ) = @_;

    open my $fh, '<', $file or die "Can not read file $file.";

    local $/ = undef;
    my $json = <$fh>;
    close $fh;

    # Replace html entities with oridinary symbols
    $json =~ s{&gt;}{>}xig;
    $json =~ s{&lt;}{<}xig;

    my $res = eval { JSON::decode_json( $json ) };

    die "Can't parse JSON file $file: $@" if $@;

    die "$file has invalid format"  unless ref $res eq 'HASH';

    return $res;
}

# Process techs of given app
sub _process_app_techs {
    my ( $app, $app_ref ) = @_;

    my $new_app_ref = { name => $app };

    my @fields = grep { exists $app_ref->{$_} } qw( scriptSrc scripts html meta headers url );
    my @html_rules;
    # Precompile regexps
    for my $field ( @fields ) {
        my $rule_ref = $app_ref->{ $field };
        my @rules_list =   !ref $rule_ref ? _parse_rule( $rule_ref )
            : ref $rule_ref eq 'ARRAY' ? ( map { _parse_rule( $_ ) } @$rule_ref )
            : () ;

        if ( $field eq 'html' || $field eq 'scripts' ) {
            push @html_rules, map { $_->{re} = qr/(?-x:$_->{re})/; $_ } @rules_list;
        }
        elsif ( $field eq 'scriptSrc' ) {
            push @html_rules,
                map {
                    $_->{re} = qr/
                        < \s* script [^>]+ src \s* = \s* ["'] [^"']* (?-x:$_->{re}) [^"']* ["']
                    /x;
                    $_
                } @rules_list;
        }
        elsif ( $field eq 'url' ) {
            my @url_rules = map { $_->{re} = qr/(?-x:$_->{re})/; $_ } @rules_list;
            $new_app_ref->{url_rules} = _optimize_rules( \@url_rules );
        }
        elsif ( $field eq 'meta' ) {
            for my $key ( keys %$rule_ref ) {
                my $lc_key = lc $key;
                my $name_re = qr/ name \s* = \s* ["']? $lc_key ["']? /x;
                my $rule = _parse_rule( $rule_ref->{$key} );
                $rule->{re} = qr/$rule->{re}/;
                my $content_re = qr/ content \s* = \s* ["'] [^"']* (?-x:$rule->{re}) [^"']* ["'] /x;

                $rule->{re} = qr/
                    < \s* meta \s+
                    (?:
                          (?: $name_re    \s+ $content_re )
                        # | (?: $content_re \s+ $name_re    ) # hangs sometimes
                    )
                /x;
                
                push @html_rules, $rule;
            }
        }
        elsif ( $field eq 'headers' ) {
            for my $key ( keys %$rule_ref ) {
                my $rule = _parse_rule( $rule_ref->{$key} );
                $rule->{re} = qr/$rule->{re}/;
                $new_app_ref->{headers_rules}{ lc $key } = $rule;
            }
        }
    }

    if ( @html_rules ) {
        $new_app_ref->{html_rules} = _optimize_rules( \@html_rules );
    }

    return $new_app_ref;
}

# separate regexp and other optional parameters from the rule
sub _parse_rule {
    my ( $rule ) = @_;
    
    my ( $re, @params ) = split /\\;/, $rule;
    
    my $confidence;
    for my $param ( @params ) {
        if ( ( $confidence ) = $param =~ /^\s*confidence\s*:\s*(\d+)\s*$/ ) {
            # supports only confidence for now
            last;
        }
    }
    
    return {
        re         => _escape_re( defined( $re ) ? $re : '' ),
        confidence => $confidence || 100,
    };
}

# Escape special symbols in regexp string of config file
sub _escape_re {
    my ( $re ) = @_;
    
    # Escape { } braces
    #$re =~ s/ ([{}]) /[$1]/xig;

    # Escape [^]
    $re =~ s{\Q[^]\E}{[\\^]}ig;

    # Escape \\1
    $re =~ s{\Q\1\E}{\\\\1}ig;

    # Escape (?!
    $re =~ s{[(][?][!]}{([?]!}ig;
    
    # turn literals in regexp to lowercase to make case insensitive search
    # i flag will be slower because we makes many searches in one text
    no warnings 'redefine';
    local *Regexp::Parser::warn = sub {}; # it may be too noisy
    
    my $parser = Regexp::Parser->new();
    if ( $parser->regex($re) ) {
        $re = '';
        
        while ( my $node = $parser->next ) {
            my $ref = ref $node;
            if ( $ref eq 'Regexp::Parser::exact' || $ref eq 'Regexp::Parser::anyof_char' ) {
                $re .= lc $node->raw;
            }
            else {
                $re .= $node->raw;
            }
        }
    }
 
    return $re;
}

# If possible combine all rules in one regexp
sub _optimize_rules {
    my ( $rules ) = @_;
    
    if ( @$rules > 1 && @$rules == grep { $_->{confidence} == 100 } @$rules ) {
        # can combine only if confidence for each is 100
        my $re = join '|', map { $_->{re} } @$rules;
        return [{
           re         => qr/$re/,
           confidence => 100,
        }];
    }
    
    return $rules;
}

=head2 add_categories_file

    add_categories_file( $filepath )

Puts additional categories file to a list of processed categories files.
See lib/WWW/wappalyzer_src/categories.json as format sample.

=cut

sub add_categories_file {
    my ( $filepath ) = @_;

    push @_cats_file_list, $filepath;

    # just clear out categories to lazy load later
    %_categories = ();
}

=head2 add_techs_file

    add_techs_file( $filepath )

Puts additional techs file to a list of processed techs files.
See lib/WWW/wappalyzer_src/technologies/a.json as format sample.

=cut

sub add_techs_file {
    my ( $filepath ) = @_;

    push @_techs_file_list, $filepath;

    # just clear out categories to lazy load later
    %_categories = ();
}

=head1 AUTHOR

Alexander Nalobin, C<< <alexander at nalobin.ru> >>

=head1 BUGS

Please report any bugs or feature requests to C<bug-www-wappalyzer at rt.cpan.org>, or through
the web interface at L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=WWW-Wappalyzer>.  I will be notified, and then you'll
automatically be notified of progress on your bug as I make changes.


=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc WWW::Wappalyzer


You can also look for information at:

=over 4

=item * GitHub

L<https://github.com/nalobin/WWW-Wappalyzer>

=item * RT: CPAN's request tracker (report bugs here)

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=WWW-Wappalyzer>

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/WWW-Wappalyzer>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/WWW-Wappalyzer>

=item * Search CPAN

L<http://search.cpan.org/dist/WWW-Wappalyzer/>

=back


=head1 ACKNOWLEDGEMENTS


=head1 LICENSE AND COPYRIGHT

Copyright 2013-2015 Alexander Nalobin.

This program is free software; you can redistribute it and/or modify it
under the terms of either: the GNU General Public License as published
by the Free Software Foundation; or the Artistic License.

See http://dev.perl.org/licenses/ for more information.


=cut

1; # End of WWW::Wappalyzer
