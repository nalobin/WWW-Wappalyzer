#!perl -T

use FindBin qw($Bin);
use Test::More tests => 9;

BEGIN {
    use_ok( 'WWW::Wappalyzer' ) || print "Bail out!\n";
}

my @cats = WWW::Wappalyzer::get_categories();

ok scalar @cats, 'get_categories';
ok scalar( grep { $_ eq 'cms' } @cats ), 'get_categories cms';

my $html = q{<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="ru-ru" lang="ru-ru" >
<head>
  <meta http-equiv="content-type" content="text/html; charset=utf-8" />
  <meta name="robots" content="index, follow" />
  <meta name="keywords" content="joomla, CMS Joomla, движок сайта" />
  <meta name="description" content="Joomla! - система управления содержимым - основа динамического портала" />
  <meta name="generator" content="Joomla! 1.5 - Open Source Content Management" />
  <title>Lib</title>
  <link href="/index.php?format=feed&amp;type=rss" rel="alternate" type="application/rss+xml" title="RSS 2.0" />
  <link href="/index.php?format=feed&amp;type=atom" rel="alternate" type="application/atom+xml" title="Atom 1.0" />
  <link href="/templates/rhuk_milkyway/favicon.ico" rel="shortcut icon" type="image/x-icon" />
  <script type="text/javascript" src="/media/system/js/jquery.1.5.4.js"></script>
  <script type="text/javascript" src="/media/system/js/caption.js"></script>};

my %detected = WWW::Wappalyzer::detect(
    html     => $html,
    headers  => {
        Server => 'nginx',
        'X-Powered-By' => 'PleskLin',
    },
);

is_deeply \%detected, {
    'web-servers' => [ 'Nginx' ],
    cms => [ 'Joomla' ],
    'javascript-frameworks' => [ 'jQuery' ],
    'hosting-panels' => [ 'Plesk' ],
}, 'detect by html & headers';

%detected = WWW::Wappalyzer::detect( url => 'http://myblog.livejournal.com' );

is_deeply \%detected, { blogs => [ 'LiveJournal' ] }, 'detect by url';

%detected = WWW::Wappalyzer::detect(
    headers  => { Server => 'nginx' },
    cats => [ 'web-servers' ],
);
is_deeply \%detected, { 'web-servers' => [ 'Nginx' ] }, 'detect single cat';

%detected = WWW::Wappalyzer::detect(
    html => q{<link href="./dist/css/bootstrap.css" rel="stylesheet">},
    cats => [ 'web-frameworks' ],
);
is_deeply \%detected, { 'web-frameworks' => [ 'Twitter Bootstrap' ] }, 're with html entity';

$html = q{
var rls = {b1: {position: '1',use_from: '0',start: '0',end: '9',amount: '10',type: 'manual'}}</script><script type="text/javascript" language="JavaScript" src="http://img.sedoparking.com/jspartner/google.js"></script><script type="text/javascript" language="JavaScript">var ads_label = '<h2><span><a class="ad_sense_help" href="https://www.google.com/adsense/support/bin/request.py?
};

%detected = WWW::Wappalyzer::detect( html => $html );
is_deeply \%detected, {}, 'detect before add clues file';

WWW::Wappalyzer::add_clues_file( "$Bin/add.json" );

%detected = WWW::Wappalyzer::detect(
    html => $html,
    headers  => { Server => 'nginx' },
);
is_deeply \%detected, { parkings => [ 'sedoparking' ], 'web-servers' => [ 'Nginx' ] }, 'detect after add clues file';
