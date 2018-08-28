package MyApache2::cms3;
  
use strict;
use warnings;
  
use Apache2::RequestRec ();
use Apache2::RequestIO ();
use Apache2::Const qw(OK NOT_FOUND REDIRECT FORBIDDEN);

use APR::Table ();
use APR::UUID;
use DBD::Pg;
use DateTime;
use URI::Escape::XS qw/uri_escape uri_unescape/;
use Encode;
use utf8;

my $dbh   = DBI->connect("dbi:Pg:dbname=userconfig",'userconfig','',{AutoCommit=>1})or die $!;
# must connect via local socket 
  
sub handler
  {
  my $r = shift;
  check_cookies();  
  $r->content_type('text/html');
  $r->print("It is now: " . scalar(localtime) . "\n<br>");
  $r->print("you tried to access $ENV{SERVER_NAME}$ENV{REQUEST_URI}");  

  my $sth = $dbh->prepare("SELECT table_name FROM information_schema.tables WHERE table_schema='public' ");
  $sth->execute();
  my @row   = $sth->fetchrow_array;
  print "<hr>Found tables: <ul>";
  print "<li>$row[0]</li>";
  print "</ul><hr>";
  return Apache2::Const::OK;
  }
sub check_cookies
  {
  return;
  }
1;
