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

# a global database handle and some debug variables
my ($dbh,$dbname,$dbuser,$dbinit_counter,$args);
# init_db();

sub init_db
  {
  my $r = shift;
  my %foo=$r->dir_config->get('foo');
  $dbname=$foo{'dbname'};
  $dbuser=$foo{'dbuser'};
  $dbh   = DBI->connect("dbi:Pg:dbname=$dbname",$dbuser,'',{AutoCommit=>1})or die $!;
  $dbinit_counter++;
  }
sub debug_one
  {
  my $r = shift;
  $r->print("query string: $args\n<br>");
  $r->print("you tried to access $ENV{SERVER_NAME}$ENV{REQUEST_URI}<br>\n");
  $r->print("(PID: $$)(dbh initialized: $dbinit_counter times)($dbh)\n<br>accessing $dbname as $dbuser\n<br>");

  my $sth = $dbh->prepare("SELECT table_name FROM information_schema.tables WHERE table_schema='public' ");
  $sth->execute();
  my @row   = $sth->fetchrow_array;
  print "<hr>Found tables: <ul>";
  print "<li>$row[0]</li>";
  print "</ul><hr>";

  }  
sub handler
  {
  my $r = shift;
  $args='';
  $args=$r->args();
  init_db($r);
  check_cookies();  
  $r->content_type('text/html');
  $r->print("It is now: " . scalar(localtime) . "\n<br>");
  if ($args eq 'debug')
    { debug_one($r) }

  return Apache2::Const::OK;
  }
sub check_cookies
  {
  return;
  }
1;
