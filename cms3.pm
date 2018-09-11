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
my ($dbh,$dbinit_counter);
# variables to be populated from %ENV
my ($method,$ip,$url,$dom,$query);
# variables to get from cookies
my ($useruuid,$usersession);

sub init_db
  {
  my $r = shift;
  my %foo=$r->dir_config->get('foo');
  my $dbname=$foo{'dbname'};
  my $dbuser=$foo{'dbuser'};
  $dbh   = DBI->connect("dbi:Pg:dbname=$dbname",$dbuser,'',{AutoCommit=>1})or die $!;
  $dbinit_counter++;
  check_cookies();
  $method='';$dom='';$url='';$query='';
  $method=$ENV{'REQUEST_METHOD'};
  $dom=$ENV{'SERVER_NAME'};
  ($url,$query)=split(/\?/,$ENV{'REQUEST_URI'});
  }
sub handler
  {
  my $r = shift;
  init_db($r);

  if ($method eq 'GET'){handle_get(   $r )}
  if ($method eq 'POST'){handle_post( $r )}
  if ($method eq 'HEAD'){handle_head( $r )}
  return Apache2::Const::OK;
  }
sub show_env
  {
  my $r = shift;
  $r->content_type('text/html');
  foreach (sort keys %ENV){print "$_ $ENV{$_}<br>\n"}
  return;
  }
sub handle_get
  {
  my $r=shift;
  my $sth=$dbh->prepare("SELECT body from pages where url=? and domain=?");
  $sth->execute($url,$dom);
  my @row   = $sth->fetchrow_array;
  my $body = $row[0];

  $r->content_type('text/html');
  $r->print($body);
  }
sub handle_post
  {

  }
sub handle_head
  {

  }
sub check_cookies
  {
  return;
  }
sub output_body
  {
  my($r,$body,$content_type)=@_;
  # can't use Strict-Transport-Security: max-age=<expire-time>
  # until SSL is enabled - maybe set to expire 1-2 days before cert does...
  # $r->headers_out->set();
  #
  #    my $t=time()+86400*90;
  #    my $maxage="max-age=$t";
  #    $r->headers_out->set('Strict-Transport-Security' => $maxage        );
  $r->headers_out->set('X-Frame-Options'           => 'sameorigin'   );
  $r->headers_out->set('X-XSS-Protection'          => '1; mode=block');
  #    $r->headers_out->set('Content-Security-Policy' => 'default-src https:');
  $r->headers_out->set('X-Content-Type-Options'    => 'nosniff');
  $r->headers_out->set('Referrer-Policy'           => 'same-origin'  );

  $r->content_type($content_type);

  return Apache2::Const::OK;
  }
1;

