package MyApache2::cms3;
 
use strict;
use warnings;

use Apache2::RequestRec ();
use Apache2::RequestIO ();
use Apache2::Const qw(OK NOT_FOUND REDIRECT FORBIDDEN HTTP_INTERNAL_SERVER_ERROR);

use APR::Table ();
use APR::UUID;
use DBD::Pg;
use DateTime;
use URI::Escape::XS qw/uri_escape uri_unescape/;
use Encode;
use utf8;

# the global database handle
my ($dbh);
# variables to be populated from %ENV
my ($method,$ip,$url,$dom,$query);
# variables to get from cookies
my ($useruuid,$usersession);
# global variable to load api endpoint template bodies into
my %api;

sub init_db
  {
  my $r = shift;
  my %foo=$r->dir_config->get('foo');
  my $dbname=$foo{'dbname'};
  my $dbuser=$foo{'dbuser'};
  #
  # with persistant database connections, this only actually connects 1x/process
  #
$dbh=DBI->connect("dbi:Pg:dbname=$dbname",$dbuser,'',{AutoCommit=>1}) or die $!;
  #
  # since init_db runs with every connection to the server, we clear variables and make
  # sure the /api templates are pre-loaded, just once.  If they change, then the server
  # has to be restarted
  #
  load_api_templates($r);
  check_cookies();
  $method='';$dom='';$url='';$query='';
  $method=$ENV{'REQUEST_METHOD'};
  $dom=$ENV{'SERVER_NAME'};
  ($url,$query)=split(/\?/,$ENV{'REQUEST_URI'});
  if (! defined $query){$query=''}
  return;
  }
sub load_api_templates
  {
  my $r=shift;
  my($sth,@row);
  my @api_pages=("/api/add_page", "/api/login");
  foreach( @api_pages )
    {
    next if (defined $api{$_});
    $sth=$dbh->prepare("select body from pages where url=?" ) or die $!;
    $sth->execute($_);
    @row=$sth->fetchrow_array;
    $api{$_}=$row[0];
    }
  return;
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
  my ($sth,@row,$body);
  $sth=$dbh->prepare("SELECT body from pages where url=? and domain=? and active=?");
  $sth->execute($url,$dom,'true');
  @row   = $sth->fetchrow_array;
  if ($#row == -1) # can't find $dom$url in pages table
    {
    if ($query eq 'edit')
      { create_page($r) }
    else
      {
      error_404($r);
      }
    }
  else # $dom$url is in pages table
    {
    if ($query eq 'edit')
      { edit_page($r,$row[0]) }
    else
      {
      $body = $row[0];
      output_body($r,$row[0],'text/html');
      #    print after_snippets($body);
      }
    }
  return;
  }
sub create_page
  {
  my $r=shift;
  my $body=$api{'/api/add_page'};
  $body =~ s/URL_VALUE/$url/;
  $body =~ s/DOMAIN_VALUE/$dom/;
  $body =~ s/TEXTAREA_VALUE//;
  output_body($r,$body,'text/html');
  return;
  }
sub edit_page
  {
  my $r=shift;
  my $page_to_edit=shift;
  my $body=$api{'/api/add_page'};
  $body =~ s/URL_VALUE/$url/;
  $body =~ s/DOMAIN_VALUE/$dom/;
  $body =~ s/TEXTAREA_VALUE/$page_to_edit/;
  output_body($r,$body,'text/html');
  return;
  }
sub error_404
  {
  my $r=shift;
  $r->status(Apache2::Const::NOT_FOUND);
  output_body($r,"Error 404: Couldn't find $dom$url in the database",'text/html');
  }
sub no_api_endpoint
  {
  my $r=shift;
  $r->status(Apache2::Const::NOT_FOUND);
  output_body($r,"Error 404: API Endpoint not found",'text/html');
  }
sub handle_post
  {
  my $r=shift;
  print "looking for $url in handle_post<br>\n";
  my $sth=$dbh->prepare("SELECT url from api_endpoints where url=?");
  $sth->execute($url);
  my @row   = $sth->fetchrow_array;
  if ($#row == 0 )
    {
    if($url eq '/api/add_page') { store_page($r) }
    }
  else
    { no_api_endpoint($r) }
  return
  }
sub store_page
  {
  my $r=shift;
  my $ip=$ENV{REMOTE_ADDR};
  if ($ip ne '72.201.204.99')
    { error_forbidden($r,"Error 403: posting not allowed, right now.");return;}
  my $data=<STDIN>;
  my %args;
  my @args=split(/&/,$data);
  foreach (@args)
    {
    my ($x,$y)=split(/=/);
    $args{$x}=uri_unescape($y);
    }
  $args{page} =~ s/\+/ /g;
  my $sth=$dbh->prepare("SELECT version_num from pages where url=? and domain=? and active=?");
  $sth->execute($args{url},$args{domain},'true');
  my @row=$sth->fetchrow_array;
  my $new_version;
  if ($#row == 0) # found a single row = good, one version active
    {
    $new_version=$row[0];
    $sth=$dbh->prepare("update pages set active='false' where version_num=? and url=? and domain=?");
    $sth->execute($new_version,$args{url},$args{domain});
    $new_version++;
    }
  elsif ($#row == -1) { $new_version=1; } # no $dom/$url in db, add it
  else
    {
    $r->status(Apache2::Const::HTTP_INTERNAL_SERVER_ERROR);
    $r->content_type('text/html');
    $r->print("Error 500: something went horribly wrong");
    # and should never happen...
    return Apache2::Const::HTTP_INTERNAL_SERVER_ERROR;
    }
  $sth=$dbh->prepare("INSERT INTO pages (body,url,domain,creation_time,username,useruuid,remote_addr,active,version_num) values (?,?,?,?,?,?,?,?,?)");
  $sth->execute($args{page},$args{url},$args{domain},now(),'admin','68489091-f591-4ba8-993c-a7421d688e8e',$ip,'true',$new_version);
  $r->headers_out->set(Location => "http://$args{domain}$args{url}");
  $r->status(Apache2::Const::REDIRECT);
  return Apache2::Const::REDIRECT;
  }
sub now
  {
  my $dt=DateTime->now();
  return $dt->year."-".$dt->month."-".$dt->day." ".$dt->hms;
  }
sub error_forbidden
  {
  my ($r,$msg)=@_;
  $r->status(Apache2::Const::FORBIDDEN);
  output_body($r,$msg,'text/html');
  }
sub handle_head
  {
  my $r=shift;
  $r->content_type('text/html; charset=UTF-8');
  return;
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
  $r->print($body);
  return Apache2::Const::OK;
  }
1;

