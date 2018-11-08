package MyApache2::cms3;

use strict;
use warnings;

use Apache2::RequestRec ();
use Apache2::RequestIO  ();
use Apache2::Const
  qw(OK NOT_FOUND REDIRECT FORBIDDEN HTTP_INTERNAL_SERVER_ERROR);

use APR::Table ();
use APR::UUID;
use DBD::Pg;
use DateTime;
use URI::Escape::XS qw/uri_escape uri_unescape/;
use Encode;
use utf8;
use Crypt::Eksblowfish::Bcrypt qw(bcrypt);
use Crypt::Random::Source;
use Email::Address;
use MIME::Lite;    # may have issues - old module, needs replaced.
use CGI::Cookie;
use Readonly;
our $VERSION = 3.0;

# the global database handle
my ($dbh);

# variables to be populated from %ENV
my ( $method, $ip, $url, $dom, $query );

# variables to get from cookies
my ( $useruuid, $session );
my $whoami;

# global variable to load api endpoint template bodies into
my ( %api, %valid_api );

# global snippets dispatch list
my %snippets;

Readonly::Scalar my $MAX_LENGTH_HASH => 16;
Readonly::Scalar my $TWO_WEEKS       => 86_400 * 14;
Readonly::Scalar my $SALT_MAX          => 12;
Readonly::Scalar my $MIN_PW_LENGTH     => 8;
Readonly::Scalar my $ALLOWED_LITERAL_3 => 3;

sub init_db {

    # starting to look a lot more like a generic init section...
    my $r      = shift;
    my %foo    = $r->dir_config->get('foo');
    my $dbname = $foo{'dbname'};
    my $dbuser = $foo{'dbuser'};
    $dbh =
      DBI->connect( "dbi:Pg:dbname=$dbname", $dbuser, q//, { AutoCommit => 1 } )
      or carp $STDERR;
#
# since init_db runs with every connection to the server, we clear variables and make
# sure the /api templates are pre-loaded, just once.  If they change, then the server
# has to be restarted
#
    load_api_templates($r);
    setup_snippets();
    #
    $session  = 0;
    $useruuid = 0;
    #
    $method = q//;
    $dom    = q//;
    $url    = q//;
    $query  = q//;
    $method = $ENV{'REQUEST_METHOD'};
    $dom    = $ENV{'SERVER_NAME'};
    $ip     = $ENV{'REMOTE_ADDR'};
    ( $url, $query ) = split /[?]/smx, $ENV{'REQUEST_URI'};

    if ( !defined $query )             { $query = q// }
    
    ##################################################
    # you may need to uncomment/edit the line below: #
    ##################################################

    # if ( $dom eq 'www.YOUR_DOMAIN' ) { $dom   = 'YOUR_DOMAIN' }
    if ( $dom eq 'www.perl-user.com' ) { $dom   = 'perl-user.com' }

    ######################################################################
    # otherwise, the www version of your domain will see different pages #
    # also: add ServerAlias www.YOUR_DOMAIN in the httpd.conf            #
    ######################################################################
    
    $whoami = q//;
    check_cookies($r);

    return;
}

sub load_api_templates {
    my $r = shift;
    my ( $sth, @row );

    # some api endpoints load a form, some are loaded from GET calls
    # some are just commands to call and don't require a page load.
    my @api_pages = qw(/api/add_page /api/login /api/register /api/delete_page /api/change_pw);
    foreach (@api_pages) {
        next if ( defined $api{$_} );
        $sth = $dbh->prepare('SELECT body FROM pages WHERE url=?')
          or carp $STDERR;
        $sth->execute($_);
        @row = $sth->fetchrow_array;
        $api{$_} = $row[0];
    }

    # load %valid_api if it hasn't loaded yet
    return if ( keys %valid_api );

    # need to restart httpd to reload new endpoints
    $sth = $dbh->prepare('SELECT url FROM api_endpoints');
    $sth->execute();
    while ( @row = $sth->fetchrow_array ) {
        $valid_api{ $row[0] } = 1;
    }
    return;
}

sub setup_snippets {
    %snippets = (
        'dom'               => \&dom,
        'url'		    => \&url,
        'created'           => \&created,
        'allpages'          => \&allpages,
        'edit'              => \&edit,
        'is_user_logged_in' => \&is_user_logged_in,
	'updated'	    => \&updated,
        'version'	    => \&version,
        'bytes'		    => \&bytes,
        'words_stripped'    => \&words_stripped,
	'generate_pw'	    => \&generate_pw,
    );
    return;
}

sub after_snippets {
    my $body = shift;

    while ( $body =~ /~~([\w-]+|[.]+)~~/smx ) {
        my $match = $1;
        if ( exists $snippets{$match} ) {

            # warn log_time_string(),"found a snippet match for $match\n";
            if ( $query eq 'debug' ) {
                warn log_time_string(),
                  " after_snippets is replacing ~~$match~~ in $dom$url\n";
            }
            my $results = $snippets{$match}->();
            if ( !$results ) {
                warn log_time_string(),
"$dom$url match=$match snippet=$snippets{$match} results=$snippets{$match}->()\n";
                return $body;
            }
            $body =~ s/~~$match~~/$results/smx;
        }
        else {
            my $results = "**error, snippet $match not found**";
            $body =~ s/~~$match~~/$results/smx;
        }
    }
    return $body;
}

sub dom {
    return $dom;
}
sub url {
    return $url;
}

sub updated
  {
  my ($sth,@row);
  $sth   = $dbh->prepare("select creation_time from pages as p,valid_domains as d where p.url=? and d.domain=? and d.id=p.domain_id and p.active");
  $sth->execute($url,$dom);
  @row = $sth->fetchrow_array;
  if ($#row < 0)
    {return "error: creation_time not found";}
  my $dt = DateTime->from_epoch(epoch => $row[0]);
  $dt->set_time_zone('America/Phoenix');
  return $dt->hms." [MST] on ".$dt->ymd;
  }

sub version
  {
  my ($sth,@row);
  $sth   = $dbh->prepare("select version_num from pages as p,valid_domains as d where p.url=? and d.domain=? and d.id=p.domain_id and p.active");
  $sth->execute($url,$dom);
  @row = $sth->fetchrow_array;
  if ($#row < 0)
    {return "error: version_num not found";}
  else
    { return $row[0] }
  }

sub bytes
  {
  my ($sth,@row);
  $sth = $dbh->prepare("select body from pages as p,valid_domains as d where p.url=? and d.domain=? and d.id=p.domain_id and p.active");
  $sth->execute($url,$dom);
  @row = $sth->fetchrow_array;
  if ($#row < 0)
    {return "error: strange, body not found..."}
  else
    {
    my $body=$row[0];
    $body =~ s/<[^<]*>//g;
    return length( uri_unescape( $body ) );
    }
  }

sub words_stripped
  {
  my ($sth,@row);
  $sth = $dbh->prepare("select body from pages as p,valid_domains as d where p.url=? and d.domain=? and d.id=p.domain_id and p.active");
  $sth->execute($url,$dom);
  @row = $sth->fetchrow_array;
  if ($#row < 0)
    {return "error: strange, body not found..."}
  else
    {
    my $body=$row[0];
    $body =~ s/<[^<]*>//g;
    my $len=length( uri_unescape($body));
    return (int( $len / 5 )+1);
    }
  }

sub generate_pw
  {
  my $alpha='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789~!@#$%^&*()_+-={}[];:,.<>?/\|';
  my $temp=q//;
  for (1..20){$temp=$temp.substr($alpha,int(rand(91)),1);}
  $temp =~ s/\</&lt;/g;
  return "<pre>$temp</pre>";
  }

sub edit {
    # if ( $ip ne '72.201.204.99' ) { return q/ /; }
    if ( $ip !~ /^192[.]168[.]1[.]/ ) { return }
    else {
        return
"<li><a href=\"$url?edit\"><span class=\"glyphicon glyphicon-pencil\"></span></a></li>";
    }
}

sub is_user_logged_in {
    if   ($whoami) { return "Welcome: $whoami"; }
    else           { return "<a href=\"http://$dom/api/login\">LOGIN</a>" }
}

sub created {
    my ( @r, $sth );
    $sth = $dbh->prepare(
'SELECT creation_time FROM pages AS p,valid_domains AS d WHERE url=? and d.domain=? and active and p.domain_id=d.id'
    );
    $sth->execute( $url, $dom );
    @r = $sth->fetchrow_array;
    if ( $#r < 0 ) { return "Error, no rows for $dom$url in pages table\n"; }
    my $dt = DateTime->from_epoch( epoch => $r[0] );

    # unpolite to force my timezone but hey...
    $dt->set_time_zone('America/Phoenix');
    return $dt->hms . ' [MST] on ' . $dt->ymd;
}

sub allpages {
    my ( @r, $ret, $sth,$count );

    $sth = $dbh->prepare(
'SELECT url,d.domain FROM pages AS p,valid_domains AS d WHERE d.domain=? and active and p.domain_id=d.id order by p.creation_time DESC'
    ) or carp $STDERR;
    $sth->execute($dom) or carp $STDERR;
    @r = $sth->fetchrow_array;
    $count=1;
    if ( $#r < 0 ) { return "no pages found for $dom at all!!" }
    else {
  # todo: think about loading this from a snippets table, then do bunch of s///;
        $ret =
"<h4>Pages on $dom</h4><div style='display: inline-block; width: 50px; '>$count </div><div style='display: inline-block; '><a href=\"http://$r[1]$r[0]\"> $r[1]$r[0]</a></div><br>";
    }
    while ( @r = $sth->fetchrow_array ) {
	$count++;
        $ret .= "<div style='display: inline-block; width: 50px; '>$count </div><div style='display: inline-block; '><a href=\"http://$r[1]$r[0]\">$r[1]$r[0]</a></div><br>";
    }
    return $ret;
}

sub handler {
    my $r = shift;
    my $rc;
    init_db($r);
    if ( $ENV{SERVER_PORT} == 443){ warn "$ip on $dom$url:$ENV{SERVER_PORT}\n"}
    if ( $method eq 'GET' )    { $rc = handle_get($r)        }
    if ( $method eq 'POST' )   { $rc = handle_post($r)       }
    if ( $method eq 'HEAD' )   { $rc = handle_head($r)       }
    if ( $method eq 'CONNECT') { $rc = error_no_connects($r) }
    if ($rc)                 { return $rc }
    else {
        return Apache2::Const::OK;
    }
}

sub show_env {
    my $r = shift;
    $r->content_type('text/html');
    foreach ( sort keys %ENV )
      {
      if ($_ eq 'QUERY_STRING')
        { $r->print("$_ ",uri_unescape($ENV{$_}),"<br>\n") }
      elsif ($_ eq 'REQUEST_URI')
        { $r->print("$_ ",uri_unescape($ENV{$_}),"<br>\n") }
      else
        { $r->print("$_ $ENV{$_}<br>\n") }
      }
    return;
}

sub show_my_cookies {
    my $r       = shift;
    my %cookies = CGI::Cookie->fetch;
    my $body    = "These are the cookies saved for $whoami on $dom:<hr>\n";
    my $content = 'text/html';

    foreach ( sort keys %cookies ) {
        $body .= "$_ = " . $cookies{$_}->value . "<br>\n";
    }
    output_body( $r, $body, $content );
    return;
}

sub delete_my_cookies {
    my $r       = shift;
    my %cookies = CGI::Cookie->fetch;

    my $cookie1 = CGI::Cookie->new(
        -name     => 'useruuid',
        -value    => q/--/,
        'max-age' => '+1s'
    );
    my $cookie2 = CGI::Cookie->new(
        -name     => 'session_uuid',
        -value    => q/--/,
        'max-age' => '+1s'
    );
    if ($session) {
        if ( $cookies{session_uuid} ) {
            my $sth = $dbh->prepare('DELETE FROM sessions WHERE sessionuuid=?');
            $sth->execute($session);
        }
    }

    $r->err_headers_out->add( 'Set-Cookie' => $cookie1 );
    $r->err_headers_out->add( 'Set-Cookie' => $cookie2 );

    my $location = "http://$dom/api/show_my_cookies";

    $r->headers_out->set( Location => $location );
    $r->status(Apache2::Const::REDIRECT);
    return Apache2::Const::REDIRECT;
}

sub logout {
    my $r       = shift;
    my %cookies = CGI::Cookie->fetch;

    if ( $cookies{session_uuid} ) {
        $session = $cookies{session_uuid}->value;
    }
    if ($session) {
        my $cookie = CGI::Cookie->new(
            -name     => 'session_uuid',
            -value    => q/--/,
            'max-age' => '+1s',
        );
        $r->err_headers_out->add( 'Set-Cookie' => $cookie );

        my $sth = $dbh->prepare('DELETE FROM sessions WHERE sessionuuid=?');
        $sth->execute($session);
    }
    my $location = "http://$dom/";
    $r->headers_out->set( Location => $location );
    $r->status(Apache2::Const::REDIRECT);
    return Apache2::Const::REDIRECT;
}

sub handle_api_call {
    my $r = shift;

    # my ( @row, $sth );

    if ( !$valid_api{$url} ) { return error_404($r); }
    if ( $url eq '/api/login' ) {
        my $newbody = $api{'/api/login'};
        $newbody =~ s/__DOMAIN__/$dom/gsmx;
        $newbody = after_snippets($newbody);
        output_body( $r, $newbody, 'text/html' );
    }
    if ( $url eq '/api/change_pw' ) {
        my $newbody = $api{'/api/change_pw'};
        $newbody =~ s/__USERNAME__/$whoami/smx;
        $newbody = after_snippets($newbody);
        output_body( $r, $newbody, 'text/html' );
    }
    if ( $url eq '/api/register' ) {
        output_body( $r, $api{'/api/register'}, 'text/html' );
    }
    if ( $url eq '/api/delete_page') {
	output_body( $r, 'ERROR: please do not call /api/delete_page diretly',
	    'text/html' );
    }
    if ( $url eq '/api/add_page' ) {
        output_body( $r, 'ERROR: please do not call /api/add_page directly',
            'text/html' );
    }
    if ( $url eq '/api/show_my_cookies' )   { show_my_cookies($r) }
    if ( $url eq '/api/delete_my_cookies' ) { delete_my_cookies($r) }
    if ( $url eq '/api/logout' )            { logout($r) }
    if ( $url eq '/api/show_env' )          { show_env($r) }
    return;
}

sub register {
    my $r        = shift;
    my %args     = %{ split_input($r) };
    my $password = $args{'password'};
    my $email    = $args{'email'};
    my $user     = $args{'username'};
    my $DEBUG    = 1;
    if ($DEBUG) {
        $r->print("<pre>\nDEBUG output:\n\n");
        $r->print("username: $user\n");
        my $stars = q/*/ x length $password;
        $r->print("password: $stars\n");
        $r->print("email:    $email\n");
        $r->print("</pre>\n");
    }
    if ( $user !~ /^\w+$/smax ) {
        $r->print(
'<h4>ERROR: Username must contain only alpha-numeric or underscore characters</h4>'
        );
        return;
    }
    if ( length($password) < $MIN_PW_LENGTH ) {
        $r->print("<h4>ERROR: Your password is too short</h4>\n");
        return;
    }
    my $valid_address = Email::Address->parse($email);
    if ($valid_address) {
        my ( $userpart, $maildom ) = split /@/smx, $email;
        if ( $maildom !~ /^[\w.-]+$/smax ) {
            $r->print("$maildom does not appear to be a valid domain\n");
            return;
        }
#
#  commenting this out - won't send email right now, just save the validation url
#

#        my $valid_maildom = `dig MX $maildom|grep MX|grep -v '^;' `;
#        if(!$valid_maildom){$r->print("Sorry, $maildom isn't a valid MX server");return;}
    }
    else {
        $r->print("Sorry, unable to validate email address: $email\n");
        return;
    }

#
#   Note: the code below was working, sending a validation email, but I decided to disable it
#     while much of the functionality for multiple users is still unimplemented.   Instead I will
#     add a quick /api/validate-users for user: admin to run to validate alternate users I will use
#     during testing.
#
    $r->print(
        "Generating a validation entry in validate_new_users table<br>\n");

#    $r->print("Generating a validation email<br>\n");
#    $r->print("Don't have an /api/validate yet<br>\n");
#    $r->print("Also, still need to save the data in a new table<br>\n");
#    $r->print(
#        "TODO: add /api/check-validation-request to ID any spammers<br>\n");
#    $r->print(
#"Thinking 2-4 requests from any IP or to a particular email in a 24 hr period.  After that, message: Please Validate Email or wait 24 hours to try again<br>\n"
#    );
    $r->print(
'Note: The version of cms3.pm on <a href="http://github.com/kordaff/cms3">http://github.com/kordaff/cms3</a> is about 3 weeks behind my working version here'
    );
    ######################################################
    my $validation_uuid = APR::UUID->new->format;

#     my $msg             = MIME::Lite->new( From    => 'webmaster@perl-user.com', To      => "$email", Subject => 'Please validate your email', Type    => 'text/html', Data => "<H3>Hello $user</H3>,<br><br>\nPlease click here to validate your email:<br><br>\n<a href='http://$dom/api/validate?$validation_uuid'>http://$dom/api/validate?$validation_uuid</a><br>Please ignore this email if you didnt register a user account on $dom.<br><br>Thank you<br><br>webmaster\@perl-user.cf aka Phil<br><br>\n",);
#
#    Todo: fix that to get user email for owner of this domain.
#
#    MIME::Lite->send( 'smtp', 'perl-user.com', Debug => 1 );
#    $msg->send();

    return;
}

sub handle_get {
    my $r = shift;
    my ( $sth, @row, $body );
    if ( $url =~ /^\/api\//smx ) { return handle_api_call($r) }

    $sth = $dbh->prepare(
'SELECT body FROM pages AS p,valid_domains AS d WHERE p.url=? and d.domain=? and p.active and p.domain_id=d.id'
    );
    $sth->execute( $url, $dom );
    @row = $sth->fetchrow_array;
    if ( $#row < 0 )    # can't find $dom$url in pages table
    {
        if   ( $query eq 'edit' ) { create_page($r) }
	elsif ( $query eq 'delete') { return error_404($r) }
        else                      { return error_404($r) }
    }
    else                # $dom$url is in pages table
    {
        if ( $query eq 'edit' ) { edit_page( $r, $row[0] ) }
        elsif ($query eq 'delete') {delete_form($r)} 
        else                    { process_the_page( $r, $row[0] ) }
    }

    return;
}
sub delete_form
  {
  my $r=shift;
  my $body=$api{'/api/delete_page'};
  $body =~ s/__DOMAIN__/$dom/gsmx;
  $body =~ s/__URL__/$url/gsmx;
  $body = after_snippets($body);
  output_body( $r, $body, 'text/html' ) ;
  return;
  }

sub process_the_page {
    my ( $r, $body ) = @_;

    if ( $body =~ /~~LOGGEDIN~~/smx ) {

    }
    my $content = 'text/html';
    if ( $url =~ /[.]txt$/smx )  { $content = 'text/plain' }
    if ( $url =~ /[.]json$/smx ) { $content = 'application/json' }
    if ( $url =~ /[.]xml$/smx )  { $content = 'text/xml' }
    if ( $url =~ /[.]js$/smx )   { $content = 'application/javascript' }
    if ( $url =~ /[.]css$/smx )  { $content = 'text/css' }

    my $newbody = after_snippets($body);
    $newbody = uri_unescape($newbody);
    output_body( $r, $newbody, $content );
    return;
}

sub create_page {
    my $r = shift;
    if ( !$session )
      {
      $url = uri_unescape($url);
      output_body( $r, "Must be logged in to create page $url", 'text/html' );
      return;
      }

    # my $sth=$dbh->prepare('SELECT u.useruuid,p.ownerid
    #
    # WIP - verify user owns the page...
    #
    my $body = $api{'/api/add_page'};
    $body =~ s/__URL__/$url/smx;
    $body =~ s/__DOMAIN__/$dom/gsmx;
    $body =~ s/TEXTAREA_VALUE//smx;
    $body =~ s/__SESSION__/$session/smx;
    output_body( $r, $body, 'text/html' );
    return;
}

sub edit_page {
    my $r            = shift;
    my $page_to_edit = shift;

    if ( !$session )
      {
      $url = uri_unescape($url);
      output_body( $r, "Must be logged in to edit page $url", 'text/html' );
      return;
      }

    my $body = $api{'/api/add_page'};
    $body =~ s/TEXTAREA_VALUE/$page_to_edit/smx;
    $body =~ s/__DOMAIN__/$dom/gsmx;
    $body =~ s/__SESSION__/$session/smx;
    $body = uri_unescape($body);
    $body =~ s/__URL__/$url/smx;

    output_body( $r, $body, 'text/html' );
    return;
}

sub error_404 {
    my $r = shift;
    $url = uri_unescape($url);
    output_body( $r, "<h5>Error 404: Couldn't find a page matching </h5> <h3>$dom$url</h3><h5> in the database</h5>", 'text/html' );
    $r->status(Apache2::Const::NOT_FOUND);
    #    return Apache2::Const::NOT_FOUND;
    return;
}

sub error_no_connects
  {
  my $r = shift;
  output_body( $r, "Error 403: Proxying not allowed", 'text/html' );
  $r->status(Apache2::Const::FORBIDDEN);
  return;
  }

sub no_api_endpoint {
    my $r = shift;
    $r->status(Apache2::Const::NOT_FOUND);
    output_body( $r, 'Error 404: API Endpoint not found', 'text/html' );
    return Apache2::Const::NOT_FOUND;
}

sub handle_post {
    my $r = shift;
    my $sth = $dbh->prepare('SELECT url FROM api_endpoints WHERE url=?');
    $sth->execute($url);
    my @row = $sth->fetchrow_array;
    if ( $#row == 0 ) {
        if ( $url eq '/api/add_page' )    { return store_page($r)  }
        if ( $url eq '/api/delete_page' ) { return delete_page($r) }
        if ( $url eq '/api/login' )       { return login($r)       }
        if ( $url eq '/api/register' )    { return register($r)    }
        if ( $url eq '/api/change_pw')    { return change_pw($r)   }
    }
    else { return no_api_endpoint($r) }
    return;
}
sub change_pw
  {
  my $r    = shift;
  if (! $session)
    { 
    print "Please login before trying to change passwords\n";
    return;
    }
  my %args = %{ split_input($r) };

  # we have a session, so $whoami should be the right username, right?
  my @row=get_pw_hashes($whoami);

  # first check for regular pw, new1 should match new2
  if ($args{new1_password} && $args{new2_password} && $args{old_password})
    {
    if ($args{new1_password} eq $args{new2_password})
      {
      if ( check_pw( $args{old_password}, $row[0] ))
        {
	my $encrypted = encrypt_password( $args{new1_password} );
        my $sth=$dbh->do("update user_data set password='$encrypted' where username='$whoami' ")or carp $STDERR;
        remove_session_cookie($r);
	print "<html><body>login pw updated <a href=\"http://$dom/api/login\">LOGIN</a>\n</body></html>";
 	} 
      else
        { print "login pw change failed\n" }
      }
    else
      {print "New passwords have to match\n" }
    }
  # next check for delete pw
  if ($args{new1_delete_password} && $args{new2_delete_password} && $args{old_delete_password} )
    {
    if ($args{new1_delete_password} eq $args{new2_delete_password})
      {
      if ( check_pw( $args{old_delete_password}, $row[3] ))
        {
	print "delete pw updated\n";
	my $encrypted = encrypt_password( $args{new1_delete_password} );
        my $sth=$dbh->do("update user_data set delete_password='$encrypted' where username='$whoami' ")or carp $STDERR;
	}
      else
        { print "delete pw change failed\n" }
      }
    else
      {print "New delete passwords have to match\n" }
    }
  return;
  }
sub get_pw_hashes
  {
  my $username=shift;
  my $sth  = $dbh->prepare( 'SELECT password,useruuid,username,delete_password FROM user_data WHERE username=?') or carp $STDERR;
  $sth->execute( $username );
  my @row = $sth->fetchrow_array;
  return (@row);
  }
sub login {
    my $r    = shift;
    my %args = %{ split_input($r) };
    my ($pw_hash,$set_useruuid,$username,$delete_pw_hash)=get_pw_hashes($args{username});
    if ( check_pw( $args{password}, $pw_hash ) ) {

        my $session_uuid = APR::UUID->new->format;
        my $now          = time;

        my $location = "http://$dom/";

        my $cookie1 = CGI::Cookie->new(
            -name     => 'useruuid',
            -value    => $set_useruuid,
            'max-age' => '+36M',
        );

        my $cookie2 = CGI::Cookie->new(
            -name     => 'session_uuid',
            -value    => $session_uuid,
            'max-age' => '+14d',
        );
        #
        # we'll load the max-age for sessions from a user setting later...
        #

        my $sth = $dbh->prepare(
"INSERT INTO sessions (sessionuuid,remote_addr,last_access,last_login,domain_id,userid) SELECT '$session_uuid','$ip',$now,$now,d.id,u.id FROM valid_domains AS d, user_data AS u WHERE d.domain='$dom' and u.username=?"
        );
        $sth->execute( $args{'username'} );

        $r->err_headers_out->add( 'Set-Cookie' => $cookie1 );
        $r->err_headers_out->add( 'Set-Cookie' => $cookie2 );
        $r->headers_out->set( Location => $location );
        $r->status(Apache2::Const::REDIRECT);
        return Apache2::Const::REDIRECT;
    }
    else
      { output_body( $r, "<h4>Login failed on $dom</h4><br>\n", 'text/html' ) }
    return;
}

sub split_input {
    my $r = shift;
    my %args;
    my $data = <STDIN>;
    my @vars = split /&/smx, $data;
    foreach (@vars) {
        my ( $x, $y ) = split /=/smx;
        $args{$x} = $y;
    }

    if ( exists $args{'url'} ) { $args{'url'} = uri_unescape( $args{'url'} ); }
    if ( exists $args{'page'} ) {
        $args{'page'} = Encode::decode_utf8( $args{'page'} );
        $args{'page'} =~ s/%7E/~/gsmx;
    }

    if ( exists $args{page} ) { $args{page} =~ s/[+]/ /gsmx }
    return ( \%args );
}

sub get_page_info
  {
  my ($u,$d)=@_;
  my ($sth, @row);
  $sth = $dbh->prepare('SELECT version_num,p.userid,p.domain_id,u.username FROM pages AS p, valid_domains AS d, user_data AS u WHERE p.domain_id=d.id and url=? and d.domain=? and d.owner_id = u.id ORDER BY version_num DESC LIMIT 1');
  $sth->execute($u,$d);
  @row=$sth->fetchrow_array;
  if (@row)
    { return ($row[0]+1,$row[1],$row[2],$row[3]) }
  else
    { 
    $sth=$dbh->prepare('SELECT owner_id,id FROM valid_domains where domain=?'); 
    $sth->execute($d);
    @row=$sth->fetchrow_array;
    if (@row) { return (1,$row[0],$row[1],'-newpage-' ) }
    else { return (-1,-1,-1,-1) }
    }
  }
sub deactivate_old_versions
  {
  my ($u,$did)=@_;
  my $sth=$dbh->prepare('UPDATE pages SET active=FALSE WHERE url=? and domain_id=?') or carp $STDERR;
  $sth->execute( $u,$did ) or carp $STDERR;
  return;
  }
sub delete_page
  {
  my $r=shift;
  my ($sth,%args,@row);
  if (! $session)
    {print "Only the logged in page owner can delete pages.";return}
  # if ( $ip ne '72.201.204.99' )
  if ($ip !~ /192[.]168[.]1[.]/ )
    {
    error_forbidden( $r, 'Error 403: Deletion not allowed from $ip.' );
    return;
    }
  %args = %{ split_input($r) };
#  print "trying to delete $args{dom}$args{url}\n";

  $sth  = $dbh->prepare( 'SELECT delete_password,u.username,p.userid,url,p.domain_id FROM user_data as u,pages as p,valid_domains as d WHERE u.username=? and url=? and domain=? and p.domain_id=d.id and p.userid=u.id');
  $sth->execute( $whoami,$args{url},$args{dom} );
  @row = $sth->fetchrow_array;
  if ($#row < 0)
    {
    print "query failed, do you own this page?\n";
    $sth = $dbh->prepare('SELECT u.username,d.domain,url from pages as p, valid_domains as d, user_data as u where url=? and d.domain=? and d.id=p.domain_id and p.userid = u.id') or carp $STDERR;
    $sth->execute($args{url}, $args{dom});
    @row=$sth->fetchrow_array;
    # this will only be reached, I hope, for users logged in that dont own 
    # the page...
    print "$row[0] owns $row[1]$row[2]\n";
    }
#  print "got $row[1] $row[2] for $row[3]\n";
  if ( check_pw( $args{pw}, $row[0] ) )
    {
    my $domain_id=$row[4];
    # print "found matching pw for $row[1]\n"
    $sth=$dbh->prepare("update pages set active='FALSE' where domain_id=? and url=?") or carp $STDERR;
    $sth->execute($domain_id,$args{url});
    print "$args{dom}$args{url} deleted\n";
    }
  else 
    { print "incorrect delete password\n" }
  return;
  }
sub store_page {
    my $r = shift;
    my ( $sth, @row, $domain_id, %args, $new_version, $owner_uuid );
    if ( $ip !~ /^192[.]168[.]1[.]/ ) {
    # if ( $ip ne '72.201.204.99' ) {
        error_forbidden( $r, 'Error 403: posting not allowed, right now.' );
        return;
    }
    %args = %{ split_input($r) };
    my ($next_version,$page_userid,$page_did,$page_ownername);

    ($next_version,$page_userid,$page_did,$page_ownername) = 
	get_page_info($args{url},$args{domain});

    if ($next_version == -1)
      {print "Error, no owner_id or id found for $args{domain}\n";return}
    if ($next_version > 1 && $whoami ne $page_ownername)
      {print "Oops, you don't own this page\n";return}

#    print "$whoami $next_version $page_userid $page_did $page_ownername\n";

    if ($next_version > 1)
      {
      deactivate_old_versions($args{url},$page_did)
      }

    $sth=$dbh->prepare('INSERT INTO pages (body,url,domain_id,creation_time,userid,remote_addr,active,version_num) values (?,?,?,?,?,?,?,?)');
    my $t = time;
    $sth->execute($args{page}, $args{url}, $page_did, $t, $page_userid, $ip, 'TRUE', $next_version );
    $r->headers_out->set( Location => "http://$args{domain}$args{url}" );
    $r->status(Apache2::Const::REDIRECT);
    return Apache2::Const::REDIRECT;
  }

sub now {
    my $dt = DateTime->now();
    return $dt->year . q/-/ . $dt->month . q/-/ . $dt->day . q/ / . $dt->hms;
}

sub log_time_string {
    my $dt = DateTime->now();
    $dt->set_time_zone('America/Phoenix');
    return
        '['
      . $dt->day_abbr . q/ /
      . $dt->month_abbr . q/ /
      . $dt->day . q/ /
      . $dt->hms . q/ /
      . $dt->year . ' MST]';
}

sub error_forbidden {
    my ( $r, $msg ) = @_;
    $r->status(Apache2::Const::FORBIDDEN);
    output_body( $r, $msg, 'text/html' );
    return Apache2::Const::FORBIDDEN;
}

sub handle_head {
    my $r = shift;
    $r->content_type('text/html; charset=UTF-8');
    return Apache2::Const::OK;
}

sub retr_cookies {

    # sets $useruuid and $session if cookies exist for them
    my %cookies = CGI::Cookie->fetch;
    if ( $cookies{useruuid} )     { $useruuid = $cookies{useruuid}->value; }
    if ( $cookies{session_uuid} ) { $session  = $cookies{session_uuid}->value; }
    return;
}

sub check_cookies {
    my $r = shift;
    my ( $t, $sth, @row );

    retr_cookies();
    if ( !$session ) { return }
    if ( $useruuid !~ /^[a-f\d-]*$/asmx ) { $session = 0; return }
    if ( $session eq q/--/ ) { $session = 0; return }
    $sth = $dbh->prepare(
'SELECT last_access,s.id,remote_addr,username FROM sessions as s,user_data as u WHERE sessionuuid=? and remote_addr=? '
    );
    $sth->execute( $session, $ip );
    @row = $sth->fetchrow_array;
    $t   = time;
    if ( $#row < 0 ) { $session = 0; return }    # invalid cookies/session
    else {

        if ( $t - $row[0] > $TWO_WEEKS ) {
            $sth = $dbh->prepare('delete from sessions where id=?');
            $sth->execute( $row[1] ) or carp $STDERR;
            warn log_time_string(), ' Session is ', $t - $row[0],
" past expiration, removing expired session $row[1] for $session from table sessions\n";
            $session = 0;   # should remove session from db and remove cookie...
            remove_session_cookie($r);
            return;
        }    # expired session
        else {
            $dbh->do("UPDATE sessions set last_access='$t' WHERE id='$row[1]'");

# warn log_time_string(), "Session for $row[3] is ", $t - $row[0], " since last access: $session\n";
            $whoami = $row[$ALLOWED_LITERAL_3];
        }
    }
    return;
}

sub remove_session_cookie {
    my $r = shift;

    # no redirect
    my $cookie = CGI::Cookie->new(
        -name     => 'session_uuid',
        -value    => q/--/,
        'max-age' => '+1s',
    );
    $r->headers_out->add( 'Set-Cookie' => $cookie );
    return;
}

sub output_body {
    my ( $r, $body, $content_type ) = @_;

    # can't use Strict-Transport-Security: max-age=<expire-time>
    # until SSL is enabled - maybe set to expire 1-2 days before cert does...
    # $r->headers_out->set();
    #
    #    my $t=time()+86400*90;
    #    my $maxage="max-age=$t";
    #    $r->headers_out->set('Strict-Transport-Security' => $maxage        );
    $r->headers_out->set( 'X-Frame-Options'  => 'sameorigin' );
    $r->headers_out->set( 'X-XSS-Protection' => '1; mode=block' );

   #    $r->headers_out->set('Content-Security-Policy' => 'default-src https:');
    $r->headers_out->set( 'X-Content-Type-Options' => 'nosniff' );
    $r->headers_out->set( 'Referrer-Policy'        => 'same-origin' );

    $r->content_type($content_type);
    $r->print($body);
    return;
}

sub encrypt_password {
    my $password = shift;
    my $salt     = shift || salt();
    my $hash     = Crypt::Eksblowfish::Bcrypt::bcrypt_hash(
        {
            key_nul => 1,
            cost    => 8,
            salt    => $salt,
        },
        $password
    );

    return join( '-', $salt, Crypt::Eksblowfish::Bcrypt::en_base64($hash) );
}

sub salt {
    return Crypt::Eksblowfish::Bcrypt::en_base64(
        Crypt::Random::Source::get_strong($SALT_MAX) );
}

sub check_pw {
    my ( $pw, $hash ) = @_;
    my ($salt) = split /-/smx, $hash, 2;
    return length $salt == $MAX_LENGTH_HASH && crypt_pw( $pw, $salt ) eq $hash;
}

sub crypt_pw {
    my $pw   = shift;
    my $salt = shift || salt();
    my $hash = Crypt::Eksblowfish::Bcrypt::bcrypt_hash(
        {
            key_nul => 1,
            cost    => 8,
            salt    => $salt,
        },
        $pw
    );
    return $salt . q/-/ . Crypt::Eksblowfish::Bcrypt::en_base64($hash);

    # using q/-/ to get around warnings in perlcritic -brutal
}

1;
