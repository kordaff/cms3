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
my ( $cookie_useruuid, $usersession );

# global variable to load api endpoint template bodies into
my ( %api, %valid_api );

Readonly::Scalar my $MAX_LENGTH_HASH => 16;
Readonly::Scalar my $TWO_WEEKS       => 86_400 * 2;
Readonly::Scalar my $SALT_MAX        => 12;
Readonly::Scalar my $MIN_PW_LENGTH   => 8;

#
# TODO: add a variable to enable/disable /api/register here
#

sub init_db {
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
    #
    $usersession     = 0;
    $cookie_useruuid = 0;
    check_cookies();
    #
    $method = q//;
    $dom    = q//;
    $url    = q//;
    $query  = q//;
    $method = $ENV{'REQUEST_METHOD'};
    $dom    = $ENV{'SERVER_NAME'};
    $ip     = $ENV{REMOTE_ADDR};
    ( $url, $query ) = split /[?]/smx, $ENV{'REQUEST_URI'};
    if ( !defined $query )             { $query = q// }
    if ( $dom eq 'www.userconfig.cf' ) { $dom   = 'userconfig.cf' }
    if ( $dom eq 'meso.perl-user.com' ) { $dom   = 'vitriol.perl-user.com' }

    # $url =~ s/[][;\'"(){}\\]*//g;
    return;
}

sub load_api_templates {
    my $r = shift;
    my ( $sth, @row );
    #
    # some api endpoints load a form, some are loaded from GET calls
    # some are just commands to call and don't require a page load.
    #
    # my @api_pages = qw(/api/add_page /api/login /api/register);
    my @api_pages = qw(/api/add_page /api/login);
    foreach (@api_pages) {
        next if ( defined $api{$_} );
        $sth = $dbh->prepare('select body from pages where url=?')
          or carp $STDERR;
        $sth->execute($_);
        @row = $sth->fetchrow_array;
        $api{$_} = $row[0];
    }

    # load %valid_api if it hasn't loaded yet
    return if ( keys %valid_api );
    #
    # need to restart httpd to reload new endpoints
    #
    $sth = $dbh->prepare('select url from api_endpoints');
    $sth->execute();
    while ( @row = $sth->fetchrow_array ) {
        $valid_api{ $row[0] } = 1;
    }
    return;
}

sub handler {
    my $r = shift;
    my $rc;

    # bubble up $rc/return code from each sub to get final return $rc here.
    # any subs returning with just return will get Apache2::Const::OK;
    init_db($r);
    if ( $method eq 'GET' )  { $rc = handle_get($r) }
    if ( $method eq 'POST' ) { $rc = handle_post($r) }
    if ( $method eq 'HEAD' ) { $rc = handle_head($r) }
    if ($rc)                 { return $rc }
    else {
        return Apache2::Const::OK;
    }
}

sub show_env {
    my $r = shift;
    $r->content_type('text/html');
    foreach ( sort keys %ENV ) { $r->print("$_ $ENV{$_}<br>\n") }
    return;
}

sub show_my_cookies {
    my $r       = shift;
    my %cookies = CGI::Cookie->fetch;
    my $body    = "These are the cookies we have saved:<hr>\n";
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
    if ( $cookies{session_uuid} ) {
        my $sth = $dbh->prepare('DELETE FROM sessions where sessionuuid=?');
        $sth->execute($usersession);
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
        $usersession = $cookies{session_uuid}->value;
    }
    if ($usersession) {
        my $cookie = CGI::Cookie->new(
            -name     => 'session_uuid',
            -value    => q/--/,
            'max-age' => '+1s',
        );
        $r->err_headers_out->add( 'Set-Cookie' => $cookie );

        my $sth = $dbh->prepare('DELETE FROM sessions where sessionuuid=?');
        $sth->execute($usersession);
    }
    my $location = "http://$dom/";
    $r->headers_out->set( Location => $location );
    $r->status(Apache2::Const::REDIRECT);
    return Apache2::Const::REDIRECT;
}

sub handle_api_call {
    my $r = shift;
    if ( !$valid_api{$url} ) { return error_404($r); }
    if ( $url eq '/api/login' ) {
        output_body( $r, $api{'/api/login'}, 'text/html' );
    }
#    if ( $url eq '/api/register' ) { output_body( $r, $api{'/api/register'}, 'text/html' ); }
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
    my %args     = %{ split_input() };
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

#     my $msg             = MIME::Lite->new( From    => 'webmaster@perl-user.com', To      => "$email", Subject => 'Please validate your email', Type    => 'text/html', Data => "<H3>Hello $user</H3>,<br><br>\nPlease click here to validate your email:<br><br>\n<a href='http://userconfig.cf/api/validate?$validation_uuid'>http://userconfig.cf/api/validate?$validation_uuid</a><br>Please ignore this email if you didnt register a user account on userconfig.cf.<br><br>Thank you<br><br>webmaster\@perl-user.cf aka Phil<br><br>\n",);
#    MIME::Lite->send( 'smtp', 'perl-user.com', Debug => 1 );
#    $msg->send();

    return;
}

sub handle_get {
    my $r = shift;
    my ( $sth, @row, $body );
    if ( $url =~ /^\/api\//smx ) { return handle_api_call($r) }
    $sth = $dbh->prepare(
        'SELECT body from pages where url=? and domain=? and active=?');
    $sth->execute( $url, $dom, 'TRUE' );
    @row = $sth->fetchrow_array;
    if ( $#row < 0 )    # can't find $dom$url in pages table
    {
        if ( $query eq 'edit' ) { create_page($r) }
        else {
            return error_404($r);
        }
    }
    else                # $dom$url is in pages table
    {
        if ( $query eq 'edit' ) { edit_page( $r, $row[0] ) }
        else                    { process_the_page( $r, $row[0] ) }
    }

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
    output_body( $r, $body, $content );

    return;

    #    print after_snippets($body);
}

sub create_page {
    my $r    = shift;
    my $body = $api{'/api/add_page'};
    $body =~ s/URL_VALUE/$url/smx;
    $body =~ s/DOMAIN_VALUE/$dom/smx;
    $body =~ s/TEXTAREA_VALUE//smx;
    output_body( $r, $body, 'text/html' );
    return;
}

sub edit_page {
    my $r            = shift;
    my $page_to_edit = shift;
    my $body         = $api{'/api/add_page'};
    $body =~ s/URL_VALUE/$url/smx;
    $body =~ s/DOMAIN_VALUE/$dom/smx;
    $body =~ s/TEXTAREA_VALUE/$page_to_edit/smx;
    output_body( $r, $body, 'text/html' );
    $r->print("url=$url");
    return;
}

sub error_404 {
    my $r = shift;
    $r->status(Apache2::Const::NOT_FOUND);
    output_body( $r, "Error 404: Couldn't find $dom$url in the database",
        'text/html' );
    return Apache2::Const::NOT_FOUND;
}

sub no_api_endpoint {
    my $r = shift;
    $r->status(Apache2::Const::NOT_FOUND);
    output_body( $r, 'Error 404: API Endpoint not found', 'text/html' );
    return Apache2::Const::NOT_FOUND;
}

sub handle_post {
    my $r   = shift;
    my $sth = $dbh->prepare('SELECT url from api_endpoints where url=?');
    $sth->execute($url);
    my @row = $sth->fetchrow_array;
    if ( $#row == 0 ) {
        if ( $url eq '/api/add_page' ) { return store_page($r) }
        if ( $url eq '/api/login' )    { return login($r) }
#        if ( $url eq '/api/register' ) { return register($r) }
    }
    else { return no_api_endpoint($r) }
    return;
}

sub login {
    my $r    = shift;
    my %args = %{ split_input() };
    my $sth =
      $dbh->prepare('select password,useruuid from user_data where username=?');
    $sth->execute( $args{username} );
    my @row = $sth->fetchrow_array;
    if ( check_pw( $args{password}, $row[0] ) ) {
        #
        #
        add_session();
        #
        # add_session() isnt written yet
        #
        my $session_uuid = APR::UUID->new->format;
        my $useruuid     = $row[1];
        my $now          = time;
        my $last_access  = $now;

        my $location = "http://$dom/";

        my $cookie1 = CGI::Cookie->new(
            -name     => 'useruuid',
            -value    => $useruuid,
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
        $sth = $dbh->prepare(
'INSERT INTO sessions (sessionuuid,useruuid,last_login,last_access,remote_addr) values (?,?,?,?,?)'
        );
        $sth->execute( $session_uuid, $useruuid, $now, $last_access, $ip );

        $r->err_headers_out->add( 'Set-Cookie' => $cookie1 );
        $r->err_headers_out->add( 'Set-Cookie' => $cookie2 );
        $r->headers_out->set( Location => $location );
        $r->status(Apache2::Const::REDIRECT);
        return Apache2::Const::REDIRECT;
    }
    else {
        # $r->print("<h4>Login failed</h4><br>\n")

        output_body( $r, "<h4>Login failed</h4><br>\n", 'text/html' );

    }
    return;
}

sub add_session {
    return;
}

sub split_input {
    my %args;
    my $data = <STDIN>;
    my @vars = split /&/smx, $data;
    foreach (@vars) {
        my ( $x, $y ) = split /=/smx;
        $args{$x} = uri_unescape($y);
    }
    if ( exists $args{page} ) { $args{page} =~ s/[+]/ /gsmx }
    return ( \%args );
}

sub store_page {
    my $r = shift;
    if ( $ip !~ /192[.]168[.]1[.]/ ) {
        error_forbidden( $r, 'Error 403: posting not allowed, right now.  Check line #461 for correct subnet or ip match - default is to allow posts from 192.168.1.0/24 by regex 192.168.1. ' );
        return;
     }

    my %args = %{ split_input() };

    my $sth = $dbh->prepare(
        'SELECT version_num from pages where url=? and domain=? and active=?');
    $sth->execute( $args{url}, $args{domain}, 'TRUE' );
    my @row = $sth->fetchrow_array;
    my $new_version;
    if ( $#row == 0 )    # found a single row = good, one version active
    {
        $new_version = $row[0];
        $sth         = $dbh->prepare(
'update pages set active=FALSE where version_num=? and url=? and domain=?'
        );
        $sth->execute( $new_version, $args{url}, $args{domain} );
        $new_version++;
    }
    elsif ( $#row < 0 ) { $new_version = 1; }    # no $dom/$url in db, add it
    else {
        $r->status(Apache2::Const::HTTP_INTERNAL_SERVER_ERROR);
        $r->content_type('text/html');
        $r->print('Error 500: something went horribly wrong');

        # and should never happen...
        return Apache2::Const::HTTP_INTERNAL_SERVER_ERROR;
    }
    $sth = $dbh->prepare(
'INSERT INTO pages (body,url,domain,creation_time,username,useruuid,remote_addr,active,version_num) values (?,?,?,?,?,?,?,?,?)'
    );
    my $t = time;
    $sth->execute( $args{page}, $args{url}, $args{domain}, $t, 'admin',
        '68489091-f591-4ba8-993c-a7421d688e8e',
        $ip, 'TRUE', $new_version );
    $r->headers_out->set( Location => "http://$args{domain}$args{url}" );
    $r->status(Apache2::Const::REDIRECT);
    return Apache2::Const::REDIRECT;
}

sub now {
    my $dt = DateTime->now();
    return $dt->year . q/-/ . $dt->month . q/-/ . $dt->day . q/ / . $dt->hms;
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

sub check_cookies {

    # my ( $cookie_useruuid, $usersession );
    #   -name      => 'useruuid',
    #   -name      => 'session_uuid',
    my %cookies = CGI::Cookie->fetch;
    if ( $cookies{useruuid} ) {
        $cookie_useruuid = $cookies{useruuid}->value;
    }
    if ( $cookie_useruuid !~ /^[a-f\d-]*$/asmx ) { $usersession = 0; return }
    if ( $cookies{session_uuid} ) {
        $usersession = $cookies{session_uuid}->value;
    }
    if ( !$usersession ) { return }
    if ( $usersession eq q/--/ ) { $usersession = 0; return }
    my $sth = $dbh->prepare(
'SELECT last_access,id from sessions where sessionuuid=? order by id desc limit 1'
    );
    $sth->execute($usersession);
    my @row = $sth->fetchrow_array;

    my $t = time;
    if ( $#row < 0 ) {

        # invalid cookies/session
        $usersession = 0;
    }
    else    # 1 or more rows, if more than 1 row, remove the extras from this ip
    {
        if ( $t - $row[0] > $TWO_WEEKS ) {
            $usersession = 0;
        }    # expired session
        else {
            $dbh->do(
                "update sessions set last_access='$t' where id='$row[1]' ");

        }    # good, refresh last_access
        if ( $#row > 0 ) {
            $dbh->do(
"delete from sessions where sessionuuid='$usersession' and id<'$row[1]'"
            );
        }
    }
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

