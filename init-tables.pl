#!/usr/bin/perl
#
use strict;
use warnings;
use DBD::Pg;
use APR::UUID;
use Crypt::Eksblowfish::Bcrypt qw(bcrypt);
use Crypt::Random::Source;
# use URI::Escape::XS qw/uri_escape uri_unescape/;
our $VERSION = 0.3;

my $dbh=DBI->connect('dbi:Pg:dbname=cms3','cms3','',{AutoCommit=>1,RaiseError=>1,PrintError=>1} ) or die $!;
print "Connected to database.\n";
my ( @row, $sth, $query );

my $user            = 'admin';
my $userid          = 0;
my $OTHER_domain_id = 0;
my $ALL_domain_id   = 0;

##################
## change these ##
##################
my $password   = 'admin';
my $del_passwd = '123';
my $email = 'change_me@perl-user.com';
my $domain = 'some-test-vm.perl-user.com';
##################

print "May need to generate randomness here...\n";

my $encrypted  = encrypt_password($password);
my $encrypt_delpw = encrypt_password($del_passwd);

my $uuid  = APR::UUID->new->format;
my $t     = time;


print "Creating tables....\n";
create_table_pages();
create_table_comments();
create_table_notes();
create_table_access_log();
create_table_user_data();
create_table_valid_domains();

create_table_api_endpoints();
load_api_form_pages();
create_table_sessions();
exit;

sub create_table_pages {

    $sth = $dbh->do(
'CREATE TABLE pages ( id SERIAL PRIMARY KEY, body text, url text, creation_time integer, remote_addr text, active boolean, version_num integer, userid integer, domain_id integer)'
    ) or die $!;
    print "Created table: pages\n";
}

sub create_table_comments {
    $sth = $dbh->do(
"CREATE TABLE comments (id SERIAL PRIMARY KEY,body text,url text,domain text,comment_time integer,remote_addr text,username text,useruuid uuid); "
    ) or die $!;
    print "Created table: comments\n";
}

sub create_table_notes {
    $sth = $dbh->do(
"CREATE TABLE notes (id SERIAL PRIMARY KEY,body text,url text,domain text,note_time integer,remote_addr text,username text,useruuid uuid); "
    ) or die $!;
    print "Created table: notes\n";
}

sub create_table_access_log {
    $sth = $dbh->do(
"CREATE TABLE access_log (id SERIAL PRIMARY KEY,url text, domain text,method text,access_time timestamp without time zone,remote_ip text,refer text,user_agent text,created timestamp without time zone); "
    ) or die $!;
    print "Created table: access_log\n";
}

sub create_table_user_data {
    $sth = $dbh->do(
'CREATE TABLE user_data ( id SERIAL PRIMARY KEY, username text, useruuid uuid, email text, user_created integer, password TEXT, delete_password TEXT)'
    ) or die $!;

    $sth = $dbh->do(
"INSERT INTO user_data (username, useruuid, email, user_created, password,delete_password) values('$user','$uuid','$email','$t','$encrypted','$encrypt_delpw')"
    );
    $sth = $dbh->prepare('select id from user_data where username=?');
    $sth->execute($user);
    my @row = $sth->fetchrow_array;
    $userid = $row[0];
    print "Created table: user_data\n";
    print "Created user $user with uuid = $uuid and userid=$userid\n";
}

sub create_table_api_endpoints {
    $sth = $dbh->do("CREATE TABLE api_endpoints (url text); ") or die $!;

    $sth = $dbh->do("INSERT INTO api_endpoints(url) values ('/api/add_page'   )");
    $sth = $dbh->do("INSERT INTO api_endpoints(url) values ('/api/login'      )");
    $sth = $dbh->do("INSERT INTO api_endpoints(url) values ('/api/delete_page')");
    $sth = $dbh->do("INSERT INTO api_endpoints(url) values ('/api/show_my_cookies')");
    $sth = $dbh->do("INSERT INTO api_endpoints(url) values ('/api/delete_my_cookies')");
    $sth = $dbh->do("INSERT INTO api_endpoints(url) values ('/api/show_env')");
    $sth = $dbh->do("INSERT INTO api_endpoints(url) values ('/api/logout')");
    $sth = $dbh->do("INSERT INTO api_endpoints(url) values ('/api/change_pw')");

    print "Created table: api_endpoints\n";
}

sub load_api_form_pages {
    my $body;
    {
        local $/ = undef;
        open( FILE, '<', 'api-add-page.txt' ) or die $!;
        $body = <FILE>;
        close FILE;
    }

    $sth = $dbh->do(
"INSERT INTO pages (body,url,domain_id,creation_time,userid,remote_addr,active,version_num) values ('$body','/api/add_page',$ALL_domain_id,$t,$userid,'72.201.204.99',true,1)"
    );
    print "Created page /api/add_page owned by $user \n";

    {
        local $/ = undef;
        open( FILE, '<', 'api-login.txt' ) or die $!;
        $body = <FILE>;
        close FILE;
    }

    $sth = $dbh->do(
"INSERT INTO pages (body,url,domain_id,creation_time,userid,remote_addr,active,version_num) values ('$body','/api/login',$ALL_domain_id,$t,$userid,'72.201.204.99',true,1)"
    );
    print "Created page /api/login owned by $user\n";

    {
        local $/ = undef;
        open( FILE, '<', 'index-page.html' ) or die $!;
        $body = <FILE>;
        close FILE;
    }
    $sth = $dbh->do( "INSERT INTO pages (body,url,domain_id,creation_time,userid,remote_addr,active,version_num) values ('$body','/',$OTHER_domain_id,$t,$userid,'72.201.204.99',true,1)");
    $sth = $dbh->do( "INSERT INTO pages (body,url,domain_id,creation_time,userid,remote_addr,active,version_num) values ('$body','/welcome',$OTHER_domain_id,$t,$userid,'72.201.204.99',true,1)");
    print "Created page http://$domain/ owned by $user\n";
    print "Created a duplicate at http://$domain/welcome too \n";



#   {
#       local $/ = undef;
#        open( FILE, '<', 'api-register.txt' ) or die $!;
#        $body = <FILE>;
#        close FILE;
#    }
#    $sth = $dbh->do( "INSERT INTO pages (body,url,domain_id,creation_time,userid,remote_addr, active,version_num) values ('$body','/api/register',$ALL_domain_id,'$t','admin','$uuid','72.201.204.99',true,1)");
#    print "Created page /api/register with useruuid = $uuid\n";

}

sub create_table_sessions {
    $sth = $dbh->do(
"CREATE TABLE sessions (id SERIAL PRIMARY KEY,sessionuuid uuid,remote_addr text,last_access integer,last_login integer,domain_id integer,userid integer)"
    ) or die $!;
    print "Created table sessions\n";
}

sub create_table_valid_domains {
    $sth = $dbh->do( 'CREATE TABLE valid_domains( id SERIAL PRIMARY KEY, domain text, owner_id integer, creation integer )') or die $!;
    $sth=$dbh->do("insert into valid_domains(domain,owner_id,creation) values('ALL',$userid,$t) ");
    $sth=$dbh->do("insert into valid_domains(domain,owner_id,creation) values('$domain',$userid,$t) ");
    $sth=$dbh->prepare("select id from valid_domains where domain='ALL' ");
    $sth->execute;
    @row=$sth->fetchrow_array;
    $ALL_domain_id=$row[0];

    $sth=$dbh->prepare("select id from valid_domains where domain=? ");
    $sth->execute($domain);
    @row=$sth->fetchrow_array;
    $OTHER_domain_id=$row[0];

    print "Created table valid_domains including \n\tdomain:ALL with domain_id=$ALL_domain_id\n\tdomain:$domain with domain_id=$OTHER_domain_id\n";
}

sub encrypt_password {
    my $password = shift;
    my $salt     = shift || salt();
    my $hash     = Crypt::Eksblowfish::Bcrypt::bcrypt_hash(
        { key_nul => 1, cost => 8, salt => $salt, }, $password );
    return join( '-', $salt, Crypt::Eksblowfish::Bcrypt::en_base64($hash) );
}

sub salt {
    print "making random numbers here...\n";
    return Crypt::Eksblowfish::Bcrypt::en_base64(
        Crypt::Random::Source::get_strong(12) );
}

sub check_password {
    my ( $password, $hash ) = @_;
    my ($salt) = split( '-', $hash, 2 );
    return length $salt == 16 && encrypt_password( $password, $salt ) eq $hash;
}
