#!/usr/bin/perl

use strict;
use warnings;
use DBD::Pg;
use APR::UUID;
use Crypt::Eksblowfish::Bcrypt qw(bcrypt);
use Crypt::Random::Source;
our $VERSION = 0.1;

my $dbh=DBI->connect('dbi:Pg:dbname=cms3','cms3','',{AutoCommit=>1,RaiseError=>1,PrintError=>1} ) or die $!;
print "Connected to database.\n";
my ( $sth );

##################
my $password;
if (! $ARGV[0])
  {
  print "using hard coded value for admin password\n";
  $password = 'admin';
  }
elsif( $ARGV[0] !~ /^[a-zA-Z0-9]+$/ )
  { print "Please use alphanumberic password only\n";exit}
else
  { $password = $ARGV[0];}

my $encrypted  = encrypt_password($password);

change_pw();

print "Admin password changed.\n";
exit;

sub change_pw {
    $sth = $dbh->prepare('update user_data set password=?');
    $sth->execute($encrypted);
}

sub encrypt_password {
    my $password = shift;
    my $salt     = shift || salt();
    my $hash     = Crypt::Eksblowfish::Bcrypt::bcrypt_hash(
        { key_nul => 1, cost => 8, salt => $salt, }, $password );
    return join( '-', $salt, Crypt::Eksblowfish::Bcrypt::en_base64($hash) );
}

sub salt {
    return Crypt::Eksblowfish::Bcrypt::en_base64(
        Crypt::Random::Source::get_strong(12) );
}
