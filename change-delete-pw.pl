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
my $password   = 'admin';
my $del_passwd;
if (! $ARGV[0])
  {
  print "using hard coded value for delete password\n";
  $del_passwd = '123';
  }
elsif( $ARGV[0] !~ /^[a-zA-Z0-9]+$/ )
  { print "Please use alphanumberic password only\n";exit}
else
  { $del_passwd = $ARGV[0];}

my $encrypted  = encrypt_password($password);
my $encrypt_delpw = encrypt_password($del_passwd);

change_del_pw();

print "Delete password changed.\n";
exit;

sub change_del_pw {
    $sth = $dbh->prepare('update user_data set delete_password=?');
    $sth->execute($encrypt_delpw);
}

sub encrypt_password {
    my $password = shift;
    my $salt     = shift || salt();
    my $hash     = Crypt::Eksblowfish::Bcrypt::bcrypt_hash(
        { key_nul => 1, cost => 8, salt => $salt, }, $password );
    return join( '-', $salt, Crypt::Eksblowfish::Bcrypt::en_base64($hash) );
}

sub salt {
	# print "making random numbers here...\n";
    return Crypt::Eksblowfish::Bcrypt::en_base64(
        Crypt::Random::Source::get_strong(12) );
}

sub check_password {
    my ( $password, $hash ) = @_;
    my ($salt) = split( '-', $hash, 2 );
    return length $salt == 16 && encrypt_password( $password, $salt ) eq $hash;
}
