#!/usr/bin/perl
use warnings;
use strict;
use DBI;
use FindBin qw($Bin);
use lib "$Bin/../source";
use Digest::MD5 qw(md5_base64);
use Digest::Bcrypt;
use Sierra::Constants;


## This script does a conversion on all of the passwords currently in your sierra
## database to convert them from md5 to bcrypt (actually to md5+bcrypt).
##
## ONLY EVER RUN THIS SCRIPT ONCE!!!!
##
## If you run this script on a database which is alredy using bcrypt passwords then
## you will double hash everything and ALL YOUR PASSWORDS WILL BREAK.  Running this 
## is a one-time operation.


warn "This script will update all of the passwords in your sierra database from md5 to bcrypt.\n";
warn "It should *only* be run *once* during a sierra upgrade which requires a password has update.\n";
warn "Running it again will irrevocably BREAK ALL PASSWORDS in your database\n\n";

warn "Are you ABSOLUTELY SURE you want to do this? (yes/no)\n";
my $answer = <STDIN>;

chomp $answer;

if ($answer ne "yes") {
    die "phew - that was close\n";
}

warn "OK - you asked for it\n";

foreach (reverse(1..10)) {
    warn "$_\n";
#    sleep(1);
}

my $dbh = DBI->connect("DBI:mysql:database=$Sierra::Constants::DB_NAME;host=$Sierra::Constants::DB_SERVER",$Sierra::Constants::DB_USERNAME,$Sierra::Constants::DB_PASSWORD,{RaiseError=>0,AutoCommit=>1});

my $get_md5_sth = $dbh -> prepare("SELECT id,password,email from person");
my $update_password_sth = $dbh -> prepare("UPDATE person set password=? where id=?");


$get_md5_sth -> execute();

while (my ($id,$md5,$email) = $get_md5_sth -> fetchrow_array()) {

    unless ($md5) {
	warn "Skipping $email since password is empty\n";
	next;
    }
    unless (length($md5) > 32) {
	warn "Skipping $email as '$md5' was too short (".length($md5).")\n";
	next;
    }

    my $bcrypt = convert_md5_to_bcrypt($md5);

    warn "Bcrypt for $id is $bcrypt\n";

    $update_password_sth -> execute($bcrypt,$id) or die "Can't update password for $id";

}



sub convert_md5_to_bcrypt {
    my ($md5) = @_;

    
    my $salt = substr($md5,0,32);
    my $hash = substr($md5,32);

    # This does the bcrypt hashing on the result
    my $bcrypt = Digest::Bcrypt -> new();
    $bcrypt->add($hash);
    $bcrypt->cost(12);
    # Our salt has already been incorporated in the generation
    # of the md5 hash so we're not going to set anything here.
    $bcrypt->salt("0000000000000000");

    my $bhash = $bcrypt->b64digest();

    return ($salt.$bhash);
}
