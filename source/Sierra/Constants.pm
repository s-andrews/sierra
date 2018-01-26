#!/usr/bin/perl
use warnings;
use strict;
use FindBin;

package Sierra::Constants;

# This is the global version for Sierra it is updated
# manually in new releases.  You don't need to (and
# shouldn't) edit this yourself

our $SIERRA_VERSION = "0.4 devel";

# The constants below are populated from a file called
# sierra.conf in the conf directory of your sierra
# installation.  You should not edit any of the values in
# this file, but should use the conf file to alter the
# values stored in this package.

our $BASE_URL;
our $TEMP_DIR;
our $DB_SERVER;
our $DB_NAME;
our $DB_USERNAME;
our $DB_PASSWORD;
our $ADMIN_NAME;
our $ADMIN_EMAIL;
our @NOTIFY_ABOUT_RUNS;
our $SMTP_SERVER;
our $SMTP_USERNAME;
our $SMTP_PASSWORD;
our $MAILS_FROM_ADDRESS;
our $SAMTOOLS_PATH;
our $PUBLIC_QUEUE;
our @DATA_FOLDERS;

our $BUDGET_DB_SERVER;
our $BUDGET_DB_NAME;
our $BUDGET_DB_USERNAME;
our $BUDGET_DB_PASSWORD;
our $BUDGET_DB_TABLE;

parse_conf_file ();

sub parse_conf_file {

  unless (-e "$FindBin::RealBin/../conf/sierra.conf") {
    die "No sierra.conf file found in $FindBin::RealBin/../conf/ - copy the example conf file and set the values up for your installation";
  }

  open (CONF,"$FindBin::RealBin/../conf/sierra.conf") or die "Can't open sierra.conf file: $!";

  while (<CONF>) {
    chomp;
    next unless ($_);

    next if (/^\s*\#/); # Ignore comments

    my ($name,$value) = split(/\s+/,$_,2);

    if ($name eq 'BASE_URL') {
      $BASE_URL = $value;
    }

    elsif ($name eq 'TEMP_DIR') {
      unless (-e $value and -d $value) {
	die "Temp folder '$value' doesn't exist";
      }
      $TEMP_DIR = $value;
    }
    elsif ($name eq 'DB_SERVER') {
      $DB_SERVER = $value;
    }
    elsif ($name eq 'DB_NAME') {
      $DB_NAME = $value;
    }
    elsif ($name eq 'DB_USERNAME') {
      $DB_USERNAME = $value;
    }
    elsif ($name eq 'DB_PASSWORD') {
      $DB_PASSWORD = $value;
    }
    elsif ($name eq 'ADMIN_NAME') {
      $ADMIN_NAME = $value;
    }
    elsif ($name eq 'ADMIN_EMAIL') {
      $ADMIN_EMAIL = $value;
    }
    elsif ($name eq 'SMTP_SERVER') {
      $SMTP_SERVER = $value;
    }
    elsif ($name eq 'SMTP_USERNAME') {
      $SMTP_USERNAME = $value;
    }
    elsif ($name eq 'SMTP_PASSWORD') {
      $SMTP_PASSWORD = $value;
    }
    elsif ($name eq 'MAILS_FROM_ADDRESS') {
      $MAILS_FROM_ADDRESS = $value;
    }
    elsif ($name eq 'PUBLIC_QUEUE') {
      $PUBLIC_QUEUE = $value;
    }
    elsif ($name eq 'SAMTOOLS_PATH') {
      $SAMTOOLS_PATH = $value;
    }
    elsif ($name eq 'BUDGET_DB_SERVER') {
      $BUDGET_DB_SERVER = $value;
    }
    elsif ($name eq 'BUDGET_DB_NAME') {
      $BUDGET_DB_NAME = $value;
    }
    elsif ($name eq 'BUDGET_DB_USERNAME') {
      $BUDGET_DB_USERNAME = $value;
    }
    elsif ($name eq 'BUDGET_DB_PASSWORD') {
      $BUDGET_DB_PASSWORD = $value;
    }
    elsif ($name eq 'NOTIFY_ABOUT_RUNS') {
      push @NOTIFY_ABOUT_RUNS, $value;
    }
    elsif ($name eq 'DATA_FOLDER') {
      unless (-e $value and -d $value) {
	die "Data folder '$value' doesn't exist";
      }
      push @DATA_FOLDERS, $value;
    }
    else {
      close CONF;
      die "Unknown configuration otion '$name'";
    }
  }

  close CONF;

}


1;

