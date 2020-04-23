#!/usr/bin/perl

##########################################################################
#                                                                        #
# Copyright 2011-20, Simon Andrews (simon.andrews@babraham.ac.uk)        #
#                                                                        #
# This file is part of Sierra.                                           #
#                                                                        #
# Sierra is free software: you can redistribute it and/or modify         #
# it under the terms of the GNU General Public License as published by   #
# the Free Software Foundation, either version 3 of the License, or      #
# (at your option) any later version.                                    #
#                                                                        #
# Sierra is distributed in the hope that it will be useful,              #
# but WITHOUT ANY WARRANTY; without even the implied warranty of         #
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the          #
# GNU General Public License for more details.                           #
#                                                                        #
# You should have received a copy of the GNU General Public License      #
# along with Sierra.  If not, see <http://www.gnu.org/licenses/>.        #
##########################################################################

use warnings;
use strict;
use HTML::Template;
use CGI;
use CGI::Session qw/-ip-match/;
use DBI;
use FindBin qw($Bin);
use CGI::Carp qw(fatalsToBrowser);
use lib "$Bin/../source";
use Sierra::Constants;
use Digest::MD5 qw(md5_base64);
use Digest::Bcrypt;
use Net::SMTP;
use List::Util qw(shuffle);
use Date::Calc qw(Delta_Days Today check_date);
use Sierra::IlluminaRun;
use Data::Dumper;

# This is the script which controls the normal user interface
# of the sierra system for managing next genreation sequencing
# data.


# Make the templates directory our working directory
chdir ("$Bin/../templates") or die "Can't move to templates directory: $!";


# Before we do anything else we need to check if this person
# is logged in.  If not then we send them to the login screen

my $q = CGI->new();

CGI::Session -> name("SIERRASESSID");

my $session = CGI::Session->new(undef,$q,{Directory=>$Sierra::Constants::TEMP_DIR});

unless ($session) {
  print_bug("Couldn't create new session");
  exit;
}

# Include some constants in the session so they pass on
# to the templates easily.  We put these in each time so
# that we don't need to expire sessions to change any of them.

$session -> param(BASE_URL => $Sierra::Constants::BASE_URL);
$session -> param(ADMIN_NAME => $Sierra::Constants::ADMIN_NAME);
$session -> param(ADMIN_EMAIL => $Sierra::Constants::ADMIN_EMAIL);
$session -> param(SIERRA_VERSION => $Sierra::Constants::SIERRA_VERSION);


# We can now try to connect to the database
my $dbh = DBI->connect("DBI:mysql:database=$Sierra::Constants::DB_NAME;host=$Sierra::Constants::DB_SERVER",$Sierra::Constants::DB_USERNAME,$Sierra::Constants::DB_PASSWORD,{RaiseError=>0,AutoCommit=>1});

unless ($dbh) {
  print_bug("Couldn't connect to main database: ".$DBI::errstr);
  exit;
}

# We now need to find out what they want to do by looking at
# the action parameter and dispatching them appropriately.

my $action = $q->param('action');


if ($session->param("person_id")) {

  # They've logged in already
  unless ($action) {
    show_home_page();
  }

  else {
    if ($action eq 'logout') {
      logout();
    }
    elsif ($action eq 'show_queue') {
      show_queue();
    }
    elsif ($action eq 'email_users') {
      email_users();
    }
    elsif ($action eq 'view_sample') {
      view_sample();
    }
    elsif ($action eq 'edit_sample') {
      edit_sample();
    }
    elsif ($action eq 'finish_edit_sample') {
      finish_edit_sample();
    }
    elsif ($action eq 'add_barcode') {
      add_barcode();
    }
    elsif ($action eq 'remove_barcode') {
      remove_barcode();
    }
    elsif ($action eq 'add_authkey') {
      add_authkey();
    }
    elsif ($action eq 'remove_authkey') {
      remove_authkey();
    }
    elsif ($action eq 'view_lane') {
      view_lane();
    }
    elsif ($action eq 'send_file') {
      send_file();
    }
    elsif ($action eq 'add_note') {
      add_note();
    }
    elsif ($action eq 'show_note_file') {
      show_note_file();
    }
    elsif ($action eq 'change_details') {
      start_change_details();
    }
    elsif ($action eq 'finish_change_details') {
      finish_change_details();
    }
    elsif ($action eq 'add_permission') {
      add_permission();
    }
    elsif ($action eq 'remove_permission') {
      remove_permission();
    }
    elsif ($action eq 'configuration') {
      configuration();
    }
    elsif ($action eq 'reports') {
      reports();
    }
    elsif ($action eq 'edit_instrument') {
      edit_instrument();
    }
    elsif ($action eq 'finish_edit_instrument') {
      finish_edit_instrument();
    }
    elsif ($action eq 'edit_run_type') {
      edit_run_type();
    }
    elsif ($action eq 'finish_edit_run_type') {
      finish_edit_run_type();
    }
    elsif ($action eq 'edit_adapter_type') {
      edit_adapter_type();
    }
    elsif ($action eq 'finish_edit_adapter_type') {
      finish_edit_adapter_type();
    }
    elsif ($action eq 'edit_sample_type') {
      edit_sample_type();
    }
    elsif ($action eq 'finish_edit_sample_type') {
      finish_edit_sample_type();
    }
    elsif ($action eq 'edit_database') {
      edit_database();
    }
    elsif ($action eq 'finish_edit_database') {
      finish_edit_database();
    }
    elsif ($action eq 'new_flowcell' or $action eq 'view_flowcell') {
      new_flowcell();
    }
    elsif ($action eq 'edit_flowcell') {
      edit_flowcell();
    }
    elsif ($action eq 'finish_edit_flowcell') {
      finish_edit_flowcell();
    }
    elsif ($action eq 'delete_flowcell') {
      delete_flowcell();
    }
    elsif ($action eq 'remove_sample') {
      remove_sample();
    }
    elsif ($action eq 'add_lane') {
      add_lane();
    }
    elsif ($action eq 'receive_sample') {
      receive_sample();
    }
    elsif ($action eq 'pass_qc_sample') {
      pass_qc_sample();
    }
    elsif ($action eq 'create_run') {
      create_run();
    }
    elsif ($action eq 'finish_new_run') {
      finish_new_run();
    }
    elsif ($action eq 'search') {
      start_search();
    }
    elsif ($action eq 'run_sample_search') {
      run_sample_search();
    }
    elsif ($action eq 'run_run_search') {
      run_run_search();
    }
    elsif ($action eq 'run_people_search') {
      run_people_search();
    }
    elsif ($action eq 'new_account') {
      start_new_account();
    }
    elsif ($action eq 'finish_new_account') {
      finish_new_account();
    }


    else {
      print_bug("Unknown action '$action'");
      exit;
    }
  }
}

else {

  # There are a couple of things they can legitimately do
  # without being logged in
  if ($action) {
    if ($action eq 'process_login') {
      process_login();
    }
    elsif ($action eq 'new_account') {
      start_new_account();
    }
    elsif ($action eq 'finish_new_account') {
      finish_new_account();
    }
    elsif ($action eq 'password_reset') {
      send_password_reset();
    }
    elsif ($action eq 'reset_password') {
      reset_password();
    }

    # If they have an authorisation key then they can also
    # potentially view individual samples, lanes, or files
    elsif ($q->param("authkey")) {

      if ($action eq 'view_sample') {
	view_sample();
      }
      elsif ($action eq 'view_lane') {
	view_lane();
      }
      elsif ($action eq 'send_file') {
	send_file();
      }
      else {
	# They're not logged in so redirect them
	# to the login screen (the front page will do)
	print $q->redirect("sierra.pl");
      }

    }




    else {
      # They're not logged in so redirect them
      # to the login screen (the front page will do)
      print $q->redirect("sierra.pl");
    }
  }
  else {
    show_login_page();
    exit();
  }

}


#########################################

sub show_login_page {
  my $template = HTML::Template -> new (filename => 'login.html', associate=>$session);
  print $session->header();
  print $template -> output();
}


sub check_password {
    my ($password, $hashsalt) = @_;

    # Our hashing is a little complex as it's the result of upgrading from
    # md5 to bcrypt, so bear with us on this.

    # The structure of the data stored in the database is that the first 32
    # chars are the salt, and the last 32 chars are the base64 encoded hash

    # The hash itself is generated by making the md5 of the password+salt
    # and then generating the bcrypt has of the md5 hash.

    my $salt = substr($hashsalt,0,32);
    my $hash = substr($hashsalt,32);

    my $check_hash = generate_hash($password,$salt);

    if ($check_hash eq $hashsalt) {
	return(1);
    }
    else {
	return(0);
    }
}

sub generate_hash {

    my ($password, $salt) = @_;

    # Our hashing is a little complex as it's the result of upgrading from
    # md5 to bcrypt, so bear with us on this.

    # The structure of the data stored in the database is that the first 32
    # chars are the salt, and the last 32 chars are the base64 encoded hash

    # The hash itself is generated by making the md5 of the password+salt
    # and then generating the bcrypt hash of the md5 hash.

    # This makes the MD5 hash
    my $calculated_hash = md5_base64($salt.$password);

    # This does the bcrypt hashing on the result
    my $bcrypt = Digest::Bcrypt -> new();
    $bcrypt->add($calculated_hash);
    $bcrypt->cost(12);
    # Our salt has already been incorporated in the generation
    # of the md5 hash so we're not going to set anything here.
    $bcrypt->salt("0000000000000000");

    my $hash = $bcrypt->b64digest();

    return ($salt.$hash);

}


sub process_login {

  my $email = $q->param('email');
  my $password = $q->param('password');

  my ($id,$first_name,$last_name,$hash,$is_admin) = $dbh->selectrow_array("SELECT id,first_name,last_name,password,is_admin FROM person where email=?",undef,($email));

  unless ($id) {
    print_error("Couldn't find an account using email '$email'.  Maybe you need to create a new account?");
    return;
  }


  # When the account is first created there may be no password entry
  # if they've not confirmed the account, so don't let them try to
  # log in.
  if (! defined $hash or length $hash < 32) {
    print_error("Invalid password for email '$email'.  Use the 'forgotten password' link if you can't remember your password");
    return;
  }

  unless (check_password($password,$hash)) {
    print_error("Incorrect password for email '$email'.  Use the 'forgotten password' link if you can't remember your password");
    return;
  }

  # We can now add to the current session

  $session -> param(first_name => $first_name);
  $session -> param(last_name => $last_name);
  $session -> param(email => $email);
  $session -> param(person_id => $id);
  $session -> param(is_admin => $is_admin);
  $session -> param(public_queue => $Sierra::Constants::PUBLIC_QUEUE);

  # We can now redirect them to the same page, but this
  # time it should work
  print $q->redirect("sierra.pl");

}

sub start_new_account {
  my $template = HTML::Template -> new (filename => 'new_account.html', associate=>$session);
  print $session->header();
  print $template -> output();
}


sub finish_new_account {

  my $email = $q->param('email');

  unless ($email) {
    print_error("No email address was entered");
    return;
  }

  my $first = $q -> param("first_name");
  unless ($first) {
    print_error("No first name was supplied");
    return;
  }

  my $last = $q -> param("last_name");
  unless ($last) {
    print_error("No last name was supplied");
    return;
  }

  my $phone = $q->param("phone");
  $phone = "[No phone number]" unless ($phone);

  my $password;
  my $make_admin = 0;

  if ($session->param("is_admin")) {
    # Admins can make other admin accounts
    $make_admin = $q->param("make_admin");
    $make_admin = 1 if ($make_admin); # Make sure that 1 == true
  }
  else {

    # This account will still be made an admin if no
    # other accounts exist on the system yet (ie this
    # is the first ever account)

    my ($account_count) = $dbh->selectrow_array("SELECT count(*) FROM person");

    unless (defined $account_count) {
      print_bug("Couldn't count the current number of accounts: ".$dbh->errstr());
      return;
    }

    if ($account_count == 0) {
      $make_admin = 1;
    }

    $password = $q->param("password");
    unless ($password) {
      print_error("No password was entered");
      return;
    }

    if (length $password < 8) {
      print_error("Your password must be at least 8 characters in length");
      return;
    }

    my $password2 = $q->param("password2");
    unless ($password2) {
      print_error("You didn't retype your password");
      return;
    }

    unless ($password eq $password2) {
      print_error("The passwords you supplied were not the same");
      return;
    }
  }

  # Check that there isn't a user with this email in the database already
  my ($id) = $dbh->selectrow_array("SELECT id FROM person WHERE email=?",undef,($email));

  if ($id) {
    print_error("There already appears to be an account on this system for $email.  Use the password reminder option if you have forgotten your password");
    return;
  }

  # We can now try to make the new entry
  # We'll leave the password blank, and create a change password
  # entry so they need to click on a link in their
  $dbh->do("INSERT INTO person (first_name,last_name,email,phone,is_admin) values (?,?,?,?,?)",undef,($first,$last,$email,$phone,$make_admin)) or do {
    print_bug("Failed to create new user: ".$dbh->errstr());
    return;
  };

  # We can now collect the id we just generated and log them in

  ($id) = $dbh->selectrow_array("SELECT LAST_INSERT_ID()");

  unless ($id) {
    print_bug("Couldn't fetch id for newly created user: ".$dbh->errstr());
    return;
  }

  # We need to put an entry in the permission table to enable them to
  # see their own samples
  $dbh->do("INSERT INTO person_permission (owner_person_id,permission_person_id) VALUES (?,?)",undef,($id,$id)) or do {
    print_bug("Couldn't create default permissions for new user:".$dbh->errstr());
    return;
  };

  if (! $session -> param("is_admin")) {

    # This really is a new user and we need to send them to the
    # password reset option to get them to confirm their
    # password

    # We need to check this worked so we don't redirect if it failed
    send_password_reset(1);
  }


  # We can send them to the home page
  print $q->redirect("sierra.pl");

}

sub create_run {

  if (!$session->param("is_admin")) {
    print_bug("Only admins can start runs, sorry");
    return;
  }

  my $template = HTML::Template -> new (filename => 'new_run.html', associate=>$session);

  # Add days months and years.

  my @days;
  for my $day (1..31) {
    if ($day == (localtime())[3]) {
      push @days, {NAME => $day,SELECTED => 1};
    }
    else {
      push @days, {NAME => $day};
    }
  }

  $template->param(DAYS => \@days);

  my @months = (
		[1,'Jan'],
		[2,'Feb'],
		[3,'Mar'],
		[4,'Apr'],
		[5,'May'],
		[6,'Jun'],
		[7,'Jul'],
		[8,'Aug'],
		[9,'Sep'],
		[10,'Oct'],
		[11,'Nov'],
		[12,'Dec'],
	       );

  my @template_months;
  foreach my $month (@months) {
    if ($month->[0] == (localtime())[4]+1) {
      push @template_months,{NUMBER=>$month->[0],NAME=>$month->[1],SELECTED=>1};
    }
    else {
      push @template_months,{NUMBER=>$month->[0],NAME=>$month->[1]};
    }

  }
  $template -> param(MONTHS => \@template_months);

  my @years;

  for my $year (2009..(localtime())[5]+1900) {

    if ($year == (localtime())[5]+1900) {
      push @years, {YEAR => $year,SELECTED => 1};
    }
    else {
      push @years, {YEAR => $year};
    }

  }

  $template->param(YEARS=>\@years);


  # We need to get details of the flowcell and the run
  my $flowcell_id = $q->param("flowcell_id");
  if (!$flowcell_id or $flowcell_id !~ /^\d+$/) {
    print_bug("Invalid flowcell id '$flowcell_id'");
    return;
  }

  my ($serial_number,$available_lanes,$run_type,$run_type_id,$run_id) = $dbh->selectrow_array("SELECT flowcell.serial_number,flowcell.available_lanes,run_type.name,run_type.id,flowcell.run_id FROM flowcell,run_type WHERE flowcell.id=? AND flowcell.run_type_id=run_type.id",undef,($flowcell_id));

  unless (defined $serial_number) {
    print_bug("Couldn't find a flowcell with id $flowcell_id:".$dbh->errstr());
    return;
  }
  if ($run_id) {
    print_bug("Flowcell $flowcell_id already appears to have a run associated with it ($run_id)");
    return;
  }

  $template->param(FLOWCELL_ID => $flowcell_id,
		   SERIAL_NUMBER => $serial_number,
		   LANES => $available_lanes,
		   RUN_TYPE => $run_type,
		  );

  # Find if there is a control lane on this flowcell
  my ($control_lane) = $dbh->selectrow_array("SELECT lane_number FROM lane WHERE flowcell_id=? AND use_as_control=1",undef,($flowcell_id));

#  unless (defined $control_lane) {
#    print_bug("Couldn't find a flowcell with id $flowcell_id:".$dbh->errstr());
#    return;
#  }

  $template->param(CONTROL_LANE => $control_lane);


  # No make up a list of machines
  my $machines_sth = $dbh->prepare("SELECT instrument.id,instrument.serial_number,instrument.description FROM run_type_instrument,instrument WHERE run_type_instrument.run_type_id=? AND run_type_instrument.instrument_id=instrument.id AND instrument.retired != 1 AND instrument.available=1");

  $machines_sth -> execute($run_type_id) or do {
    print_bug("Can't get list of instruments: ".$dbh->errstr());
    return;
  };

  my @machines;

  my $first_serial;
  while (my ($id,$serial,$description) = $machines_sth->fetchrow_array()) {

    $first_serial = $serial unless ($first_serial);

    my $name;
    if ($serial and $description) {
      $name = "$description ($serial)";
    }
    elsif ($serial) {
      $name = $serial;
    }
    else {
      $name = $description;
    }

    push @machines, {MACHINE_ID => $id,
		     MACHINE_NAME => $name};

  }

  $template->param(MACHINES => \@machines);

  # Let's guess a run folder name

  my $run_year = substr((localtime())[5]+1900,2);
  my $run_month = (localtime())[4]+1;
  if (length $run_month == 1) {
    $run_month = '0'.$run_month;
  }
  my $run_day = (localtime())[3];
  if (length ($run_day) == 1) {
    $run_day = '0'.$run_day;
  }

  my $run_folder_name = join("_",("$run_year$run_month$run_day",$first_serial,"0001",$serial_number));

  $template->param(RUN_FOLDER => $run_folder_name);

  print $session->header();
  print $template->output();

}

sub finish_new_run {

  if (!$session->param("is_admin")) {
    print_bug("Only admins can start runs, sorry");
    return;
  }

  # We need to get details of the flowcell and the machine
  my $flowcell_id = $q->param("flowcell_id");
  if (!$flowcell_id or $flowcell_id !~ /^\d+$/) {
    print_bug("Invalid flowcell id '$flowcell_id'");
    return;
  }

  # Check this flowcell isn't already marked as being run

  my ($existing_run) = $dbh->selectrow_array("SELECT id FROM run WHERE flowcell_id=?",undef,($flowcell_id));

  if ($existing_run) {
    print_bug("This flowcell already has a run associated with it ($existing_run)");
    return;
  }

  # Get the machine to use
  my $machine_id = $q->param("machine_id");
  if (!$machine_id or $machine_id !~ /^\d+$/) {
    print_bug("Invalid machine id '$machine_id'");
    return;
  }

  # Check that this machine is able to run this flowcell
  my ($run_mapping_id) = $dbh->selectrow_array("SELECT run_type_instrument.id FROM flowcell,run_type_instrument WHERE flowcell.id=? AND flowcell.run_type_id=run_type_instrument.run_type_id AND run_type_instrument.instrument_id=?",undef,($flowcell_id,$machine_id));

  unless ($run_mapping_id) {
    print_bug("Couldn't confirm mapping between flowcell $flowcell_id and machine $machine_id:".$dbh->errstr());
    return;
  }

  # Get the name of this run type
  my ($run_type_name) = $dbh->selectrow_array("SELECT run_type.name FROM flowcell,run_type WHERE flowcell.id=? AND flowcell.run_type_id=run_type.id",undef,($flowcell_id));

  unless ($run_type_name) {
    print_bug("Couldn't get the run type name for flowcell $flowcell_id:".$dbh->errstr());
    return;
  }


  # Get the date
  my $day = $q -> param("day");
  my $month = $q -> param("month");
  my $year = $q -> param("year");

  # Check if this is valid
  if (!check_date($year,$month,$day)) {
    print_error("Date $year-$month-$day doesn't appear to be a valid date");
    return;
  }

  if (Delta_Days(Today(),$year,$month,$day) > 1) {
    print_error("Your run date appears to be more than one day in the future");
    return;
  }

  my $date = sprintf("%d-%02d-%02d",$year,$month,$day);

  my $run_folder = $q->param("run_folder");

  unless ($run_folder) {
    print_error("No run folder name was provided");
    return;
  }

  # We can now make the new run entry

  $dbh->do("INSERT INTO run (flowcell_id,instrument_id,date,run_folder_name) VALUES (?,?,?,?)",undef,($flowcell_id,$machine_id,$date,$run_folder)) or do {
    print_bug("Unable to create new run: ".$dbh->errstr());
    return;
  };

  # Now get the new run id
  my ($run_id) = $dbh->selectrow_array("SELECT LAST_INSERT_ID()");

  unless ($run_id) {
    print_bug ("Couldn't get the ID for the newly created run:".$dbh->errstr());
    return;
  }

  # Update the flowcell with the run id (we shouldn't really be storing this here...)
  $dbh->do("UPDATE flowcell SET run_id=? where id=?",undef,($run_id,$flowcell_id)) or do {
    print_bug("Couldn't set the run id ($run_id) for flowcell $flowcell_id:".$dbh->errstr());
    return;
  };

  # Send emails out to the people on the run telling them that a run has
  # been started

  my $users_on_this_flowcell_sth = $dbh->prepare("select sample_id,sample.users_sample_name,person.email, person.first_name, person.last_name from lane,sample,person where lane.flowcell_id=? and lane.sample_id=sample.id and sample.person_id = person.id and sample.is_suitable_control != 1");

  $users_on_this_flowcell_sth -> execute($flowcell_id) or do {
    print_bug("Couldn't get sample list for flowcell $flowcell_id: ".$dbh->errstr());
    return;
  };

  # Group the samples by user
  my %grouped_samples;

  while (my ($sample_id,$sample_name,$email,$first_name, $last_name) = $users_on_this_flowcell_sth -> fetchrow_array()) {

    push @{$grouped_samples{$email}},{SAMPLE_NAME => $sample_name, SAMPLE_ID => $sample_id};

    # We also add all samples to the people who get
    # notified about all runs
    push @{$grouped_samples{$_}},{
				  SAMPLE_NAME => $sample_name, 
				  SAMPLE_ID => $sample_id,
				  USER_NAME => "$first_name $last_name",
				 } foreach (@Sierra::Constants::NOTIFY_ABOUT_RUNS);
  }

  my $email_template = HTML::Template -> new (filename => 'new_run_email.txt');

  foreach my $email (keys %grouped_samples) {

    $email_template ->param(FLOWCELL_ID => $flowcell_id,
			    RUN_TYPE => $run_type_name,
			    SAMPLES => $grouped_samples{$email});

    # Send email returns false upon failure so we don't
    # want to go on if it's failed.
    return unless (send_email("New Sequencing Run Started",$email_template->output(),($email)));

  }



  # Finally send them back to the start
  print $q->redirect("sierra.pl");

}


sub start_search {
  my $template = HTML::Template -> new (filename => 'search.html', associate=>$session);

  my @users;

  if ($session->param("is_admin")) {
    push @users, {ID => 0,USERNAME=> "[Anyone]"};
  }

  # If we're an admin we get the full list of users.  Everyone else
  # simply gets the users they have persmission to view

  my $db_sth;

  if ($session->param("is_admin")) {
    $db_sth = $dbh->prepare("SELECT id,first_name,last_name FROM person ORDER BY last_name,first_name DESC");

    $db_sth->execute() or do {
      print_bug("Couldn't get list of people: ".$dbh->errstr());
      return;
    };
  }
  else {
    $db_sth = $dbh->prepare("SELECT person.id,person.first_name,person.last_name FROM person,person_permission WHERE person_permission.permission_person_id=? AND person_permission.owner_person_id=person.id ORDER BY person.last_name,person.first_name DESC");

    $db_sth->execute($session->param("person_id")) or do {
      print_bug("Couldn't get list of people: ".$dbh->errstr());
      return;
    };
  }


  while (my ($id,$first,$last) = $db_sth->fetchrow_array()) {
    if (!$session->param("is_admin") and $id == $session->param("person_id")) {
      push @users, {ID=>$id,SELF => 1,USERNAME=>"$last, $first"};
    }
    else {
      push @users, {ID=>$id,USERNAME=>"$last, $first"};	
    }
  }

  $template->param(USERS => \@users);
  

  # Add months and years.
  my @months = (
		[1,'Jan'],
		[2,'Feb'],
		[3,'Mar'],
		[4,'Apr'],
		[5,'May'],
		[6,'Jun'],
		[7,'Jul'],
		[8,'Aug'],
		[9,'Sep'],
		[10,'Oct'],
		[11,'Nov'],
		[12,'Dec'],
	       );

  my @template_months;
  foreach my $month (@months) {
    if ($month->[0] == (localtime())[4]+1) {
      push @template_months,{NUMBER=>$month->[0],NAME=>$month->[1],SELECTED=>1};
    }
    else {
      push @template_months,{NUMBER=>$month->[0],NAME=>$month->[1]};
    }

  }
  $template -> param(MONTHS => \@template_months);

  my @years;

  for my $year (2009..(localtime())[5]+1900) {

    if ($year == (localtime())[5]+1900) {
      push @years, {YEAR => $year,SELECTED => 1};
    }
    else {
      push @years, {YEAR => $year};
    }

  }

  # Add a list of sample types
  my @sample_types;
  my $sample_type_sth = $dbh->prepare("SELECT id,name FROM sample_type ORDER BY name");
  $sample_type_sth -> execute() or do {
    print_bug("Couldn't get list of sample types: ".$dbh->errstr());
    return;
  };
  while (my ($id,$name) = $sample_type_sth->fetchrow_array()) {
    push @sample_types ,{
			 ID => $id,
			 NAME => $name,
			};
  }
  $template -> param(SAMPLE_TYPES => \@sample_types);

  # For Admins we can attach a list of run types
  if ($session->param("is_admin")) {

    my $runtypes_sth = $dbh->prepare("SELECT id,name FROM run_type");

    $runtypes_sth -> execute() or do {
      print_bug("Couldn't get list of run types: ".$dbh->errstr());
      return;
    };

    my @runtypes;
    while (my ($id,$name) = $runtypes_sth->fetchrow_array()) {
      push @runtypes, {
		       RUN_TYPE_ID => $id,
		       RUN_TYPE_NAME => $name,
		      };
    }

    $template->param(RUN_TYPES => \@runtypes);
  }


  $template->param(YEARS=>\@years);


  print $session->header();
  print $template -> output();
}

sub run_sample_search {

  my $template = HTML::Template -> new (filename => 'search_results.html', associate=>$session);


  my $sql_query = "SELECT sample.id,sample.users_sample_name,sample.sample_type_id,sample.lanes_required,DATE_FORMAT(sample.received_date,'%e %b %Y'),person.first_name,person.last_name FROM sample,person WHERE sample.person_id=person.id";

  my @parameters;

  # Sort out the person id first
  my $person_id = $q -> param("user");

  if ($person_id) {

    if ($person_id !~ /^\d+$/) {
      print_bug("Person id should be a number and not $person_id");
      return;
    }

    # Check that this person can use this person id
    unless ($session -> param("is_admin")) {
      my ($permission_id) = $dbh->selectrow_array("SELECT id FROM person_permission WHERE permission_person_id=? AND owner_person_id=?",undef,($session->param("person_id"),$person_id));

      unless ($permission_id) {
	print_bug("You do not have permission to look at samples for user $person_id");
	return;
      }
    }

    $sql_query .= " AND person.id=?";
    push @parameters,$person_id;
  }
  else {
    # Non admins must provide a person id

    unless ($session->param("is_admin")) {
      print_bug("No person id was selected");
      return;
    }
  }
  

  # Filter by type
  my $sample_type = $q->param("sample_type");
  if ($sample_type) {
    $sql_query .= " AND sample.sample_type_id=?";
    push @parameters,$sample_type;
  }

  # Filter by status
  my $status = $q -> param("status");

  if ($status ne '[Any]') {
    $sql_query .= " AND sample.is_complete=?";

    if ($status eq 'Active') {
      push @parameters,0;
    }
    elsif ($status eq 'Complete') {
      push @parameters,1;
    }
    else {
      print_bug("Unknown status '$status'");
      return;
    }
  }

  # Filter by date
  my $date_type = $q->param("date_type");
  if ($date_type) {

    if ($date_type eq 'submitted') {
      $sql_query .= " AND sample.submitted_date>=? AND sample.submitted_date<?";
    }
    elsif ($date_type eq 'accepted') {
      $sql_query .= " AND sample.received_date>=? AND sample.received_date<?";
    }
    else {
      print_bug("Unknown date file type $date_type");
      return;
    }

    my $from_month = $q->param('from_month');
    my $from_year = $q->param('from_year');
    my $to_month = $q->param('to_month');
    my $to_year = $q->param('to_year');

    unless ($from_month =~ /^\d+$/) {print_bug("From month $from_month was not a number");return;}
    unless ($to_month =~ /^\d+$/) {print_bug("To month $to_month was not a number");return;}
    unless ($from_year =~ /^\d+$/) {print_bug("From year $from_year was not a number");return;}
    unless ($to_year =~ /^\d+$/) {print_bug("To year $to_year was not a number");return;}

    if (length $from_month == 1) {
      $from_month = '0'.$from_month;
    }
    my $from_date="${from_year}-${from_month}-01";
    $to_month++;
    if ($to_month == 13) {
      $to_month = 1;
      $to_year++;
    }

    my $to_date = "${to_year}-${to_month}-01";

    push @parameters,$from_date,$to_date;

  }

  # Sample ID / Lane ID

  # Since we can't search for a lane ID explicitly we need to turn a lane
  # ID into a sample ID if we want to use this as a parameter to the 
  # search.

  my $lane_id_filter = $q->param("lane_id");
  my $sample_from_lane;
  if ($lane_id_filter) {

    unless ($lane_id_filter =~ /^\d+$/) {
      print_error("Lane IDs must be numbers ($lane_id_filter wasn't)");
      return;
    }

    ($sample_from_lane) = $dbh->selectrow_array("SELECT sample_id FROM lane WHERE id=?",undef,($lane_id_filter));
    $sample_from_lane = -1 unless ($sample_from_lane); # We might not have found a hit.
  }

  my $sample_id_filter = $q->param("sample_id");

  if ($sample_id_filter and $sample_from_lane and $sample_from_lane ne $sample_id_filter) {
    print_error("Incompatible sample and lane ids supplied as search terms");
    return;
  }

  if ($sample_from_lane) {
    $sample_id_filter = $sample_from_lane;
  }


  if ($sample_id_filter) {
    unless ($sample_id_filter =~ /^\d+$/ || $sample_id_filter eq "-1") {
      print_error("Sample IDs must be numbers ($sample_id_filter wasn't)");
      return;
    }


    $sql_query .= " AND sample.id=?";
    push @parameters,$sample_id_filter;

  }

  # Sample Name
  my $sample_name_filter = $q->param("name");

  if ($sample_name_filter) {

    if ($sample_name_filter =~ /\*/) {
      # We're doing a wildcard search

      # Remove anything potentially nasty from the string
      $sample_name_filter =~ s/[\'\"\\;%]//g;

      # Replace stars with %
      $sample_name_filter =~ s/\*/%/g;

#      print_bug("Search string was '$sample_name_filter'");
#      return;

      # Add it to the search
      $sql_query .= " AND sample.users_sample_name LIKE \"$sample_name_filter\"";

    }
    else {
      # We're looking for an exact match
      $sql_query .= " AND sample.users_sample_name=?";
      push @parameters,$sample_name_filter;
    }

  }

  my $samples_sth = $dbh->prepare($sql_query);

  $samples_sth -> execute(@parameters) or do {
    print_bug("Couldn't run sample search: ".$dbh->errstr());
    return;
  };


  my $lane_count_sth = $dbh->prepare("SELECT lane.id FROM lane,flowcell,run WHERE lane.sample_id=? AND lane.flowcell_id=flowcell.id AND flowcell.run_id=run.id");
  my $sample_type_sth = $dbh->prepare("SELECT name FROM sample_type WHERE id=?");

  my @samples;
  while (my ($id,$name,$sample_type,$requested,$received,$first_name,$last_name)= $samples_sth->fetchrow_array()) {

    $lane_count_sth ->execute($id) or do {
      print_bug("Couldn't count lanes run for sample '$id': ".$dbh->errstr());
      return;
    };

    my @lane_ids;

    my $sample_type_name = 'Unknown';
    if ($sample_type) {
      $sample_type_sth->execute($sample_type) or do {
	print_bug("Couldn't look up name for sample type $sample_type: ".$dbh->errstr());
	return;
      };
      ($sample_type_name) = $sample_type_sth -> fetchrow_array();
    }

    while (my ($id) = $lane_count_sth->fetchrow_array()) {
      push @lane_ids,$id;
    }


    # If there's only one lane of results then we link directly to that
    # lane rather than making them go through the sample page.

    my $lane_id;
    $lane_id = $lane_ids[0] if (@lane_ids == 1);

    push @samples, {
		    SAMPLE_ID => $id,
		    NAME => $name,
		    SAMPLE_TYPE => $sample_type_name,
		    RECEIVED => $received,
		    LANES_REQUESTED => $requested,
		    LANES_RUN => scalar @lane_ids,
		    LANE_ID => $lane_id,
		    OWNER => "$first_name $last_name",
		   };

  }

  $template -> param(SAMPLES => \@samples);

  print $session->header();
  print $template -> output();

}


sub run_run_search {

  my $template = HTML::Template -> new (filename => 'search_results_run.html', associate=>$session);


  my $sql_query = "SELECT run.id,run.run_folder_name,DATE_FORMAT(run.date,'%e %b %Y'),run.flowcell_id,run_type.name FROM run,run_type,flowcell WHERE run.flowcell_id=flowcell.id AND flowcell.run_type_id=run_type.id";

  my @parameters;

  # Sort out the person id first
  unless ($session ->param("is_admin")) {
    print_bug("Only admins can search for runs");
    return;
  }

  # Filter by run type
  my $run_type = $q -> param("run_type");

  if ($run_type ne '[Any]') {

    if ($run_type !~ /^\d+$/) {
      print_bug("Run type should be a number, not '$run_type'");
      return;
    }

    $sql_query .= " AND run_type.id=?";
    push @parameters,$run_type;
  }

  # Filter by date
  unless ($q->param("any_date")) {

    $sql_query .= " AND run.date>=? AND run.date<?";

    my $from_month = $q->param('from_month');
    my $from_year = $q->param('from_year');
    my $to_month = $q->param('to_month');
    my $to_year = $q->param('to_year');

    unless ($from_month =~ /^\d+$/) {print_bug("From month $from_month was not a number");return;}
    unless ($to_month =~ /^\d+$/) {print_bug("To month $to_month was not a number");return;}
    unless ($from_year =~ /^\d+$/) {print_bug("From year $from_year was not a number");return;}
    unless ($to_year =~ /^\d+$/) {print_bug("To year $to_year was not a number");return;}

    if (length $from_month == 1) {
      $from_month = '0'.$from_month;
    }
    my $from_date="${from_year}-${from_month}-01";
    $to_month++;
    if ($to_month == 13) {
      $to_month = 1;
      $to_year++;
    }

    my $to_date = "${to_year}-${to_month}-01";

    push @parameters,$from_date,$to_date;

  }
	  
  # Flowcell ID
  my $flowcell_id_filter = $q->param("flowcell_id");

  if ($flowcell_id_filter) {
    unless ($flowcell_id_filter =~ /^\d+$/) {
      print_error("Flowcell IDs must be numbers ($flowcell_id_filter wasn't)");
      return;
    }

    $sql_query .= " AND run.flowcell_id=?";
    push @parameters,$flowcell_id_filter;

  }

  # Run Folder Name
  my $runfolder_name_filter = $q->param("name");

  if ($runfolder_name_filter) {

    if ($runfolder_name_filter =~ /\*/) {
      # We're doing a wildcard search

      # Remove anything potentially nasty from the string
      $runfolder_name_filter =~ s/[\'\"\\;%]//g;

      # Replace stars with %
      $runfolder_name_filter =~ s/\*/%/g;

#      print_bug("Search string was '$runfolder_name_filter'");
#      return;

      # Add it to the search
      $sql_query .= " AND run.run_folder_name LIKE \"$runfolder_name_filter\"";

    }
    else {
      # We're looking for an exact match
      $sql_query .= " AND run.run_folder_name=?";
      push @parameters,$runfolder_name_filter;
    }

  }

	  my $runs_sth = $dbh->prepare($sql_query);

  $runs_sth -> execute(@parameters) or do {
    print_bug("Couldn't run run search: ".$dbh->errstr());
    return;
  };


  my @runs;
  while (my ($run_id,$run_folder,$date,$flowcell_id,$run_type)= $runs_sth->fetchrow_array()) {

    push @runs, {
		 RUN_ID => $run_id,
		 FLOWCELL_ID => $flowcell_id,
		 RUN_TYPE => $run_type,
		 DATE => $date,
		 RUN_FOLDER => $run_folder,
		};

  }

  $template -> param(RUNS => \@runs);

  print $session->header();
  print $template -> output();

}

sub run_people_search {

  my $template = HTML::Template -> new (filename => 'search_results_people.html', associate=>$session);


  my $sql_query = "SELECT id,first_name,last_name,email FROM person WHERE id=id";

  my @parameters;

  # Sort out the person id first
  unless ($session ->param("is_admin")) {
    print_bug("Only admins can search for people");
    return;
  }

  # First Name
  my $first_name = $q->param("first_name");

  if ($first_name) {

    if ($first_name =~ /\*/) {
      # We're doing a wildcard search

      # Remove anything potentially nasty from the string
      $first_name =~ s/[\'\"\\;%]//g;

      # Replace stars with %
      $first_name =~ s/\*/%/g;

      # Add it to the search
      $sql_query .= " AND first_name LIKE \"$first_name\"";

    }
    else {
      # We're looking for an exact match
      $sql_query .= " AND first_name=?";
      push @parameters,$first_name;
    }
  }

  # Last Name
  my $last_name = $q->param("last_name");

  if ($last_name) {

    if ($last_name =~ /\*/) {
      # We're doing a wildcard search

      # Remove anything potentially nasty from the string
      $last_name =~ s/[\'\"\\;%]//g;

      # Replace stars with %
      $last_name =~ s/\*/%/g;

      # Add it to the search
      $sql_query .= " AND last_name LIKE \"$last_name\"";

    }
    else {
      # We're looking for an exact match
      $sql_query .= " AND last_name=?";
      push @parameters,$last_name;
    }
  }

  # Email
  my $email = $q->param("email");

  if ($email) {

    if ($email =~ /\*/) {
      # We're doing a wildcard search

      # Remove anything potentially nasty from the string
      $email =~ s/[\'\"\\;%]//g;

      # Replace stars with %
      $email =~ s/\*/%/g;

      # Add it to the search
      $sql_query .= " AND email LIKE \"$email\"";

    }
    else {
      # We're looking for an exact match
      $sql_query .= " AND email=?";
      push @parameters,$email;
    }
  }

  $sql_query .= " ORDER BY last_name,first_name";


  my $people_sth = $dbh->prepare($sql_query);

  $people_sth -> execute(@parameters) or do {
    print_bug("Couldn't run people search: ".$dbh->errstr());
    return;
  };

  my $sample_count_sth = $dbh->prepare("SELECT count(*) FROM sample WHERE person_id=? AND is_suitable_control=0 AND is_complete=?");


  my @people;
  while (my ($id,$first,$last,$email)= $people_sth->fetchrow_array()) {

    # Get active sample count
    $sample_count_sth -> execute($id,0) or do {
      print_bug("Failed to get active sample count for person $id: ".$dbh->errstr());
      return;
    };
    my $active_count = $sample_count_sth ->fetchrow_array();

    # Get complete sample count
    $sample_count_sth -> execute($id,1) or do {
      print_bug("Failed to get inactive sample count for person $id: ".$dbh->errstr());
      return;
    };
    my $inactive_count = $sample_count_sth ->fetchrow_array();


    push @people, {
		   PERSON_ID => $id,
		   FIRST_NAME => $first,
		   LAST_NAME => $last,
		   EMAIL => $email,
		   ACTIVE_SAMPLES => $active_count,
		   INACTIVE_SAMPLES => $inactive_count,
		  };

  }

  $template -> param(PEOPLE => \@people);

  print $session->header();
  print $template -> output();

}



sub start_change_details {
  my $template = HTML::Template -> new (filename => 'change_details.html', associate=>$session);

  # Find out if this is an admin changing someone else's details
  my $person_id = $q->param("person_id");
  my $force_person_id;

  if ($person_id) {
    unless ($session->param("is_admin")) {
      print_bug("Only admins can change someone else's details");
      return;
    }

    unless ($person_id =~ /^\d+$/) {
      print_bug("Person ID should be a number, not $person_id");
      return;
    }

    $force_person_id = $person_id;
  }
  else {
    $person_id = $session->param("person_id");
  }


  # Fill in their current details
  my ($first_name,$last_name,$phone,$email,$is_admin,$is_anonymous) = $dbh->selectrow_array("SELECT first_name,last_name,phone,email,is_admin,anonymous FROM person WHERE id=?",undef,($person_id));

  unless ($email) {
    print_bug("Couldn't fetch existing person details: ".$dbh->errstr());
    return;
  }

  $template->param(DETAILS_FIRST_NAME => $first_name,
		   DETAILS_LAST_NAME => $last_name,
		   PHONE => $phone,
		   DETAILS_EMAIL => $email,
		   FORCE_PERSON_ID => $force_person_id,
		   DETAILS_IS_ADMIN => $is_admin,
		   DETAILS_ANONYMOUS => $is_anonymous,
		  );

  # We also need to list any permissions granted to other people on their samples
  my @permissions;

  my $permissions_sth = $dbh->prepare("SELECT person_permission.id,person_permission.permission_person_id,person.first_name,person.last_name,person.email FROM person_permission,person WHERE person_permission.owner_person_id=? AND person_permission.permission_person_id=person.id ORDER BY person.last_name,person.first_name");

  $permissions_sth->execute($person_id) or do {
    print_bug("Couldn't get list of permissions for person $person_id:".$dbh->errstr());
    return;
  };

  while (my ($id,$owner_id,$first,$last,$email) = $permissions_sth->fetchrow_array()) {

    # We don't need to show the permission that you can see your own files
    next if ($owner_id == $person_id);

    push @permissions,{
		       PERMISSION_ID => $id,
		       NAME => "$first $last",
		       EMAIL => $email,
		      };
  }

  $template -> param(PERMISSIONS => \@permissions);


  # We also need to list any permissions we have on other people's samples
  my @other_permissions;

  my $other_permissions_sth = $dbh->prepare("SELECT person_permission.id,person_permission.owner_person_id,person.first_name,person.last_name,person.email FROM person_permission,person WHERE person_permission.permission_person_id=? AND person_permission.owner_person_id=person.id ORDER BY person.last_name,person.first_name");

  $other_permissions_sth->execute($person_id) or do {
    print_bug("Couldn't get list of permissions for person $person_id:".$dbh->errstr());
    return;
  };


  while (my ($id,$owner_id,$first,$last,$email) = $other_permissions_sth->fetchrow_array()) {

    # We don't need to show the permission that you can see your own files
    next if ($owner_id == $person_id);

    push @other_permissions,{
		       NAME => "$first $last",
		       EMAIL => $email,
		      };
  }

  $template -> param(OTHER_PERMISSIONS => \@other_permissions);


  print $session->header();
  print $template -> output();
}

sub finish_change_details {

  my $submit = $q->param("submit");

  unless ($submit) {
    print_bug("Couldn't tell if we were changing details or passwords");
    return;
  }

  if ($submit eq 'Update Details') {

    # Find out if we're an admin changing someone else's details
    my $person_id = $q->param("person_id");
    my $changing_others = 0;

    if ($person_id) {
      unless ($session->param("is_admin")) {
	print_bug("Only admins can change someone else's details");
	return;
      }

      unless ($person_id =~ /^\d+$/) {
	print_bug("Person ID should be a number, not $person_id");
	return;
      }
      $changing_others = 1;
    }
    else {
      $person_id = $session->param("person_id");
    }

    my $first_name = $q->param("first_name");
    unless ($first_name) {
      print_error("No first name supplied");
      return;
    }

    my $last_name = $q->param("last_name");
    unless ($last_name) {
      print_error("No last name supplied");
      return;
    }

    my $anonymous = $q->param("anonymous");
    if ($anonymous) {
      $anonymous = 1;
    }
    else {
      $anonymous = 0;
    }

    my $phone = $q->param("phone");
    $phone = "[No phone number]" unless ($phone);

    my $template;

    if ($changing_others) {

      my $email = $q->param("email");
      unless ($email) {
	print_error("No email address was supplied");
	return;
      }
      unless ($email =~ /\@/) {
	print_error("Email address didn't look like an email address");
	return;
      }


      my $is_admin = $q->param("is_admin");
      if ($is_admin) {
	$is_admin = 1;
      }
      else {
	$is_admin = 0;
      }

      # We can now do the update.
      $dbh->do("UPDATE person set first_name=?,last_name=?,phone=?,email=?,is_admin=?,anonymous=? WHERE id=?",undef,($first_name,$last_name,$phone,$email,$is_admin,$anonymous,$person_id)) or do {
	print_bug("Couldn't update person details: ".$dbh->errstr());
	return;
      };

      $template = HTML::Template -> new (filename=>'logged_in_message.html',associate => $session);

      $template -> param(MESSAGE => "Details for $first_name $last_name have been updated.");

  }

    else {
      # We can now do the update.
      $dbh->do("UPDATE person set first_name=?,last_name=?,phone=?,anonymous=? WHERE id=?",undef,($first_name,$last_name,$phone,$anonymous,$session->param("person_id"))) or do {
	print_bug("Couldn't update person details: ".$dbh->errstr());
	return;
      };

      $template = HTML::Template -> new (filename=>'logged_in_message.html',associate => $session);

      $template -> param(MESSAGE => 'Your details have been updated.');
    }

    print $session->header();
    print $template->output();


  }
  elsif ($submit eq 'Change Password') {

    my $old_password = $q->param("old_password");
    unless ($old_password) {
      print_error("You didn't enter your old password");
      return;
    }

    # We need to check that the password the supplied is valid
    my ($hash) = $dbh->selectrow_array("SELECT password FROM person where id=?",undef,($session->param("person_id")));

    unless ($hash) {
	print_bug("Couldn't find an account for id '".$session->param("person_id")."'.  This shouldn't happen.");
	return;
    }

    unless (check_password($old_password,$hash)) {
	print_error("Incorrect old password - sorry.");
	return;
    }

    my $new_password = $q->param("password");
    unless ($new_password) {
      print_error("You didn't enter your new password");
      return;
    }
    my $new_password2 = $q->param("password2");
    unless ($new_password2) {
      print_error("You didn't retype your new password");
      return;
    }

    unless ($new_password eq $new_password2) {
      print_error("The new passwords you entered did not match");
      return;
    }

    my $new_hash = generate_hash($new_password,get_salt());

    # We can now change the password
    $dbh->do("UPDATE person SET password=? WHERE id=?",undef,($new_hash,$session->param("person_id"))) or do {
      print_bug("Can't update password: ".$dbh->errstr());
      return;
    };

    my $template = HTML::Template -> new (filename=>'logged_in_message.html',associate => $session);

    $template -> param(MESSAGE => 'Your password has been changed.');

    print $session->header();
    print $template->output();


  }
  else {
    print_bug("Don't know what to do with '$submit'");
    return;
  }

}


sub add_permission {

  # Find out if we're an admin adding permission on someone else's details
  my $person_id = $q->param("person_id");
  my $changing_others = 0;

  if ($person_id) {
    unless ($session->param("is_admin")) {
      print_bug("Only admins can change someone else's details");
      return;
    }

    unless ($person_id =~ /^\d+$/) {
      print_bug("Person ID should be a number, not $person_id");
      return;
    }
    $changing_others = 1;
    }
  else {
    $person_id = $session->param("person_id");
  }

  my $email = $q->param("email");
  unless ($email) {
    print_error("No email address was supplied");
    return;
  }
  unless ($email =~ /\@/) {
    print_error("Email address didn't look like an email address");
    return;
  }

  # We now need to see if we can find an account with that email
  my ($new_person_id) = $dbh->selectrow_array("SELECT id FROM person WHERE email=?",undef,($email));

  unless ($new_person_id) {
    print_error("Couldn't find a user corresponding to '$email' - they need to have an account on the system before you can grant them access permissions");
    return;
  }

  # We need to check that this permission hasn't already been granted
  my ($existing_id) = $dbh->selectrow_array("SELECT id FROM person_permission WHERE owner_person_id=? AND permission_person_id=?",undef,($person_id,$new_person_id));

  if ($existing_id) {
    print_error("$email already has permission to view this data");
    return;
  }

  # We can now go ahead and add the permissions
  $dbh->do("INSERT INTO person_permission (owner_person_id,permission_person_id) VALUES (?,?)",undef,($person_id,$new_person_id)) or do {
    print_bug("Couldn't create new permission: ".$dbh->errstr());
    return;
  };

  # We now just return them back to the change details page
  if ($changing_others) {
    print $q->redirect("sierra.pl?action=change_details&person_id=$person_id");
  }
  else {
    print $q->redirect("sierra.pl?action=change_details");
  }

}

sub remove_permission {

  my $permission_id = $q->param("permission_id");
  unless ($permission_id and $permission_id =~ /^\d+$/) {
    print_bug("Permission ID should be a number, not $permission_id");
    return;
  }


  # Find out whose samples this applies to
  my ($person_id) = $dbh->selectrow_array("SELECT owner_person_id FROM person_permission WHERE id=?",undef,($permission_id));

  unless ($person_id) {
    print_bug("Couldn't get details for permission id $permission_id:". $dbh->errstr());
    return;
  }

  my $changing_others = 0;

  if ($person_id != $session->param("person_id")) {
    unless ($session->param("is_admin")) {
      print_bug("Only admins can change someone else's permissions");
      return;
    }
    $changing_others = 1;
  }

  # We can go ahead and delete the permission
  $dbh->do("DELETE FROM person_permission WHERE id=?",undef,($permission_id)) or do {
    print_bug("Couldn't delete permission $permission_id:".$dbh->errstr());
    return;
  };


  # We now just return them back to the change details page
  if ($changing_others) {
    print $q->redirect("sierra.pl?action=change_details&person_id=$person_id");
  }
  else {
    print $q->redirect("sierra.pl?action=change_details");
  }

}


sub send_password_reset {

  # This flag will be set if we've been sent here from creating
  # a new account.  If not then it's a direct request from the site
  my ($is_new_account) = @_;

  my $email = $q->param("email");

  my $password = $q->param("password");

  my $password2 = $q->param("password2");


  # If there's no data then show them the input form
  unless ($email || $password || $password2) {
    my $template = HTML::Template -> new (filename => 'password_reminder.html', associate=>$session);
    print $session->header();
    print $template -> output();
    return;
  }

  # We actually need to process the form.
  else {

    unless ($email) {
      print_error("No email address was entered");
      return;
    }

    unless ($password) {
      print_error("No password was entered");
      return;
    }

    if (length $password < 8) {
      print_error("Your password needs to be at least 8 characters");
      return;
    }

    unless ($password2) {
      print_error("You didn't retype your password");
      return;
    }

    unless ($password eq $password2) {
      print_error("The passwords you supplied were not the same");
      return;
    }


    my $salt = get_salt();
    my $hash = generate_hash($salt.$password);


    # See if this email is actually associated with an account
    my ($person_id) = $dbh->selectrow_array("SELECT id FROM person WHERE email=?",undef,($email));

    unless ($person_id) {
      print_error("No account appears to be registered under the address '$email'.  Use the 'Create New Account' option to create a new account or check that you typed your address correctly.");
      return;
    }

    # Check to see if they have submitted a reset request in the
    # last 30 mins
    my ($request_id) = $dbh->selectrow_array("SELECT id FROM password_reset WHERE person_id=? AND date > NOW()-INTERVAL 30 MINUTE",undef,($person_id));

    if ($request_id) {
      print_error("You appear to have sent a reminder in the last 30 minutes.  Please try again later");
      return;
    }

    # We can now go ahead and generate a new reminder

    # We need a secret code.  We shuffle all the letters
    # and numbers then take the first 20-40 as the secret
    my $secret = join('',(shuffle('a'..'z','A'..'Z',0..9))[0..20+int(rand(20))]);

    # Now delete any existing reminders we may have
    $dbh->do("DELETE FROM password_reset WHERE person_id=?",undef,($person_id)) or do {
      print_bug("Couldn't delete old password reminders: ".$dbh->errstr());
      return;
    };

    # Now create the new reminder
    $dbh->do("INSERT INTO password_reset (person_id,date,secret,password) values (?,NOW(),?,?)",undef,($person_id,$secret,"$salt$hash")) or do {
      print_bug("Couldn't create new password reminder: ".$dbh->errstr());
      return;
    };

    # Send the user and email to say what we've done.
    my $email_template = HTML::Template -> new (filename=>'password_reset_email.txt',associate => $session);
    $email_template -> param(PERSON_ID => $person_id,
			     SECRET => $secret,
			     IS_NEW_ACCOUNT => $is_new_account);

    if ($is_new_account) {
      send_email("[Sierra] New account registered",$email_template->output(),$email) or return;
    }
    else {
      send_email("[Sierra] Password Reset Request",$email_template->output(),$email) or return;
    }

    # Print out a message saying what we've done

    my $template = HTML::Template -> new (filename=>'not_logged_in_message.html',associate => $session);

    if ($is_new_account) {
      $template -> param(MESSAGE => 'Your account has been created and you have been send a confirmatory email.  Your new account will not work until you click on the link in the email.');
    }
    else {
      $template -> param(MESSAGE => 'Your password reset email has been sent.  Your new password will not work until you click on the link in the email.');
    }
    print $session->header();
    print $template->output();

  }

}

sub get_salt {

  my $salt;
  my @chars = shuffle('a'..'z','A'..'Z',0..9);

  for (1..32) {
    $salt .= $chars[int rand @chars];
  }

  return $salt;


}


sub reset_password {

  my $person_id=$q->param("person_id");
  unless ($person_id) {
    print_error("No person_id was included in the password reset request - check the link you cliked on didn't wrap onto two lines in your email program.");
    return;
  }

  my $secret = $q->param("secret");
  unless ($secret) {
    print_error("No authorisation code was included in the password reset request - check the link you cliked on didn't wrap onto two lines in your email program.");
    return;
  }

  # Check to see if we're going to let them do this
  my ($reset_id,$hash) = $dbh->selectrow_array("SELECT id,password FROM password_reset WHERE person_id=? AND secret=? AND date > NOW() - INTERVAL 1 DAY",undef,($person_id,$secret));

  unless ($reset_id) {
    print_error("Couldn't find a valid reset request using the data you sent.  Reset requests expire after 24 hours - you need to generate another request if you left it longer than that to reply");
    return;
  }

  # OK we can change their password
  $dbh->do("UPDATE person SET password=? WHERE id=?",undef,($hash,$person_id)) or do {
    print_bug("Can't update password:".$dbh->errstr());
    return;
  };

  # We can now delete the request
  $dbh->do("DELETE FROM password_reset WHERE id=?",undef,($reset_id)) or do {
    print_bug("Can't delete password reset entry:".$dbh->errstr());
    return;
  };

    my $template = HTML::Template -> new (filename=>'not_logged_in_message.html',associate => $session);

    $template -> param(MESSAGE => 'Your new password has been activated.  You should now be able to log in using the new password you chose.');

    print $session->header();
    print $template->output();

}

sub send_file {

  my $lane_id = $q->param("lane_id");
  unless ($lane_id and $lane_id =~ /^\d+$/) {
    print_bug("Expected a lane id but got '$lane_id'");
    return;
  }

  # We can now get the details for this lane
  my ($run_folder,$sample_id,$lane_number) = $dbh->selectrow_array("SELECT run.run_folder_name,lane.sample_id,lane.lane_number FROM run,lane WHERE lane.id=? AND lane.flowcell_id=run.flowcell_id",undef,($lane_id));

  unless ($sample_id) {
    print_bug("Couldn't get details for lane $lane_id: ".$dbh->errstr());
    return;
  }

  # We need to check that this person can view this sample
  unless (check_sample_view_permission($sample_id,$session->param("person_id"))) {
    print_bug("You do not have permission to view this sample.  Sorry.");
    return;
  }

  # Get the path they've requested
  my $path = $q->param("path");
  unless ($path) {
    print_bug("No file path was specified");
    return;
  }

  # We need to get the full list of files to see if this matches one of them.
  my $run_obj = Sierra::IlluminaRun->new($run_folder);
  my $lane_obj = $run_obj->get_lane($lane_number);

  my @folders = $run_obj->get_results_folders();

  foreach my $folder (@folders) {

    my @files = $folder -> get_files_for_lane($lane_obj);

    foreach my $file (@files) {

      if ($file->path() eq $path) {
	open (IN,$file->path()) or do {
	  print_bug("Couldn't read $path: $!");
	  return;
	};

	if ($file->mime_type()) {
	  print "Content-type: ",$file->mime_type(),"\n";
	}

	else {
	  print "Content-type: application/octet-stream\nContent-disposition: attachment; filename=",$file->name()."\n";
	}



	if ($file->mime_type() and $file->mime_type() eq 'text/html') {

	  # We munge the internal links within HTML files so they're replaced with
	  # further calls to send_file.  This is particularly used for FastQC reports
	  # so people can view the reports without having to download and unzip them
	  # each time.  It other types of html file are listed then this might well
	  # break them.


	  # As we're munging the content we can't send a content size since we don't
	  # know in advance how big the response is going to be, so just end the
	  # headers here.
	  print "\n";


	  # The base for the path is the directory which contains the HTML file
	  my $base = $file->path();

	  $base =~ s/\/[^\/]+$/\//;
	  while (<IN>) {

	    # We should probably URI escape the path as this may contain
	    # special characters.
	    #
	    # This breaks links to external addresses, or links which contain
	    # base64 encoded data, so we need to make this a bit more specific
	    if ($q->param("authkey")) {
	      my $key = $q->param("authkey");
	      s/src=\"(?!data)/src=\"sierra.pl?action=send_file&lane_id=$lane_id&authkey=$key&path=$base/g;
	    }
	    else {
	      s/src=\"(?!data)/src=\"sierra.pl?action=send_file&lane_id=$lane_id&path=$base/g;
	    }
		
	    print;
	  }
	}

	else {

	  # Since we're sending the file verbatim we can let them know how big
	  # it's going to be.
	  print "Content-length: ",(stat($file->path()))[7],"\n\n";
	  binmode IN;
	  print while (<IN>);
	}

	return;

      }
    }

  }

  print_bug("Couldn't find file '$path' associated with lane $lane_id");

}

sub view_lane {

  my $template = HTML::Template -> new (filename=>'view_lane.html',associate => $session);

  my $lane_id = $q->param("lane_id");
  unless ($lane_id and $lane_id =~ /^\d+$/) {
    print_bug("Expected a lane id but got '$lane_id'");
    return;
  }

  # We can now get the details for this lane
  my ($run_folder,$lane_number,$sample_id,$sample_name,$run_type,$date_run,$search_database_id,$run_id,$flowcell_id) = $dbh->selectrow_array("SELECT run.run_folder_name,lane.lane_number,lane.sample_id,sample.users_sample_name,run_type.name,DATE_FORMAT(run.date,'%e %b %Y'),sample.search_database_id,run.id,run.flowcell_id FROM lane,flowcell,run,run_type,sample WHERE lane.id=? AND lane.flowcell_id=run.flowcell_id AND lane.flowcell_id=flowcell.id AND lane.sample_id=sample.id AND flowcell.run_type_id=run_type.id",undef,($lane_id));

  unless ($sample_id) {
    print_bug("Couldn't get details for lane $lane_id: ".$dbh->errstr());
    return;
  }

  # We need to check that this person can view this sample
  unless (check_sample_view_permission($sample_id,$session->param("person_id"))) {
    print_bug("You do not have permission to view this sample.  Sorry.");
    return;
  }

  # Translate the search database into a real name
  my $search_database;

  if ($search_database_id) {
    my ($species,$assembly) = $dbh->selectrow_array("SELECT species,assembly FROM search_database WHERE id=?",undef,($search_database_id));
    $search_database = "$species : $assembly";
  }

  $template -> param(SAMPLE_ID => $sample_id,
		     USER_SAMPLE_NAME => $sample_name,
		     DATE_RUN => $date_run,
		     LANE_ID => $lane_id,
		     FLOWCELL_ID => $flowcell_id,
		     LANE_NUMBER => $lane_number,
		     RUN_TYPE => $run_type,
		     SEARCH_DATABASE => $search_database,
		     RUN_FOLDER => $run_folder,
		     AUTHKEY => $q->param("authkey") || 0,
		    );


  # See if we have a barcode to filter on
  my $barcode_id = $q->param("barcode");

  if ($barcode_id) {
    unless ($barcode_id =~ /^\d+$/) {
      print_bug("Unusual barcode id '$barcode_id' found");
      return;
    }
  }

  # See if we have a file type to filter on
  my $file_type_filter = $q->param("filetype");
  

  # Make an array to store the codes we're going to 
  # filter files against.
  my @barcode_sequences;

  # Make a hash to store the different file types we're going to see
  my %file_types;

  # Make up an array for the barcode templates
  my @barcodes;

  # Now list all barcodes and select the one we're
  # showing.

  my $list_barcodes_sth = $dbh->prepare("SELECT id,5_prime_barcode,3_prime_barcode,name FROM barcode WHERE sample_id=?");
  $list_barcodes_sth -> execute($sample_id) or do {
    print_bug("Couldn't list barcodes for sample $sample_id:".$dbh->errstr());
    return;
  };

  while (my ($id,$prime5,$prime3,$name) = $list_barcodes_sth->fetchrow_array()) {
    my $selected = 0;

    # If we have multiple barcodes we'll only show the first one
    # since that's what will be on the filename anyway and it makes
    # things shorter and more manageable.

    # To be consistent about which one we use we need to sort the
    # barcodes we have.  On the filenames we always show the 
    # 'lowest' one.


    $prime5 = (sort{$a cmp $b} (split(/\:/,$prime5)))[0] if ($prime5);
    $prime3 = (sort{$a cmp $b} (split(/\:/,$prime3)))[0] if ($prime3);

    if ($id == $barcode_id) {
      push @barcode_sequences, $prime5 if ($prime5);
      push @barcode_sequences, $prime3 if ($prime3);
      $selected = 1;
    }

    push @barcodes, {
		     BARCODE_ID => $id,
		     SELECTED => $selected,
		     '5PRIME' => $prime5,
		     '3PRIME' => $prime3,
		     DESC => $name
		    };

  }

  $template -> param(BARCODES => \@barcodes);

  # Now we can see if we have any files to show

  my %file_type_results;

  # If we have an AUTHCODE we'll also make up a list of static links
  my @links;


  my $run_obj = Sierra::IlluminaRun->new($run_folder);
  my $lane_obj = $run_obj->get_lane($lane_number);


  my @folders = $run_obj->get_results_folders();

  foreach my $folder (@folders) {

    my @files = $folder -> get_files_for_lane($lane_obj,$file_type_filter, @barcode_sequences);

    next if (@files == 0);

    foreach my $file (@files) {
      # Some files can be downloaded, but shouldn't show up in
      # the initial list of files.
      next if ($file->hidden());

      $file_types{$file->type()} = 1;

      # If we're filtering by file type only show hits to the matched type
      if ($file_type_filter and $file->type() ne $file_type_filter) {
	next;
      }

      unless (exists $file_type_results{$file->type()}) {
	$file_type_results{$file->type()} = {FILE_TYPE => $file->type(),
					     FILES => []};
      }

      my $path = $file->path();
      # We remove everything up to the run folder from the path
      # and replace it with just the run folder so that we can hide
      # away the internal representation of where the data is stored.
      $path =~  s/^.*\Q$run_folder\E\/*/$run_folder\//;


      # We also strip off everything from the file name onwards.  For
      # things like fastqc reports the name we see isn't what's at the
      # end of the path (it shows the folder) so we need to remove 
      # everything after that as well to leave just the path.
      my $file_name = $file->name();
      $path =~ s/\Q$file_name\E.*//;

      push @{$file_type_results{$file->type()}->{FILES}},{
							  LANE_ID => $lane_id,
							  FILE_NAME => $file->name(),
							  FILE_PATH => $file->path(),
							  FILE_INFORMATION => $file->info(),
							  PATH => $path,
							  FILE_SIZE => $file->size(),
							  AUTHKEY => $q->param("authkey") || 0,
				      };

      # If we have an AUTHKEY we'll populate the links data structure
      if ($q->param("authkey")) {
	  push @links, {
	      LINK => "$Sierra::Constants::BASE_URL/".$file->name()."?action=send_file&lane_id=$lane_id;path=".$file->path().";authkey=".$q->param('authkey'),
	      FILENAME => $file->name(),
	  };
      }

    }

  }

  # Now turn the %file_type_results hash into an array to include
  # it in the template
  my @results;
  foreach my $file_type (sort {$a cmp $b} keys %file_type_results) {
    push @results, $file_type_results{$file_type};
  }

  $template->param(
      FILE_TYPE_RESULTS => \@results,
      LINKS => \@links,
      );

#  print "Content-type:text/plain\n\n",(Dumper(\@results));
#  return;


  my @file_types;
  foreach my $type (sort {$a cmp $b} keys %file_types) {
    if (defined($file_type_filter) and $type eq $file_type_filter) {
      push @file_types , {FILE_TYPE => $type, SELECTED=>1};
    }
    else {
      push @file_types , {FILE_TYPE => $type};
    }
  }

  $template->param(FILE_TYPES => \@file_types);

  print $session->header();
  print $template->output();

}


sub view_sample {

  my $template = HTML::Template -> new (filename=>'view_sample.html',associate => $session);

  my $sample_id = $q->param("sample_id");
  unless ($sample_id and $sample_id =~ /^\d+$/) {
    print_bug("Expected a sample id but got '$sample_id'");
    return;
  }

  # We can now get the details for this sample
  my ($person_id,$user_sample_name,$sample_type_id,$lanes_requested,$adapter_id,$submitted,$received,$passed_qc,$run_type,$search_id,$is_complete,$first_name,$last_name) = $dbh->selectrow_array("SELECT sample.person_id,sample.users_sample_name,sample.sample_type_id,sample.lanes_required,sample.adapter_id,DATE_FORMAT(sample.submitted_date,'%e %b %Y'),DATE_FORMAT(sample.received_date,'%e %b %Y'),DATE_FORMAT(sample.passed_qc_date,'%e %b %Y'),run_type.name,sample.search_database_id,sample.is_complete,person.first_name,person.last_name FROM sample,run_type,adapter,person WHERE sample.id=? AND sample.run_type_id=run_type.id AND sample.person_id=person.id",undef,($sample_id));

  unless ($person_id) {
    print_bug("Couldn't fetch details for sample '$sample_id':".$dbh->errstr());
    return;
  }

  # We need to check that this person can view this sample
  unless (check_sample_view_permission($sample_id,$session->param("person_id"))) {
    print_error("You do not have permission to view this sample.  Sorry.");
    return;
  }

  # Translate the search database into a real name
  my $search_database;

  if ($search_id) {
    my ($species,$assembly) = $dbh->selectrow_array("SELECT species,assembly FROM search_database WHERE id=?",undef,($search_id));
    $search_database = "$species : $assembly";
  }

  # Translate the sample type into a real name
  my $sample_type = 'Unknown';
  if ($sample_type_id) {
    ($sample_type) = $dbh->selectrow_array("SELECT name FROM sample_type WHERE id=?",undef,($sample_type_id));
    unless (defined $sample_type) {
      print_bug("Couldn't get sample type from id $sample_type_id:".$dbh->errstr());
      return;
    }
  }

  # Translate the adapter id into a real name
  my $adapter_name;
  if ($adapter_id) {
    ($adapter_name) = $dbh->selectrow_array("SELECT name FROM adapter WHERE id=?",undef,($adapter_id));
  }

  $template -> param(SAMPLE_ID => $sample_id,
		     USER_SAMPLE_ID => $user_sample_name,
		     SAMPLE_TYPE => $sample_type,
		     LANES_REQUESTED => $lanes_requested,
		     ADAPTER => $adapter_name,
		     SUBMITTED_DATE => $submitted,
		     DATE_RECEIVED => $received,
		     DATE_PASSED_QC => $passed_qc,
		     RUN_TYPE => $run_type,
		     SEARCH_DATABASE => $search_database,
		     IS_ACTIVE => !$is_complete,
		     SAMPLE_OWNER => "$first_name $last_name",
		    );


    # Check what barcodes are present
    my $list_barcodes_sth = $dbh->prepare("SELECT 5_prime_barcode,3_prime_barcode,name FROM barcode WHERE sample_id=?");
    $list_barcodes_sth->execute($sample_id) or do {
      print_bug("Failed to list barcodes for sample $sample_id: ".$dbh->errstr());
      return;
    };

    my @barcodes;
    while (my ($barcode5,$barcode3,$desc) = $list_barcodes_sth->fetchrow_array()) {
      push @barcodes,{
		      '5PRIME' => $barcode5,
		      '3PRIME' => $barcode3,
		      DESCRIPTION => $desc,
		     };
    }

    $template->param(BARCODES => \@barcodes);


  # Now add any notes
  my $notes_sth = $dbh->prepare("SELECT person.first_name,person.last_name,DATE_FORMAT(sample_note.date,'%e %b %Y'),sample_note.note, sample_note.filename FROM sample_note,person WHERE sample_note.sample_id=? AND sample_note.person_id=person.id ORDER BY sample_note.date");

  $notes_sth -> execute($sample_id) or do {
    print_bug("Can't get notes for sample '$sample_id': ".$dbh->errstr());
    return;
  };

  my @notes;
  while (my ($first,$last,$date,$text,$filename) = $notes_sth->fetchrow_array()) {
    my @paragraphs;

    # The filename has a timestamp on the front.  We'll hide this
    # when we show it to use the user.
    my $viewname = $filename;
    $viewname =~ s/^\d+_//;

    push @paragraphs, {TEXT => $_} foreach (split(/[\r\n]+/,$text));
    push @notes, {
		  FIRST_NAME => $first,
		  LAST_NAME => $last,
		  DATE => $date,
		  PARAGRAPHS => \@paragraphs,
		  FILENAME => $filename,
		  VIEWNAME => $viewname,
		  SAMPLE_ID => $sample_id,
		 };
  }

  $template -> param(NOTES => \@notes);

  # Now we can find any results for this sample
  my @results;

  my $results_sth = $dbh->prepare("SELECT lane.id,lane.lane_number,run.run_folder_name,flowcell.id,DATE_FORMAT(run.date,'%e %b %Y') FROM lane,flowcell,run WHERE lane.sample_id=? AND lane.flowcell_id=flowcell.id AND run.flowcell_id=flowcell.id ORDER BY run.date, lane.lane_number");

  $results_sth -> execute($sample_id) or do {
    print_bug("Couldn't get results for sample id '$sample_id': ".$dbh->errstr());
    return;
  };

  while (my ($lane_id,$lane_number,$run_folder,$flowcell_id,$date) = $results_sth->fetchrow_array()) {
    if ($session -> param("is_admin")) {
      push @results, {
		      DATE => $date,
		      FLOWCELL_ID => $flowcell_id,
		      RUN_FOLDER => $run_folder,
		      LANE => $lane_number,
		      LANE_ID => $lane_id
		     };

    }
    else {
      push @results, {
		      DATE => $date,
		      RUN_FOLDER => $run_folder,
		      LANE => $lane_number,
		      LANE_ID => $lane_id,
		      AUTHKEY => $q->param("authkey"),
		     };
    }
  }


  $template -> param(RESULTS => \@results,
		     RESULT_COUNT => scalar @results);

  print $session->header();
  print $template -> output();

}

{

  my %barcode_aliases;

  sub get_barcode_for_alias {
    my ($name) = @_;

    unless (%barcode_aliases) {
      open (BARCODES,"$Bin/../conf/barcode_aliases.txt") or do {
	print_bug("Couldn't read barcode_aliases.txt file:$!");
	exit;
      };

      while (<BARCODES>) {
	next if (/^\#/);
	chomp;
	s/[\r\n]//g;
	my ($alias,$code) = split(/\t/);
	$barcode_aliases{$alias} = $code;
      }

      close BARCODES;
    }

    if (exists $barcode_aliases{$name}) {
      return $barcode_aliases{$name};
    }
    return $name;
  }

}


sub add_barcode {

  my $sample_id = $q->param("sample_id");
  unless ($sample_id =~ /^\d+$/) {
    print_bug("Expected a sample id but got '$sample_id'");
    return;
  }

  # We need to check that this person can view this sample
  unless (check_sample_edit_permission($sample_id,$session->param("person_id"))) {
    print_bug("You do not have permission to edit this sample.  Sorry.");
    return;
  }

  # Now we can check that we have a barcode from at least one end
  my $barcode5 = $q->param("5prime");
  my $barcode3 = $q->param("3prime");
  my $description = $q->param("description");

  unless ($barcode5 or $barcode3) {
    print_error("No barcode sequence was supplied");
    return;
  }

  # Take any spaces out of the barcode sequence
  $barcode5 =~ s/\s+//g;
  $barcode3 =~ s/\s+//g;

  # For consistency we'll keep all barcodes as upper case
  $barcode5 = uc($barcode5);
  $barcode3 = uc($barcode3);

  if ($barcode5 and $barcode5 !~ /^[GATC\:]+$/) {
    # Try to look up the barcode as an alias
    $barcode5 = get_barcode_for_alias($barcode5);
  }

  if ($barcode3 and $barcode3 !~ /^[GATC\:]+$/) {
    # Try to look up the barcode as an alias
    $barcode3 = get_barcode_for_alias($barcode3);
  }

  if ($barcode3 and ! $barcode5) {
      print_error("You can't have just a Second barcode without a First one");
      return;
  }


  # We used to allow admins to put in non GATC barcodes, but
  # I'm going to disable this as there's no real case for
  # letting people do this.

  unless ("$barcode5$barcode3" =~ /^[GATC\:]+$/ | $session->param("is_admin")) { # Admins can use non-GATC barcodes
    print_error("Barcode sequences must only contain GATC");
    return;
  }

  # If there are existing barcodes we need to check that the new barcodes
  # match the length and structure (5', 3' or both) of the existing ones
  # otherwise things will break.

  my ($existing_id,$existing5,$existing3) = $dbh->selectrow_array("SELECT id,5_prime_barcode,3_prime_barcode FROM barcode WHERE sample_id=? LIMIT 1",undef,($sample_id));

  if ($existing_id) {

    # We can validate the new barcode against the existing codes
    if ($existing5 and ! $barcode5) {
      print_error("No First barcode supplied when there is an existing First barcode on this sample");
      return;
    }

    if (!$existing5 and $barcode5) {
      print_error("First barcode supplied when there isn't a First barcode on previous barcodes on this sample");
      return;
    }

    if ($existing3 and ! $barcode3) {
      print_error("No Second barcode supplied when there is an existing Second barcode on this sample");
      return;
    }

    if (!$existing3 and $barcode3) {
      print_error("Second barcode supplied when there isn't a Second barcode on previous barcodes on this sample");
      return;
    }

    if ($existing5 and $barcode5) {
      if (length($existing5) != length($barcode5)) {
	print_error("New First barcode '$barcode5' wasn't the same length as the existing First barcode '$existing5'");
	return;
      }
    }

    if ($existing3 and $barcode3) {
      if (length($existing3) != length($barcode3)) {
	print_error("New Second barcode '$barcode3' wasn't the same length as the existing Second barcode '$existing3'");
	return;
      }
    }
  }

  # We should check that this barcode doesn't exist for
  # this sample already
  my ($barcode_id) = $dbh->selectrow_array("SELECT id FROM barcode WHERE sample_id=? AND 5_prime_barcode=? AND 3_prime_barcode=?",undef,($sample_id,$barcode5,$barcode3));

  if ($barcode_id) {
    print_error("This sample already has an entry for this barcode combination");
    return;
  }

  # We should check that this barcode name doesn't exist for
  # this sample already

  # If there isn't a name then we just go with barcode-x and
  # keep increasing x until we find a name which hasn't been
  # used.  If they specified the name then it's their job to
  # make sure it's unique.

  if ($description) {
      my ($barcode_id) = $dbh->selectrow_array("SELECT id FROM barcode WHERE sample_id=? AND name=?",undef,($sample_id,$description));

      if ($barcode_id) {
	  print_error("This sample already has a barcode sample called \"$description\"");
	  return;
      }
  }
  else {
      my $number = 0;

      while (1) {
	  ++$number;
	  $description = "Barcode-$number";

	  my ($barcode_id) = $dbh->selectrow_array("SELECT id FROM barcode WHERE sample_id=? AND name=?",undef,($sample_id,$description));

	  last unless ($barcode_id);

	  if ($number > 1000) {
	      # Something's broken - we're never going to have more than 1000 barcodes
	      # for a sample

	      print_bug("Couldn't create a suitable barcode name for sample $sample_id");
	      return;
	  }
      }
  }
  # Make the new barcode
  $dbh->do("INSERT INTO barcode (sample_id,5_prime_barcode,3_prime_barcode,name) VALUES (?,?,?,?)",undef,($sample_id,$barcode5,$barcode3,$description)) or do {
    print_bug("Failed to insert new barcode: ".$dbh->errstr());
    return;
  };

  # Redirect them back to the edit sample page
  print $q->redirect("sierra.pl?action=edit_sample&sample_id=$sample_id");

}

sub show_note_file {

  # Returns a file which was previously attached to a note

  my $sample_id = $q -> param('sample_id');

  unless ($sample_id =~ /^\d+$/) {
      print_bug("Didn't look like a sample id");
      return;
  };


  my $filename = $q -> param('filename');

  unless ($filename =~ /^[\w\-._ ]+$/) {
      print_error("Invalid file name");
      return;
  }


  my $file_path = $Sierra::Constants::FILES_DIR . "/Sample${sample_id}/${filename}";


  my $mime_type = 'text/plain';


  my %overridden_types = (
			  docx => 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
			  pptx => 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
			  xlsx => 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
			  pl => 'text/plain',
                          sh => 'text/plain',
			  pzfx => 'application/x-graphpad-prism-pzfx',
			 );

  if ($filename =~ /\.(\w+)$/) {
    my $extension = lc($1);

    if (exists $overridden_types{$extension}) {
      $mime_type = $overridden_types{$extension};
    }
    else {

      open (MIME,'/etc/mime.types') or do{print_bug("Can't open MIME type file: $!"); return;};

      while (<MIME>) {
	chomp;
	my ($type,$ext) = split(/\s+/);
	next unless ($ext);

	if ($ext eq $extension) {
	  $mime_type = $type;
	  last;
	}
      }

      close MIME;
    }
  }

  open (FILE,$file_path) or do {print_bug("Can't read $file_path: $!");return;};

  binmode FILE;

  print "Content-type: $mime_type\n\n";

  print while (<FILE>);

  close FILE;

}


sub remove_barcode {

  my $barcode_id = $q->param("barcode_id");
  unless ($barcode_id =~ /^\d+$/) {
    print_bug("Expected a barcode id but got '$barcode_id'");
    return;
  }

  # Get the corresponding sample id
  my ($sample_id) = $dbh->selectrow_array("SELECT sample_id FROM barcode WHERE id=?",undef,($barcode_id));

  unless ($sample_id) {
    print_bug("Couldn't find sample id for barcode $barcode_id".$dbh->errstr());
    return;
  }

  # We need to check that this person can view this sample
  unless (check_sample_edit_permission($sample_id,$session->param("person_id"))) {
    print_bug("You do not have permission to edit this sample.  Sorry.");
    return;
  }


  # Delete the barcode
  $dbh->do("DELETE FROM barcode WHERE sample_id=? AND id=?",undef,($sample_id,$barcode_id)) or do {
    print_bug("Failed to delete barcode: ".$dbh->errstr());
    return;
  };

  # Redirect them back to the edit sample page
  print $q->redirect("sierra.pl?action=edit_sample&sample_id=$sample_id");

}


sub add_authkey {

  my $sample_id = $q->param("sample_id");
  unless ($sample_id =~ /^\d+$/) {
    print_bug("Expected a sample id but got '$sample_id'");
    return;
  }

  # We need to check that this person can edit this sample
  unless (check_sample_edit_permission($sample_id,$session->param("person_id"))) {
    print_bug("You do not have permission to edit this sample.  Sorry.");
    return;
  }

  # Now we can check whether they've provided a message
  my $message = $q->param("message");
  $message = "Created at ".localtime() unless ($message);

  # Generate a new random key
  my $authkey = make_random_string(50);

  # Make the new authkey
  $dbh->do("INSERT INTO sample_auth_key (sample_id,person_id,authkey,message) VALUES (?,?,?,?)",undef,($sample_id,$session->param("person_id"),$authkey,$message)) or do {
    print_bug("Failed to insert new sample authkey: ".$dbh->errstr());
    return;
  };

  # Redirect them back to the edit sample page
  print $q->redirect("sierra.pl?action=edit_sample&sample_id=$sample_id");

}


sub remove_authkey {

  my $authkey_id = $q->param("authkey_id");
  unless ($authkey_id =~ /^\d+$/) {
    print_bug("Expected an authkey id but got '$authkey_id'");
    return;
  }

  # Get the corresponding sample id
  my ($sample_id) = $dbh->selectrow_array("SELECT sample_id FROM sample_auth_key WHERE id=?",undef,($authkey_id));

  unless ($sample_id) {
    print_bug("Couldn't find sample id for authkey $authkey_id".$dbh->errstr());
    return;
  }

  # We need to check that this person can edit this sample
  unless (check_sample_edit_permission($sample_id,$session->param("person_id"))) {
    print_bug("You do not have permission to edit this sample.  Sorry.");
    return;
  }


  # Delete the barcode
  $dbh->do("DELETE FROM sample_auth_key WHERE sample_id=? AND id=?",undef,($sample_id,$authkey_id)) or do {
    print_bug("Failed to delete authkey: ".$dbh->errstr());
    return;
  };

  # Redirect them back to the edit sample page
  print $q->redirect("sierra.pl?action=edit_sample&sample_id=$sample_id");

}

sub edit_sample {

  my $template = HTML::Template -> new (filename=>'edit_sample.html',associate => $session);

  # If this gets called without a sample id then we're making a new sample

  my $sample_id = $q->param("sample_id");
  if ($sample_id) {
    unless ($sample_id =~ /^\d+$/) {
      print_bug("Expected a sample id but got '$sample_id'");
      return;
    }
  }

  # We can now get the details for this sample
  my ($person_id,$user_sample_name,$sample_type_id,$lanes_requested,$adapter_id,$budget_code,$run_type,$search_id,$is_complete,$is_control);
  my $lanes_run;
  if ($sample_id) {

    ($person_id,$user_sample_name,$sample_type_id,$lanes_requested,$adapter_id,$budget_code,$run_type,$search_id,$is_complete,$is_control) = $dbh->selectrow_array("SELECT sample.person_id,sample.users_sample_name,sample.sample_type_id,sample.lanes_required,sample.adapter_id,sample.budget_code,run_type.id,sample.search_database_id,sample.is_complete,sample.is_suitable_control FROM sample,run_type WHERE sample.id=? AND sample.run_type_id=run_type.id",undef,($sample_id));

    unless ($person_id) {
      print_bug("Couldn't fetch details for sample '$sample_id':".$dbh->errstr());
      return;
    }

    # We need to check that this person can view this sample
    unless (check_sample_edit_permission($sample_id,$session->param("person_id"))) {
      print_bug("You do not have permission to edit this sample.  Sorry.");
      return;
    }

    # We need to know how many lanes have already been run for this sample
    ($lanes_run) = $dbh->selectrow_array("SELECT count(*) FROM lane WHERE sample_id=?",undef,($sample_id));

    unless (defined $lanes_run) {
      print_bug("Couldn't get lanes run count for sample $sample_id:".$dbh->errstr());
      return;
    }
    $template->param(LANES_RUN => $lanes_run);


    # Check what barcodes are present
    my $list_barcodes_sth = $dbh->prepare("SELECT id,5_prime_barcode,3_prime_barcode,name FROM barcode WHERE sample_id=?");
    $list_barcodes_sth->execute($sample_id) or do {
      print_bug("Failed to list barcodes for sample $sample_id: ".$dbh->errstr());
      return;
    };

    my @barcodes;
    while (my ($id,$barcode5,$barcode3,$desc) = $list_barcodes_sth->fetchrow_array()) {
      push @barcodes,{
		      BARCODE_ID => $id,
		      '5PRIME' => $barcode5,
		      '3PRIME' => $barcode3,
		      DESCRIPTION => $desc,
		     };
    }

    $template->param(BARCODES => \@barcodes);


    # See if there are any authkeys
    my $list_authkeys_sth = $dbh->prepare("SELECT id,authkey,message FROM sample_auth_key WHERE sample_id=?");
    $list_authkeys_sth->execute($sample_id) or do {
      print_bug("Failed to list auth keys for sample $sample_id: ".$dbh->errstr());
      return;
    };

    my @authkeys;
    while (my ($id,$authkey,$message) = $list_authkeys_sth->fetchrow_array()) {
      push @authkeys,{
		      AUTHKEY_ID => $id,
		      AUTHKEY => $authkey,
		      MESSAGE => $message,
		      SAMPLE_ID => $sample_id,
		     };
    }

    $template->param(AUTHKEYS => \@authkeys);

  }
  else {
    # We may still have been passed some parameters from a
    # previously entered sample

    $sample_type_id = $q->param("sample_type");
    $lanes_requested = $q->param("lanes_required");
    $adapter_id = $q->param("adapter_id");
    $run_type = $q->param("run_type_id");
    $search_id = $q->param("database_id");
    $person_id = $q->param("person_id");
    $budget_code = $q->param("budget");

    my $last_sample_id = $q->param("last_sample_id");

    # We give the new sample the current user as an owner by default
    $person_id = $session->param("person_id") unless ($person_id);


    $template->param(LAST_SAMPLE_ID => $last_sample_id);
  }



  # We need a list of run types

  my @runs;
  my $run_sth = $dbh->prepare("SELECT id,name,retired FROM run_type ORDER BY retired, name");

  $run_sth->execute() or do {
    print_bug("Couldn't get list of run types: ".$dbh->errstr());
    return;
  };

  while (my ($id,$name,$desc,$retired) = $run_sth->fetchrow_array()) {
    # Non admins only get to see run types which are either current
    # or are currently applied to their sample.  Admins can see
    # retired types as well.
    next if ($retired and ((!$run_type) or $id != $run_type) and ! $session->param("is_admin"));

    # We flag retired types so admins don't use them inadvertently
    if ($retired) {
      $name = "[Retired] $name";
    }

    if ($id eq $run_type) {
      push @runs, {ID=>$id,NAME=>$name, SELECTED=>1};
    }
    else {
      push @runs, {ID=>$id,NAME=>$name,DESCRIPTION=>$desc};
    }
  }

  # We need a list of adapter types
  my @adapter_types;
  my $adapter_type_sth = $dbh->prepare("SELECT id,name,retired FROM adapter ORDER BY retired, name");
  $adapter_type_sth->execute() or do {
    print_bug("Couldn't get list of adapter types: ".$dbh->errstr());
    return;
  };

  while (my ($id,$name,$retired) = $adapter_type_sth->fetchrow_array()) {

    if ($retired) {
      $name = "[Retired] $name";
    }

    # Adapter type can be undef if no sample type was specified
    if ($adapter_id and $id eq $adapter_id) {
      push @adapter_types, {ID=>$id,NAME=>$name, SELECTED=>1};
    }
    else {
      push @adapter_types, {ID=>$id,NAME=>$name};
    }
  }

  # We need a list of sample types
  my @sample_types;
  my $sample_type_sth = $dbh->prepare("SELECT id,name,retired FROM sample_type ORDER BY retired, name");
  $sample_type_sth->execute() or do {
    print_bug("Couldn't get list of sample types: ".$dbh->errstr());
    return;
  };

  while (my ($id,$name,$retired) = $sample_type_sth->fetchrow_array()) {

    if ($retired) {
      $name = "[Retired] $name";
    }

    # Sample type can be undef if no sample type was specified
    if ($sample_type_id and $id eq $sample_type_id) {
      push @sample_types, {ID=>$id,NAME=>$name, SELECTED=>1};
    }
    else {
      push @sample_types, {ID=>$id,NAME=>$name};
    }
  }

  # We need a list of valid budget codes

  # If we're editing an existing sample then only admins get to
  # see the budget code, and they can change it to anything
  #
  # If we're making a new sample then admins get a full list of
  # all codes, and everyone else only sees the codes they can
  # use.  If they don't have a valid code then we don't put
  # anything up for them to select from.

  my $show_budget_codes = 1;

  # If we're an admin we get all codes, otherwise get the ones this person is allowed to see
  my @budget_codes;
  if ($session->param("is_admin")) {
      @budget_codes = get_valid_budget_list();
  }
  else {
      @budget_codes = get_valid_budget_list($person_id,$sample_id);
  }

  # See if any of the codes here matches the one in the database
  foreach my $code (@budget_codes) {
      if ($code->{CODE} eq $budget_code) {
	  $code->{SELECTED} = 1;
      }
  }
      
  if (@budget_codes) {
      $template->param(BUDGET_CODES => \@budget_codes);
  }
  else {
      $show_budget_codes = 0;
  }



  $template->param(SHOW_BUDGET_CODES => $show_budget_codes);




  # And a list of databases
  my @databases = ({ID=>0,SPECIES=>'[No mapping]'});
  my $db_sth = $dbh->prepare("SELECT id,species,assembly FROM search_database ORDER BY species,assembly DESC");
  $db_sth->execute() or do {
    print_bug("Couldn't get list of search databases: ".$dbh->errstr());
    return;
  };

  while (my ($id,$species,$assembly) = $db_sth->fetchrow_array()) {
    # SearchID can be undef if no search was specified
    if ($search_id and $id eq $search_id) {
      push @databases, {ID=>$id,SPECIES=>$species,ASSEMBLY=>$assembly,SELECTED=>1};
    }
    else {
      push @databases, {ID=>$id,SPECIES=>$species,ASSEMBLY=>$assembly};
    }
  }

  # If we're an admin we can also select which user to associate this
  # sample with (if we're not then it goes to us
  if ($session->param("is_admin")) {

    my @users;
    my $db_sth = $dbh->prepare("SELECT id,first_name,last_name FROM person ORDER BY last_name,first_name DESC");
    $db_sth->execute() or do {
      print_bug("Couldn't get list of people: ".$dbh->errstr());
      return;
    };

    while (my ($id,$first,$last) = $db_sth->fetchrow_array()) {
      if ($id eq $person_id) {
	push @users, {ID=>$id,SELF => 1,USERNAME=>"$last, $first"};
      }
      else {
	push @users, {ID=>$id,USERNAME=>"$last, $first"};

      }
    }
    $template->param(USERS => \@users);

    # As an admin we can also mark a sample as a control
    $template->param(CONTROL => $is_control);

  }

  my $force_complete = 0;

  $force_complete = 1 if ($sample_id and $is_complete and $lanes_requested < $lanes_run);


  $template -> param(SAMPLE_ID => $sample_id,
		     USER_SAMPLE_ID => $user_sample_name,
		     LANES_REQUESTED => $lanes_requested,
		     RUNTYPES => \@runs,
		     ADAPTERS => \@adapter_types,
		     SAMPLE_TYPES => \@sample_types,
		     DATABASES => \@databases,
		    );


  print $session->header();
  print $template -> output();

}

sub finish_edit_sample {

  my $sample_id = $q->param("sample_id");

  # If we don't have a sample id then we're making a new sample

  my $lanes_run = 0;

  my ($person_id,$original_lanes_requested,$original_is_complete);

  if ($sample_id) {
    unless ($sample_id =~ /^\d+$/) {
      print_bug("Expected a sample id but got '$sample_id'");
      return;
    }

    # We can now get some of the details for this sample
    ($person_id,$original_lanes_requested,$original_is_complete) = $dbh->selectrow_array("SELECT sample.person_id,sample.lanes_required,sample.is_complete FROM sample WHERE sample.id=?",undef,($sample_id));


    unless ($person_id) {
      print_bug("Couldn't fetch details for sample '$sample_id':".$dbh->errstr());
      return;
    }

    # We need to check that this person can view this sample
    unless (check_sample_edit_permission($sample_id,$session->param("person_id"))) {
      print_bug("You do not have permission to edit this sample.  Sorry.");
      return;
    }

    # We need to know how many lanes have already been run for this sample
    ($lanes_run) = $dbh->selectrow_array("SELECT count(*) FROM lane WHERE sample_id=?",undef,($sample_id));

    unless (defined $lanes_run) {
      print_bug("Couldn't get lanes run count for sample $sample_id:".$dbh->errstr());
      return;
    }
  }

  else {
    # We give the new sample the current user as an owner by default
    $person_id = $session->param("person_id");
  }

  # Now we can collect the new sample details

  my $sample_name = $q->param("name");

  unless ($sample_name) {
    print_error("No sample name was supplied");
    return;
  }

  my $lanes_required = $q->param("lanes_required");

  unless ($lanes_required) {
    # We default to 1.  Users now can't specify the number of required
    # lanes so they'll always get 1.
    $lanes_required = 1;
  }

  if ($lanes_required !~ /^\d+$/ or $lanes_required > 20 or $lanes_required < $lanes_run) {
    print_error("Lanes required must be a number between $lanes_run and 20");
    return;
  }

  # Database
  my $db_id=$q->param("database");

  if (defined $db_id) {
    unless ($db_id =~ /^\d+$/) {
      print_bug("Database id must be a number, not $db_id");
      return;
    }
  }
  else {
    $db_id = undef;
  }


  # Sample type
  my $sample_type_id=$q->param("sample_type");

  if (defined $sample_type_id) {
    unless ($sample_type_id =~ /^\d+$/) {
      print_bug("Sample type id must be a number, not $sample_type_id");
      return;
    }
  }
  else {
    $sample_type_id = undef;
  }

  # Run type
  my $run_type;
  unless ($lanes_run) {
    $run_type = $q->param("type");
    unless ($run_type and $run_type =~ /^\d+$/) {
      print_bug("Run type id must be a number, not $db_id");
      return;
    }
  }

  # Adapter type
  my $adapter_id=$q->param("adapter");

  if ($adapter_id) {
    unless ($adapter_id =~ /^\d+$/) {
      print_bug("Adapter id must be a number, not $adapter_id");
      return;
    }
  }
  else {
    $adapter_id = undef;
  }



  # If we're an admin we can also select which user to associate this
  # sample with

  my $new_person_id = $person_id;
  my $is_control = 0;

  if ($session->param("is_admin")) {
    $new_person_id = $q->param("user");

    if ($q->param("control")) {
	$is_control = 1;
    }

  }

  unless ($new_person_id and $new_person_id =~ /^\d+$/) {
    print_bug("Person id must be a number, not $db_id");
    return;
  }

  # Budget code
  my $budget_code = $q->param('budget');

  # If this is a normal user we need to validate that
  # they're allowed to use this code
  if ($budget_code and (! $session->param("is_admin"))) {

    # TODO: We need to think how to do this.  Because a code
    # isn't valid now, doesn't mean it wasn't valid when the
    # sample was first submitted since the budget database can
    # change over time.  For the moment we'll not validate this
    # but we might need to come back to this.
  }


  my @barcodes;

  # If we're making a new sample they might have supplied a
  # file of barcodes

  if ($q->param("barcode_file")) {

    my $fh = $q->upload("barcode_file");

    my %seen_barcodes;
    my %seen_names;

    my $empty_barcode_number = 1;

    my $all_text;
    while (<$fh>) {
      $all_text .= $_;
    }

    my @lines = split(/[\r\n]+/,$all_text);

    # This is going to record the lengths of the codes for
    # the first barcode we see so we can check that the
    # rest all have the same characteristics
    my $first_barcode;

    foreach (@lines) {

      next unless ($_);

      my ($desc,$barcode5,$barcode3) = split(/\t/);

      unless($desc) {
	  $desc = "Barcode-$empty_barcode_number";
	  ++$empty_barcode_number;
      }

      $barcode3 = '' unless ($barcode3);

      $barcode5 = uc($barcode5);
      $barcode3 = uc($barcode3);

      unless ($barcode5 or $barcode3) {
	print_error("No barcode supplied for sample '$desc'");
	return;
      }

      if ($barcode5 and $barcode5 !~ /^[GATC\:]+$/) {
	# Try to look up the barcode as an alias
	$barcode5 = get_barcode_for_alias($barcode5);
      }

      if ($barcode3 and $barcode3 !~ /^[GATC\:]+$/) {
	# Try to look up the barcode as an alias
	$barcode3 = get_barcode_for_alias($barcode3);
      }

      if ($barcode3 and ! $barcode5) {
	print_error("You can't have just a Second barcode without a First one");
	return;

      }

      if ("$barcode5$barcode3" =~ /([^GATC\:]+)/) {
	unless ($session->param("is_admin")) { # Admins can enter non GATC barcodes
	  print_error("Non GATC sequences ('$1') in barcode for $desc");
	  return;
	}
      }

      if ($first_barcode) {
	if (length($barcode5) != $first_barcode->[0]) {
	  print_error("First barcodes didn't all have the same length");
	  return;
	}
	if (length($barcode3) != $first_barcode->[1]) {
	  print_error("Second barcodes didn't all have the same length");
	  return;
	}
	
      }
      else {
	$first_barcode = [length($barcode5),length($barcode3)];
      }

      if (exists $seen_barcodes{"$barcode5:$barcode3"}) {
	print_error("Duplicate barcode $barcode5:$barcode3 supplied");
	return;
      }

      if (exists $seen_names{$desc}) {
	  print_error("Duplicate barcode name '$desc' supplied");
	  return;
      }

      $seen_barcodes{"$barcode5:$barcode3"} = 1;
      $seen_names{$desc} = 1;

      push @barcodes,{description => $desc,
		      '5prime' => $barcode5,
		      '3prime' => $barcode3,
		     };

    }

  }



  # Now we can figure out if this sample need to be flagged complete

  # If the force complete flag is set then we're going to be complete
  if ($q->param("force_complete")) {

    # Throw an error if they've tried to change the number of lanes
    # as well
    if ($lanes_required != $original_lanes_requested) {
      print_error("It doesn't make sense to change the number of requested lanes and force the sample to be complete - do one or the other, not both");
      return;
    }

    $original_is_complete = 1;
  }

  elsif ($lanes_required == $lanes_run) {
    $original_is_complete = 1
  }
  else {
    $original_is_complete = 0;
  }

  # Now we can go ahead and make the changes to the sample

  my $made_new_sample = 0;

  if ($sample_id) {

    $dbh->do("UPDATE sample set person_id=?,users_sample_name=?,sample_type_id=?,lanes_required=?,adapter_id=?,budget_code=?,search_database_id=?,is_complete=?,is_suitable_control=? WHERE id=?",undef,($new_person_id,$sample_name,$sample_type_id,$lanes_required,$adapter_id,$budget_code,$db_id,$original_is_complete,$is_control,$sample_id)) or do {
      print_bug("Couldn't update sample details: ".$dbh->errstr());
      return;
    };
  }

  else {
    $made_new_sample = 1;

    $dbh->do("INSERT INTO sample (person_id,users_sample_name,sample_type_id,lanes_required,adapter_id,budget_code,search_database_id,is_complete,is_suitable_control,submitted_date) VALUES (?,?,?,?,?,?,?,0,?,NOW())",undef,($new_person_id,$sample_name,$sample_type_id,$lanes_required,$adapter_id,$budget_code,$db_id,$is_control)) or do {
      print_bug("Couldn't create sample: ".$dbh->errstr());
      return;
    };
    # Get the new sample id
    ($sample_id) = $dbh->selectrow_array("SELECT LAST_INSERT_ID()");
    unless ($sample_id) {
      print_bug("Couldn't get the id for newly created sample: ".$dbh->errstr());
      return;
    }

    # Add an explanatory note if the sample was added by an admin
    if ($new_person_id != $session->param("person_id")) {
      $dbh->do("INSERT into sample_note (sample_id,person_id,date,note) VALUES (?,?,NOW(),?)",undef,($sample_id,$session->param("person_id"),"Sample created by Admin ".$session->param("first_name")." ".$session->param("last_name"))) or do {
	print_bug("Couldn't insert sample note: ".$dbh->errstr());
	return;
      };
    }

    # If the sample is a control then it doesn't need to be received and we can flag it as
    # received immediately
    if ($is_control) {
	$dbh->do("UPDATE sample set received_date=NOW(),received_by_person_id=? WHERE id=?",undef,($session->param("person_id"),$sample_id)) or do {
	    print_bug("Failed to set received date on control sample: ".$dbh->errstr());
	    return;
	};
    }

  }

  # If they've changed the run type then we update that separately
  if ($run_type) {
    $dbh->do("UPDATE sample set run_type_id=? WHERE id=?",undef,($run_type,$sample_id)) or do {
      print_bug("Couldn't update sample details: ".$dbh->errstr());
      return;
    };
  }

  # If they supplied a barcode file then wipe out any existing barcodes
  # and use these instead
  if (@barcodes) {
    $dbh->do("DELETE FROM barcode WHERE sample_id=?",undef,($sample_id)) or do {
      print_bug("Failed to delete any existing barcodes for sample $sample_id:".$dbh->errstr());
      return;
    };

    foreach my $barcode (@barcodes) {
      $dbh->do("INSERT INTO barcode (sample_id,5_prime_barcode, 3_prime_barcode,name) VALUES (?,?,?,?)",undef,($sample_id,$barcode->{'5prime'},$barcode->{'3prime'},$barcode->{description})) or do {
	print_bug("Error inserting new barcode: ".$dbh->errstr());
	return;
      }
    }
  }

  # Finally add a note to the sample if they supplied any text
  my $note_text = $q->param("note");

  if ($note_text) {
    $dbh->do("INSERT into sample_note (sample_id,person_id,date,note) VALUES (?,?,NOW(),?)",undef,($sample_id,$session->param("person_id"),$note_text)) or do {
      print_bug("Couldn't insert sample note: ".$dbh->errstr());
      return;
    };
  }

  # If they've created a new sample then we send them to make another
  # one with the same settings
  if ($made_new_sample) {
    print $q->redirect("sierra.pl?action=edit_sample&last_sample_id=$sample_id&sample_type=$sample_type_id&lanes_required=$lanes_required&run_type_id=$run_type&database_id=$db_id&person_id=$new_person_id&adapter=$adapter_id&budget=$budget_code");
  }

  # Otherwise we send them back to look at the details for the sample
  # they just edited
  else {
    print $q->redirect("sierra.pl?action=view_sample&sample_id=$sample_id");
  }

}

sub add_note {

  my $sample_id = $q -> param("sample_id");
  unless ($sample_id and $sample_id =~ /^\d+$/) {
    print_bug ("'$sample_id' didn't look like a real sample ID when adding a note");
    return;
  }

  # Check that this is a real sample
  my ($returned_id) = $dbh->selectrow_array("SELECT id FROM sample WHERE id=?",undef,($sample_id));
  unless($returned_id) {
    print_bug("Couldn't find a sample with id '$sample_id'");
    return;
  }

  # We need to check that this person can view this sample
  unless (check_sample_view_permission($sample_id,$session->param("person_id"))) {
    print_bug("You do not have persmission to view this sample.  Sorry.");
    return;
  }

  # See if they attached a file
  my $filename = $q->param('attachment');

  # If there is a filename then we'll retrieve the data and
  # save it under the appropriate sample folder.
  if ($filename) {
      unless ($filename =~ /^[\w\-._ ]+$/) {
	  print_error("Uploaded filenames can only contain numbers, letters dashes underscores spaces and dots");
	  return;
      }

      # To make sure we have unique filenames we prepend the current
      # timestamp to the name.

      $filename = time()."_".$filename;

      # Check to see if there's a folder for this sample already
      my $folder_to_save_to = $Sierra::Constants::FILES_DIR . "/Sample$sample_id";

      unless (-e $folder_to_save_to) {
	  mkdir($folder_to_save_to) or do {
	      print_bug("Couldn't create '$folder_to_save_to': $!");
	      return();
	  };
      }

      my $fh = $q -> upload('attachment');

      binmode($fh);

      open (ATT, ">","${folder_to_save_to}/${filename}") or do {
	  print_bug("Couldn't save to '${folder_to_save_to}/${filename}': $!");
	  return;
      };

      binmode(ATT);
      
      print ATT while (<$fh>);

      close ATT or do {
	  print_bug("Couldn't write to '${folder_to_save_to}/${filename}': $!");
	  return;
      };

  }
  else {
      $filename = undef;
  }


  my $note_text = $q->param("note");
  if ($note_text) {

    # We can now create a note
    $dbh->do("INSERT INTO sample_note (sample_id,person_id,date,note,filename) values (?,?,NOW(),?,?)",undef,($sample_id,$session->param("person_id"),$note_text,$filename)) or do {
      print_bug("Couldn't insert note into sample: ".$dbh->errstr());
      return;
    }
  }

  # Now we can redirect them to the newly created note
  print $q->redirect("sierra.pl?action=view_sample&sample_id=$sample_id#notes");
}

sub receive_sample {

  my $sample_id = $q -> param("sample_id");
  unless ($sample_id and $sample_id =~ /^\d+$/) {
    print_bug ("'$sample_id' didn't look like a real sample ID when adding a note");
    return;
  }

  # Check that this is a real sample
  my ($returned_id) = $dbh->selectrow_array("SELECT id FROM sample WHERE id=?",undef,($sample_id));
  unless($returned_id) {
    print_bug("Couldn't find a sample with id '$sample_id'");
    return;
  }

  # Check the user is an admin (they need to be to do this)
  unless ($session->param("is_admin")) {
    print_bug("Only admins can receive samples,  Sorry.");
    return;
  }

  # Mark the sample as received
  $dbh->do("UPDATE sample SET received_date=NOW(),received_by_person_id=? WHERE id=?",undef,($session->param("person_id"),$sample_id)) or do {
    print_bug("Can't flag sample '$sample_id' as received: ".$dbh->errstr());
    return;
  };



  # Now we can redraw the home screen
  print $q->redirect("sierra.pl?action=show_queue");
}

sub pass_qc_sample {

  my $sample_id = $q -> param("sample_id");
  unless ($sample_id and $sample_id =~ /^\d+$/) {
    print_bug ("'$sample_id' didn't look like a real sample ID when adding a note");
    return;
  }

  # Check that this is a real sample
  my ($returned_id) = $dbh->selectrow_array("SELECT id FROM sample WHERE id=?",undef,($sample_id));
  unless($returned_id) {
    print_bug("Couldn't find a sample with id '$sample_id'");
    return;
  }

  # Check the user is an admin (they need to be to do this)
  unless ($session->param("is_admin")) {
    print_bug("Only admins can receive samples,  Sorry.");
    return;
  }

  # Check that the sample has been received
  my ($received_date) = $dbh->selectrow_array("SELECT received_date FROM sample WHERE id=?",undef,($sample_id));
  unless ($received_date) {
    print_bug("Tried to pass QC on a sample ('$sample_id') which hasn't been received");
    return;
  }

  # Mark the sample as passing QC
  $dbh->do("UPDATE sample SET passed_qc_date=NOW() WHERE id=?",undef,($sample_id)) or do {
    print_bug("Can't flag sample '$sample_id' as passing qc: ".$dbh->errstr());
    return;
  };


  # Now we can redraw the home screen
  print $q->redirect("sierra.pl?action=show_queue");
}

sub remove_sample {

  unless ($session -> param("is_admin")) {
    print_bug("Only admins can view this page and you don't appear to be one");
    return;
  }

  my $lane_id = $q->param("lane_id");
  if (! $lane_id or $lane_id !~ /^\d+$/) {
    print_bug("Lane id '$lane_id' didn't look right when removing sample");
    return;
  }

  # Get the flowcell associated with this lane id so we know
  # where to redirect people later.

  my ($flowcell_id,$sample_id) = $dbh->selectrow_array("SELECT flowcell_id,sample_id FROM lane WHERE id=?",undef,($lane_id));

  unless ($flowcell_id) {
    print_bug("Couldn't find a flowcell associated with lane $lane_id");
    return;
  }

  # Check that this flowcell doesn't already have a run associated with
  # it (since we can't change it if it has)

  my ($run_id) = $dbh->selectrow_array("SELECT id FROM run WHERE flowcell_id=?",undef,($flowcell_id));

  if ($run_id) {
    print_bug("Can't delete lane as flowcell has already been run (with run id $run_id)");
    return;
  }

  # OK we're good to delete the lane
  $dbh->do("DELETE FROM lane WHERE id=?",undef,($lane_id)) or do {
    print_bug("Failed to delete lane $lane_id ".$dbh->errstr());
    return;
  };

  # We also need to remove the is_complete flag if it was set on this sample
  $dbh->do("UPDATE sample SET is_complete=0 where id=?",undef,($sample_id)) or do {
    print_bug("Failed to remove is_complete flag from sample $sample_id ".$dbh->errstr());
    return;
  };

  # Redirect them back to the flowcell editor
  print $q->redirect("sierra.pl?action=new_flowcell&flowcell_id=$flowcell_id");

}

sub new_flowcell {

  unless ($session -> param("is_admin")) {
    print_bug("Only admins can view this page and you don't appear to be one");
    return;
  }

  my $template = HTML::Template -> new (filename=>'flowcell.html',associate => $session);

  my $flowcell_id = $q->param("flowcell_id");

  if ($flowcell_id) {

    # We need to print out the status of the current flowcell
    $template->param(FLOWCELL_ID => $flowcell_id);

    # See if this flowcell has already been run
    my ($run_id,$run_date,$run_folder,$flowcell_serial,$instrument_serial,$instrument_name) = $dbh->selectrow_array("SELECT run.id,DATE_FORMAT(run.date,'%e %b %Y'),run.run_folder_name,flowcell.serial_number,instrument.serial_number,instrument.description FROM run,flowcell,instrument WHERE run.flowcell_id=? AND run.flowcell_id=flowcell.id AND run.instrument_id=instrument.id",undef,($flowcell_id));

    if ($run_id) {
      $template->param(RUN_ID => $run_id,
		       RUN_DATE => $run_date,
		       RUN_FOLDER => $run_folder,
		       MACHINE => "$instrument_serial ($instrument_name)",
		       FLOWCELL_SERIAL => $flowcell_serial,
		      );
    }


    # Get the details for the lanes which have already been added.
    my @lanes;
    my @free_lanes;

    my ($lane_count,$run_type_id,$run_type) = $dbh->selectrow_array("SELECT flowcell.available_lanes, run_type.id, run_type.name FROM flowcell,run_type WHERE flowcell.id=? AND flowcell.run_type_id=run_type.id",undef,($flowcell_id));
    unless ($lane_count) {
      print_bug("Couldn't get lane count for flowcell '$flowcell_id': ".$dbh->errstr());
      return;
    }

    $template->param(RUN_TYPE=>$run_type);


    my $get_lane_details_sth = $dbh->prepare("SELECT lane.id,sample.id,lane.use_as_control,sample.users_sample_name,sample.search_database_id,sample.sample_type_id,person.first_name,person.last_name FROM lane,sample,person WHERE lane.sample_id=sample.id AND sample.person_id=person.id AND lane.flowcell_id=? AND lane.lane_number=?");

    for my $lane_number (1..$lane_count) {

      $get_lane_details_sth -> execute($flowcell_id,$lane_number) or do {
	print_bug("Couldn't get details for lane $lane_number on flowcell $flowcell_id: ".$dbh->errstr());
	return;
      };

      my ($lane_id,$sample_id,$control,$sample_name,$search_db_id,$sample_type_id,$first,$last) = $get_lane_details_sth ->fetchrow_array();

      my $sample_type = '[Unknown]';

      if ($sample_type_id) {
	($sample_type) = $dbh->selectrow_array("SELECT name FROM sample_type WHERE id=?",undef,($sample_type_id));
      }

      my $search_db = '[Unknown]';

      if ($search_db_id) {
	my($species, $assembly) = $dbh->selectrow_array("SELECT species,assembly FROM search_database WHERE id=?",undef,($search_db_id));
	$search_db = "$species $assembly";
      }

      # Get the number of barcodes for this sample
      my ($barcode_count) = $dbh->selectrow_array("SELECT count(*) FROM barcode WHERE sample_id=?",undef,($sample_id));

      push @lanes, {
		    LANE => $lane_number,
		    LANE_ID => $lane_id,
		    SAMPLE_ID => $sample_id,
		    BARCODES => $barcode_count,
		    SAMPLE_NAME => $sample_name,
		    SAMPLE_TYPE => $sample_type,
		    SEARCH_DB => $search_db,
		    IS_CONTROL => $control,
		    OWNER => "$first $last",
		    RUN_ID => $run_id,
      };

      unless ($sample_id) {
	push @free_lanes, {
			   LANE_NUMBER => $lane_number,
			  };
      }

    }

    $template -> param(LANES => \@lanes,
		       FREE_LANES => scalar @free_lanes);

    # We also need to list the samples which could potentially be added to this
    # flowcell

    my @controls;
    my $available_controls_sth = $dbh->prepare("SELECT id,users_sample_name FROM sample WHERE sample.is_suitable_control = 1 ");
    $available_controls_sth -> execute() or do {
      print_bug("Failed to list available controls: ".$dbh->errstr());
      return;
    };
    while (my ($sample_id,$sample_name) = $available_controls_sth->fetchrow_array()) {
      push @controls,{SAMPLE_ID => $sample_id,
		      NAME=> $sample_name,
		      FLOWCELL_ID=>$flowcell_id,
		      FREE_LANES => \@free_lanes};
    }

    $template -> param("AVAILABLE_CONTROLS" => \@controls);

    my @available_samples;

    my $available_samples_sth = $dbh->prepare("SELECT sample.id,sample.users_sample_name,person.first_name,person.last_name,DATE_FORMAT(passed_qc_date,'%e %b %Y'),sample.lanes_required FROM sample,person WHERE sample.is_complete != 1 AND sample.passed_qc_date IS NOT NULL AND sample.run_type_id=? AND sample.person_id=person.id");

    my $count_used_lanes_sth = $dbh->prepare("SELECT COUNT(*) FROM lane WHERE sample_id=?");

    $available_samples_sth -> execute($run_type_id) or do {
      print_bug("Failed to list available samples: ".$dbh->errstr());
      return;
    };

    while (my ($sample_id,$name,$first,$last,$passed_qc,$requested) = $available_samples_sth->fetchrow_array()) {

      $count_used_lanes_sth -> execute($sample_id) or do {
	print_bug("Couldn't count lanes used by sample '$sample_id': ".$dbh->errstr());
	return;
      };

      my ($lanes_run) = $count_used_lanes_sth->fetchrow_array();

      push @available_samples, {
				SAMPLE_ID => $sample_id,
				NAME => $name,
				OWNER => "$first $last",
				PASSED_QC => $passed_qc,
				LANES_REQUESTED => $requested,
				FREE_LANES => \@free_lanes,
				LANES_RUN => $lanes_run,
				FLOWCELL_ID => $flowcell_id,
			       };
    }



    $template -> param(AVAILABLE_SAMPLES => \@available_samples);


  }

  else {
    # We're either making a new flowcell or starting from scratch
    my $serial = $q->param("serial");
    my $run_type = $q->param("run_type");

    if ($serial or $run_type) {

      # We're trying to make a new flowcell

      unless ($run_type) {
	print_error("No run type was selected");
	return;
      }
      unless ($serial) {
	print_error("No flowcell serial number was entered");
	return;
      }

      # We should check the run type is valid.  We can kill two birds with
      # one stone by finding the number of lanes we need.
      my ($lanes) = $dbh->selectrow_array("SELECT lanes from run_type WHERE id=?",undef,($run_type));
      unless ($lanes) {
	print_bug("Couldn't find a run type of '$run_type' in the database");
	return;
      }

      # Check that this serial number hasn't already been used
      my ($existing_flowcell_id) = $dbh->selectrow_array("SELECT id FROM flowcell WHERE serial_number=?",undef,($serial));
      if ($existing_flowcell_id) {
	print_error("There already appears to be a flowcell registered with serial number '$serial'");
	return;
      }

      # OK, lets make a flowcell
      $dbh->do("INSERT INTO flowcell (serial_number,run_type_id,available_lanes) values (?,?,?)",undef,($serial,$run_type,$lanes)) or do {
	print_bug("Can't create new flowcell: ".$dbh->errstr());
	return;
      };

      # Get the id of the new flowcell
      my ($flowcell_id) = $dbh->selectrow_array("SELECT LAST_INSERT_ID()");
      unless ($flowcell_id) {
	print_bug("Can't get id of newly created flowcell: ".$dbh->errstr());
	return;
      }

      print $q->redirect("sierra.pl?action=new_flowcell&flowcell_id=$flowcell_id");
      return;

    }

    else {
      # Put out the new flowcell form
      # All we need to provide are the types of run which are available

      my @runtypes;

      my $runtypes_sth = $dbh->prepare("SELECT id,name FROM run_type");
      $runtypes_sth -> execute() or do {
	print_bug("Can't get list of run_types: ".$dbh->errstr());
	return;
      };

      my $pending_samples_sth = $dbh->prepare("SELECT id,lanes_required FROM sample WHERE run_type_id=? AND is_complete=0 AND received_date IS NOT NULL AND is_suitable_control=0 AND passed_qc_date IS NOT NULL");
      my $allocated_lanes_sth = $dbh->prepare("SELECT count(*) from lane WHERE sample_id=?");

      while (my ($id,$name) = $runtypes_sth->fetchrow_array()) {

	$pending_samples_sth -> execute($id) or do {
	  print_bug("Couldn't get list of pending samples for runttype $id:".$dbh->errstr());
	  return;
	};

	my $total_pending = 0;
	while (my ($sample_id,$required) = $pending_samples_sth->fetchrow_array()) {
	  $allocated_lanes_sth -> execute($sample_id) or do {
	    print_bug("Failed to get list of lanes for sample_id $sample_id:".$dbh->errstr());
	    return;
	  };
	  my ($used_count) = $allocated_lanes_sth->fetchrow_array();
	  $total_pending += $required-$used_count;

	}

	push @runtypes, {
			 ID => $id,
			 NAME => $name,
			 PENDING_COUNT=> $total_pending,
			} if ($total_pending > 0);
      }

      $template->param(RUN_TYPES => \@runtypes);

    }
  }

  print $session->header();
  print $template -> output();

}


sub edit_flowcell {

    # This can only ever be called for flowcells which have
    # been run already.  We don't let them change much about
    # this.  Only the flowcell ID and the run folder name.

    unless ($session -> param("is_admin")) {
	print_bug("Only admins can view this page and you don't appear to be one");
	return;
    }

    my $template = HTML::Template -> new (filename=>'edit_flowcell.html',associate => $session);

    my $flowcell_id = $q->param("flowcell_id");

    my ($id,$serial,$run_folder, $run_date) = $dbh->selectrow_array("SELECT flowcell.id, flowcell.serial_number, run.run_folder_name,run.date FROM flowcell,run WHERE flowcell.id=? AND run.flowcell_id=flowcell.id",undef,($flowcell_id));
    unless ($id) {
	print_bug("Couldn't find a run flowcell with id $flowcell_id: ".$dbh->errstr());
	return;
    }

    $template -> param (
	FLOWCELL_ID => $flowcell_id,
	SERIAL_NUMBER => $serial,
	RUN_FOLDER_NAME => $run_folder,
	);

    my ($run_year,$run_month, $run_day) = split(/-/,$run_date);


    my @days;
    for my $day (1..31) {
	if ($day == $run_day) {
	    push @days, {NAME => $day,SELECTED => 1};
	}
	else {
	    push @days, {NAME => $day};
	}
    }
    
    $template->param(DAYS => \@days);

    my @months = (
	[1,'Jan'],
	[2,'Feb'],
	[3,'Mar'],
	[4,'Apr'],
	[5,'May'],
	[6,'Jun'],
	[7,'Jul'],
	[8,'Aug'],
	[9,'Sep'],
	[10,'Oct'],
	[11,'Nov'],
	[12,'Dec'],
	);
    
    my @template_months;
    foreach my $month (@months) {
	if ($month->[0] == $run_month) {
	    push @template_months,{NUMBER=>$month->[0],NAME=>$month->[1],SELECTED=>1};
	}
	else {
	    push @template_months,{NUMBER=>$month->[0],NAME=>$month->[1]};
	}
	
    }
    $template -> param(MONTHS => \@template_months);

    my @years;

    for my $year (2009..(localtime())[5]+1900) {

	if ($year == $run_year) {
	    push @years, {YEAR => $year,SELECTED => 1};
	}
	else {
	    push @years, {YEAR => $year};
	}

    }

    $template->param(YEARS=>\@years);

  
    print $session->header();
    print $template -> output();

}

sub finish_edit_flowcell {

    unless ($session -> param("is_admin")) {
	print_bug("Only admins can view this page and you don't appear to be one");
	return;
    }

    my $flowcell_id = $q->param("flowcell_id");

    unless ($flowcell_id =~ /^\d+$/) {
	print_bug("Flowcell id should be an integer, not '$flowcell_id'");
	return;
    }

    # Get the run folder name
    my $run_folder = $q->param("run_folder");
    unless ($run_folder) {
	print_error("No run folder name was supplied");
	return;
    }

    # Get the flowcell serial number
    my $serial_number = $q->param("serial_number");
    unless ($serial_number) {
	print_error("No serial number was supplied");
	return;
    }

  # Get the date
  my $day = $q -> param("day");
  my $month = $q -> param("month");
  my $year = $q -> param("year");

  # Check if this is valid
  if (!check_date($year,$month,$day)) {
    print_error("Date $year-$month-$day doesn't appear to be a valid date");
    return;
  }

  if (Delta_Days(Today(),$year,$month,$day) > 1) {
    print_error("Your run date appears to be more than one day in the future");
    return;
  }

  my $date = sprintf("%d-%02d-%02d",$year,$month,$day);


    # We need to update the flowcell details
    $dbh->do("UPDATE flowcell SET serial_number=? WHERE id=?",undef,($serial_number,$flowcell_id)) or do {
	print_bug("Failed to update serial number for flowcell '$flowcell_id'".$dbh->errstr());
	return;
    };


    # We need to update the run details
    $dbh->do("UPDATE run SET run_folder_name=?, date=? WHERE flowcell_id=?",undef,($run_folder,$date,$flowcell_id)) or do {
	print_bug("Failed to update run folder name for flowcell '$flowcell_id'".$dbh->errstr());
	return;
    };

    print $q->redirect("sierra.pl?action=view_flowcell&flowcell_id=$flowcell_id");

}

sub delete_flowcell {

    unless ($session -> param("is_admin")) {
	print_bug("Only admins can view this page and you don't appear to be one");
	return;
    }

    my $flowcell_id = $q->param("flowcell_id");

    unless ($flowcell_id =~ /^\d+$/) {
	print_bug("Flowcell id should be an integer, not '$flowcell_id'");
	return;
    }

    # Check that this flowcell doesn't already have a run associated with
    # it (since we can't change it if it has)

    my ($run_id) = $dbh->selectrow_array("SELECT id FROM run WHERE flowcell_id=?",undef,($flowcell_id));

    if ($run_id) {
	print_bug("Can't delete this flowcell as it has has already been run (with run id $run_id)");
	return;
    }

    # We need to remove any samples which have been added as lanes
    # to this flowcell.

    my $get_lanes_sth = $dbh->prepare("SELECT id, sample_id FROM lane where flowcell_id=?");

    $get_lanes_sth -> execute($flowcell_id) or do {
	print_bug("Couldn't list samples for flowcell $flowcell_id: ".$dbh->errstr());
	return;
    };

    while (my ($lane_id,$sample_id) = $get_lanes_sth->fetchrow_array()) {
	$dbh-> do ("DELETE FROM lane WHERE id=?",undef,($lane_id)) or do {
	    print_bug("Failed to delete lane $lane_id:".$dbh->errstr());
	    return;
	};
	
	# Unset the complete flag on the sample it came from
	$dbh -> do("UPDATE sample SET is_complete=0 WHERE id=?",undef,($sample_id)) or do {
	    print_bug("Failed to reset complete flag on sample $sample_id:".$dbh->errstr());
	    return;
	};
    }

    # Now we can delete the flowcell itself
    $dbh->do("DELETE from flowcell where id=?",undef,($flowcell_id)) or do {
	print_bug("Failed to delete flowcell $flowcell_id: ".$dbh->errstr());
	return;
    };

    # Return them to the front screen where they came from
    print $q->redirect("sierra.pl#pending");

}



sub add_lane {

  # This adds a sample to a lane of a flowcell.

  unless ($session -> param("is_admin")) {
    print_bug("Only admins can view this page and you don't appear to be one");
    return;
  }

  # We should have a flowcell_id, a sample_id and a lane number
  my $flowcell_id = $q->param("flowcell_id");
  unless ($flowcell_id) {
    print_bug("No flowcell id provided when adding a sample to a lane");
    return;
  }
  my $sample_id = $q->param("sample_id");
  unless ($sample_id) {
    print_bug("No sample id provided when adding a sample to a lane");
    return;
  }
  my $lane_number = $q->param("lane");
  unless ($lane_number) {
    print_bug("No lane number provided when adding a sample to a lane");
    return;
  }

  # We need to check that this sample is suitable for this flowcell (and
  # also check the ids at the same time

  # If this is a control sample we don't need to do this, so check that
  # first.

  my ($is_control) = $dbh->selectrow_array("SELECT is_suitable_control FROM sample WHERE id=?",undef,($sample_id));

  my ($lane_count,$lanes_required); # Need to declare these, even though we only use them if this isn't a control

  if (! $is_control) {

    ($lane_count,$lanes_required) = $dbh->selectrow_array("SELECT flowcell.available_lanes,sample.lanes_required FROM flowcell,sample WHERE sample.id=? AND sample.is_complete != 1 AND flowcell.id=? AND sample.run_type_id=flowcell.run_type_id",undef,($sample_id,$flowcell_id));

    unless ($lane_count) {
      print_bug("Couldn't confirm that sample '$sample_id' is compatible with flowcell '$flowcell_id':".$dbh->errstr());
      return;
    }

    # Check that the requested lane number is possible
    unless ($lane_number =~ /^\d+$/ and $lane_number >=1 and $lane_number <= $lane_count) {
      print_bug("Lane '$lane_number' can't be on a flowcell with $lane_count lanes");
      return;
    }
  }

  # Check that there's nothing in this lane already
  my ($lane_taken) = $dbh->selectrow_array("SELECT id FROM lane WHERE flowcell_id=? AND lane_number=?",undef,($flowcell_id,$lane_number));
  if ($lane_taken) {
    print_error("There already appears to be a sample in that lane.  Refresh the page to see the current flowcell layout");
    return;
  }

  my $lanes_already_run; # Only used for non-control samples

  if (!$is_control) {
    # Check that we actually need to add some more lanes from this sample
    ($lanes_already_run) = $dbh->selectrow_array("SELECT count(*) FROM lane WHERE sample_id=?",undef,($sample_id));

    if ($lanes_already_run >= $lanes_required) {
      print_error("This sample already seems to have been completely run.  Refresh the page to update the sample counts");
      return;
    }
  }

  # If this is a control sample then check if this flowcell already
  # has a control sample on it.  If not then use this one.
  my ($control_lane_id) = $dbh->selectrow_array("SELECT id FROM lane WHERE flowcell_id=? AND use_as_control=1",undef,($flowcell_id));

  my $use_as_control = 0;

  if ($is_control and !$control_lane_id) {
    $use_as_control = 1;
  }


  # Now we can make the new lane
  $dbh->do("INSERT INTO lane (flowcell_id,sample_id,lane_number,use_as_control) values (?,?,?,?)",undef,($flowcell_id,$sample_id,$lane_number,$use_as_control)) or do {
    print_bug("Can't create new lane for sample '$sample_id' on flowcell '$flowcell_id': ".$dbh->errstr());
  };


  if (!$is_control) {
    # Finally, if this was the last lane required for this sample, mark the
    # sample as complete.

    if ($lanes_already_run+1 == $lanes_required) {
      $dbh->do("UPDATE sample SET is_complete=1 WHERE id=?",undef,($sample_id)) or do {
	print_bug("Can't flag sample '$sample_id' as complete: ".$dbh->errstr());
	return;
      }
    }
  }

  # Now send them back to the flowcell construction view.
  print $q->redirect("sierra.pl?action=new_flowcell&flowcell_id=$flowcell_id");


}

sub email_users {

  unless ($session -> param("is_admin")) {
    print_bug("Only admins can view this page and you don't appear to be one");
    return;
  }

  my $template = HTML::Template -> new (filename=>'email_users.html',associate => $session);


  my $message = $q->param("message");
  my $subject = $q->param("subject");
  my $users = $q->param("which_users");

  if ($users) {

    # We're actually going to try to send a message

    unless ($message) {
      print_error("No message text was supplied");
      return;
    }

    unless ($subject) {
      $subject = "Message from sierra admin";
    }

    $subject = "[Sierra] $subject";

    # Find the set of users we're going to send this to

    my $query;

    if ($users eq 'Users active in the last year') {
      $query = "SELECT DISTINCT person.email FROM person,sample WHERE sample.submitted_date >= NOW()-INTERVAL 365 DAY AND sample.person_id=person.id";
    }
    elsif ($users eq 'Users with samples in the queue') {
      $query = "SELECT DISTINCT person.email FROM person,sample WHERE sample.is_complete = 0 AND sample.person_id=person.id";
    }
    elsif ($users eq 'All users') {
      $query = "SELECT email FROM person";
    }

    my $sth = $dbh->prepare($query);

    $sth->execute() or do {
      print_bug("Failed to run query for email addresses ".$dbh->errstr());
      return;
    };

    my @addresses;

    while (my ($address) = $sth->fetchrow_array()) {
      push @addresses,$address;
    }

    # Now we can send the email
    send_bcc_email($subject,$message,@addresses) or do {
      print_bug("Failed to send BCC email");
      return;
    };


    print $q->redirect("sierra.pl?action=email_users&sent_count=".scalar @addresses);
    return;
  }

  $template -> param(SENT_COUNT => $q->param("sent_count"));

  print $session->header();
  print $template -> output();

}


sub configuration {

  unless ($session -> param("is_admin")) {
    print_bug("Only admins can view this page and you don't appear to be one");
    return;
  }

  my $template = HTML::Template -> new (filename=>'configuration.html',associate => $session);

  my $list_instruments_sth = $dbh->prepare("SELECT id,available,retired,description FROM instrument ORDER BY retired, available DESC, id");
  $list_instruments_sth -> execute() or do {
    print_bug("Couldn't get list of instruments: ".$dbh->errstr());
    return;
  };

  my $count_runs_sth = $dbh->prepare("SELECT count(*) FROM run_type_instrument WHERE instrument_id=?");


  my @instruments;
  while (my ($id,$available,$retired,$description) = $list_instruments_sth -> fetchrow_array()) {

    $count_runs_sth->execute($id) or do {
      print_bug("Can't count run types for instrument $id:".$dbh->errstr());
      return;
    };

    my ($run_types) = $count_runs_sth->fetchrow_array();

    push @instruments, {
			INSTRUMENT_ID => $id,
			AVAILABLE => $available,
			RETIRED => $retired,
			DESCRIPTION => $description,
			RUN_TYPES =>$run_types,
		       };
  }

  $template->param(INSTRUMENTS => \@instruments);

  # Now we list the run types
  my $list_run_types_sth = $dbh->prepare("SELECT id,name,lanes,retired FROM run_type ORDER BY retired,name");
  $list_run_types_sth -> execute() or do {
    print_bug("Couldn't get list of run_types: ".$dbh->errstr());
    return;
  };

  my $count_instruments_sth = $dbh->prepare("SELECT count(*) FROM run_type_instrument WHERE run_type_id=?");

  my @run_types;
  while (my ($id,$name,$lanes,$retired) = $list_run_types_sth -> fetchrow_array()) {

    $count_instruments_sth->execute($id) or do {
      print_bug("Can't count instruments for run_type $id:".$dbh->errstr());
      return;
    };

    my ($instruments) = $count_instruments_sth->fetchrow_array();

    push @run_types, {
			RUN_TYPE_ID => $id,
			NAME => $name,
			LANES => $lanes,
			RETIRED => $retired,
			INSTRUMENTS =>$instruments,
		       };
  }

  $template->param(RUN_TYPES => \@run_types);

  # Now we list the adapter types
  my $list_adapter_types_sth = $dbh->prepare("SELECT id,name,retired FROM adapter ORDER BY name");
  $list_adapter_types_sth -> execute() or do {
    print_bug("Couldn't get list of adapter_types: ".$dbh->errstr());
    return;
  };

  my @adapter_types;
  while (my ($id,$name,$retired) = $list_adapter_types_sth -> fetchrow_array()) {

    push @adapter_types, {
			ADAPTER_TYPE_ID => $id,
			NAME => $name,
			RETIRED => $retired,
		       };
  }

  $template->param(ADAPTER_TYPES => \@adapter_types);



  # Now we list the sample types
  my $list_sample_types_sth = $dbh->prepare("SELECT id,name,description,retired FROM sample_type ORDER BY name");
  $list_sample_types_sth -> execute() or do {
    print_bug("Couldn't get list of sample types: ".$dbh->errstr());
    return;
  };

  my @sample_types;
  while (my ($id,$name,$description,$retired) = $list_sample_types_sth -> fetchrow_array()) {

    push @sample_types, {
			 SAMPLE_TYPE_ID => $id,
			 NAME => $name,
			 DESCRIPTION => $description,
			 RETIRED => $retired,
			};
  }

  $template->param(SAMPLE_TYPES => \@sample_types);


  # Now we list search databases
  my $list_databases_sth = $dbh->prepare("SELECT id,species,assembly,folder FROM search_database ORDER BY species,assembly");
  $list_databases_sth -> execute() or do {
    print_bug("Couldn't get list of databases: ".$dbh->errstr());
    return;
  };

  my @databases;
  while (my ($id,$species,$assembly,$folder) = $list_databases_sth -> fetchrow_array()) {

    push @databases, {
			 DATABASE_ID => $id,
			 SPECIES => $species,
			 ASSEMBLY => $assembly,
			 FOLDER => $folder,
			};
  }

  $template->param(DATABASES => \@databases);


  print $session->header();
  print $template -> output();

}

sub reports {

  unless ($session -> param("is_admin")) {
    print_bug("Only admins can view this page and you don't appear to be one");
    return;
  }


  my $template = HTML::Template -> new (filename=>'reports.html',associate => $session);

  # See if we got any parameters passed to us
  my $report_type = $q->param("report_type");
  my $from_month = $q->param("from_month");
  my $to_month = $q->param("to_month");
  my $from_year = $q->param("from_year");
  my $to_year = $q->param("to_year");

  # Set the report type

  my @report_types;

  foreach my $type (qw(Usage Runs Instruments)) {
    if ($type eq $report_type) {
      push @report_types, {TYPE=>$type, SELECTED=>1};
    }
    else {
      push @report_types, {TYPE=>$type};
    }
  }

  $template ->param(REPORT_TYPES => \@report_types);


  # Validate the months/years
  my $invalid = 0;
  if ($report_type) {
    # All other parameters should be present
    unless ($from_month =~ /^\d+$/ and $from_month >=1 and $from_month <=12) {
      $invalid = 1;
    }
    unless ($to_month =~ /^\d+$/ and $to_month >=1 and $to_month <=12) {
      $invalid = 1;
    }
    unless ($from_year =~ /^\d+$/ and $from_year >=2009 and $from_year <=((localtime())[5]+1900)) {
      $invalid = 1;
    }
    unless ($to_year =~ /^\d+$/ and $to_year >=2009 and $to_year <=((localtime())[5]+1900)) {
      $invalid = 1;
    }

    if ($invalid) {
      print_bug("Invalid date range $from_month:$from_year - $to_month:$to_year");
      return;
    }

  }
  else {
    $from_month = (localtime())[4]+1;
    $to_month = $from_month;
    $from_year = (localtime())[5]+1900;
    $to_year = $from_year;
  }


  # Get a list of months
  my @from_months = (
		     {NUMBER => 1,
		      NAME => 'Jan'},
		     {NUMBER => 2,
		      NAME => 'Feb'},
		     {NUMBER => 3,
		      NAME => 'Mar'},
		     {NUMBER => 4,
		      NAME => 'Apr'},
		     {NUMBER => 5,
		      NAME => 'May'},
		     {NUMBER => 6,
		      NAME => 'Jun'},
		     {NUMBER => 7,
		      NAME => 'Jul'},
		     {NUMBER => 8,
		      NAME => 'Aug'},
		     {NUMBER => 9,
		      NAME => 'Sep'},
		     {NUMBER => 10,
		      NAME => 'Oct'},
		     {NUMBER => 11,
		      NAME => 'Nov'},
		     {NUMBER => 12,
		      NAME => 'Dec'},
		    );

  # Set the selected month
  $from_months[$from_month - 1]->{SELECTED} = 1;

  my @to_months = (
		   {NUMBER => 1,
		    NAME => 'Jan'},
		   {NUMBER => 2,
		    NAME => 'Feb'},
		   {NUMBER => 3,
		    NAME => 'Mar'},
		   {NUMBER => 4,
		    NAME => 'Apr'},
		   {NUMBER => 5,
		    NAME => 'May'},
		   {NUMBER => 6,
		    NAME => 'Jun'},
		   {NUMBER => 7,
		    NAME => 'Jul'},
		   {NUMBER => 8,
		    NAME => 'Aug'},
		   {NUMBER => 9,
		    NAME => 'Sep'},
		   {NUMBER => 10,
		    NAME => 'Oct'},
		   {NUMBER => 11,
		    NAME => 'Nov'},
		   {NUMBER => 12,
		    NAME => 'Dec'},
		  );

  # Set the selected month
  $to_months[$to_month - 1]->{SELECTED} = 1;


  # Do all years from 2009 onwards
  my @from_years;
  my @to_years;
  foreach my $year (2009..((localtime())[5]+1900)) {
    if ($year == $from_year) {
      push @from_years,{YEAR => $year,SELECTED => 1};
    }
    else {
      push @from_years,{YEAR => $year};
    }
    if ($year == $to_year) {
      push @to_years,{YEAR => $year,SELECTED => 1};
    }
    else {
      push @to_years,{YEAR => $year};
    }
  }


  $template->param(FROM_MONTHS => \@from_months,
		   FROM_YEARS => \@from_years,
		   TO_MONTHS => \@to_months,
		   TO_YEARS => \@to_years);



  # See if we need to create a report.
  if ($report_type) {

    my @headers;
    my @rows;

    if ($report_type eq 'Usage') {

     @headers = (
		 {NAME=>'Sample'},
		 {NAME =>'Run Type'},
		 {NAME => 'Lanes'},
		 {NAME => 'Date'},
		 {NAME => 'Name'},
		 {NAME => 'Email'},
		 {NAME => 'Budget'},
		);


     # First get a list of all of the lanes run in this period.
     my $report_sth = $dbh->prepare("SELECT sample.id,sample.users_sample_name,run_type.name,DATE_FORMAT(run.date,'%e %b %Y'),person.first_name,person.last_name, person.email,sample.budget_code FROM run,flowcell,lane,sample,run_type,person WHERE run.date>= ? AND run.date < ? AND run.flowcell_id=flowcell.id AND flowcell.run_type_id=run_type.id AND flowcell.id=lane.flowcell_id AND lane.sample_id=sample.id AND sample.person_id=person.id ORDER BY sample.id,run.date");

     $report_sth -> execute("${from_year}-${from_month}-01","${to_year}-${to_month}-31") or do {
       print_bug("Failed to run usage search: ".$dbh->errstr());
       return;
     };


     my $last_entry;

     while (my ($sample_id,$sample_name,$run_type,$date,$first_name,$last_name,$email,$budget) = $report_sth->fetchrow_array) {

       next if ($sample_id == 1);
       next if ($sample_name =~ /phix/i);
       next if ($sample_name =~ /empty lane/i);

       if ($last_entry and $last_entry ->{SAMPLE_ID} == $sample_id) {
	 ++$last_entry->{ROW}->[2]->{VALUE}; # Increment the number of lanes
	 $last_entry ->{ROW}->[3]->{VALUE} = $date; # Set the date to the more recent date
	 next;
       }
       else {
	 push @rows,{ROW => $last_entry->{ROW}} if ($last_entry);
       }

       $last_entry = {
		      SAMPLE_ID => $sample_id,
		      ROW => [],
		     };

       foreach ("Sample $sample_id ($sample_name)",$run_type,1,$date,"$first_name $last_name",$email,$budget) {
	 push @{$last_entry->{ROW}},{VALUE => $_};
       }

     }

     if ($last_entry) {
       push @rows,{ROW => $last_entry->{ROW}};
     }


    }

    elsif ($report_type eq 'Runs') {
           @headers = (
		 {NAME=>'Run Type'},
		 {NAME =>'Count'},
		);


     # Get a list of all of the runs in this period.
     my $report_sth = $dbh->prepare("select run_type.name,count(run_type.id) from run,flowcell,run_type WHERE run.date >= ? AND run.date < ? and run.flowcell_id=flowcell.id AND flowcell.run_type_id=run_type.id GROUP BY run_type.id");

     $report_sth -> execute("${from_year}-${from_month}-01","${to_year}-${to_month}-31") or do {
       print_bug("Failed to run run search: ".$dbh->errstr());
       return;
     };

     while (my ($run_type,$count) = $report_sth->fetchrow_array) {

       push @rows,{ROW => [{VALUE=>$run_type},{VALUE=>$count}]};
     }


    }


    elsif ($report_type eq 'Instruments') {
           @headers = (
		       {NAME=>'Instrument ID'},
		       {NAME=>'Instrument Name'},
		       {NAME =>'Count'},
		      );


     # Get a list of all of the runs per instrument in this period.
     my $report_sth = $dbh->prepare("select instrument.id,instrument.description,count(instrument.id) from run,instrument WHERE run.date >= ? AND run.date < ? and run.instrument_id=instrument.id GROUP BY instrument.id;");

     $report_sth -> execute("${from_year}-${from_month}-01","${to_year}-${to_month}-31") or do {
       print_bug("Failed to run run search: ".$dbh->errstr());
       return;
     };

     while (my ($instrument_id,$instrument_name,$count) = $report_sth->fetchrow_array) {

       push @rows,{ROW => [{VALUE=>$instrument_id},{VALUE=>$instrument_name},{VALUE=>$count}]};
     }


    }

    else {
      print_bug("Unknown report type '$report_type'");
      return;
    }

    $template ->param(HEADERS => \@headers,
		      ROWS => \@rows
		     );

  }


  print $session->header();
  print $template -> output();

}

sub edit_instrument {

  unless ($session -> param("is_admin")) {
    print_bug("Only admins can view this page and you don't appear to be one");
    return;
  }

  my $template = HTML::Template -> new (filename=>'edit_instrument.html',associate => $session);

  my %matched_run_ids;

  my $instrument_id = $q->param("instrument_id");

  if ($instrument_id) {
    my ($id,$serial,$description,$retired) = $dbh->selectrow_array("SELECT id,serial_number,description,retired FROM instrument WHERE id=?",undef,($instrument_id));
    unless ($id) {
      print_bug("Couldn't find an instrument with id $instrument_id".$dbh->errstr());
      return;
    }

    $template -> param (
			INSTRUMENT_ID => $instrument_id,
			SERIAL => $serial,
			DESCRIPTION => $description,
			RETIRED => $retired,
		       );


    # We also need a list of run types for this instrument
    my $run_types_sth = $dbh->prepare("SELECT run_type_id FROM run_type_instrument WHERE instrument_id=?");
    $run_types_sth -> execute($instrument_id) or do {
      print_bug("Couldn't list run types for instrument $instrument_id:".$dbh->errstr());
      return;
    };

    while (my ($run_id) = $run_types_sth -> fetchrow_array()) {
      $matched_run_ids{$run_id} = 1;
    }
  }

  # Now we need to list all run types

  my $run_type_sth = $dbh->prepare("SELECT id,name FROM run_type");
  $run_type_sth ->execute() or do {
    print_bug("Couldn't list run types:".$dbh->errstr());
    return;
  };


  my @run_types;
  while (my ($id,$name) = $run_type_sth->fetchrow_array()) {
    my $selected = 0;
    $selected = 1 if (exists $matched_run_ids{$id});
    push @run_types, {
		      ID => $id,
		      NAME => $name,
		      SELECTED => $selected,
		     };
  }


  $template->param(RUN_TYPES => \@run_types);

  print $session->header();
  print $template -> output();

}

sub finish_edit_instrument {

  unless ($session -> param("is_admin")) {
    print_bug("Only admins can view this page and you don't appear to be one");
    return;
  }

  my $instrument_id = $q->param("instrument_id");

  if ($instrument_id) {
    unless ($instrument_id =~ /^\d+$/) {
      print_bug("Instrument id should be an integer, not '$instrument_id'");
      return;
    }
  }

  # Get the serial no
  my $serial = $q->param("serial");
  unless ($serial) {
    $serial = '[No Serial No]';
  }

  # Get the description
  my $description = $q->param("description");
  unless ($description) {
    print_error("No description was supplied");
    return;
  }

  # See if it's retired
  my $retired = $q->param("retired");
  if ($retired) {
    $retired = 1;
  }
  else {
    $retired = 0;
  }

  # Get the list of run_types which apply
  my @run_types = $q->param("run_type");

  foreach my $type (@run_types) {
    unless ($type =~ /^\d+$/) {
      print_bug("Run types should be integers, not '$type'");
      return;
    }
  }

  # If we have an instrument id we need to update its details
  if ($instrument_id) {
    $dbh->do("UPDATE instrument SET serial_number=?,description=?,retired=? WHERE id=?",undef,($serial,$description,$retired,$instrument_id)) or do {
      print_bug("Failed to update instrument '$instrument_id'".$dbh->errstr());
      return;
    };
  }
  else {
    # We're creating a new instrument
    $dbh->do("INSERT INTO instrument (serial_number,description,retired,available) VALUES (?,?,0,1)",undef,($serial,$description)) or do {
      print_bug("Failed to create new instrument:".$dbh->errstr());
      return;
    };

    ($instrument_id) = $dbh->selectrow_array("SELECT LAST_INSERT_ID()");
    unless ($instrument_id) {
      print_bug("Failed to get ID for newly created instrument: ".$dbh->errstr());
      return;
    }

  }

  # Now we can wipe out the run mappings we already have and add in the ones
  # specified
  $dbh->do("DELETE FROM run_type_instrument WHERE instrument_id=?",undef,($instrument_id)) or do {
    print_bug("Failed to delete run type mappings for instrument $instrument_id:".$dbh->errstr());
    return;
  };

  my $add_run_type_sth = $dbh->prepare("INSERT INTO run_type_instrument (instrument_id,run_type_id) VALUES (?,?)");

  foreach my $type (@run_types) {
    $add_run_type_sth -> execute($instrument_id,$type) or do {
      print_bug("Couldn't create new run type mapping between $instrument_id and $type: ".$dbh->errstr());
      return;
    };
  }

  print $q->redirect("sierra.pl?action=configuration#machines");

}

sub edit_run_type {

  unless ($session -> param("is_admin")) {
    print_bug("Only admins can view this page and you don't appear to be one");
    return;
  }

  my $template = HTML::Template -> new (filename=>'edit_run_type.html',associate => $session);

  my %matched_instrument_ids;

  my $run_type_id = $q->param("run_type_id");

  if ($run_type_id) {
    my ($id,$name,$lanes,$retired) = $dbh->selectrow_array("SELECT id,name,lanes,retired FROM run_type WHERE id=?",undef,($run_type_id));
    unless ($id) {
      print_bug("Couldn't find a run type with id $run_type_id".$dbh->errstr());
      return;
    }

    $template -> param (
			RUN_TYPE_ID => $run_type_id,
			NAME => $name,
			LANES => $lanes,
			RETIRED => $retired,
		       );


    # We also need a list of instruments for this run type
    my $instruments_sth = $dbh->prepare("SELECT instrument_id FROM run_type_instrument WHERE run_type_id=?");
    $instruments_sth -> execute($run_type_id) or do {
      print_bug("Couldn't list instruments for run type $run_type_id:".$dbh->errstr());
      return;
    };

    while (my ($instrument_id) = $instruments_sth -> fetchrow_array()) {
      $matched_instrument_ids{$instrument_id} = 1;
    }
  }

  # Now we need to list all instruments

  my $instruments_sth = $dbh->prepare("SELECT id,description FROM instrument");
  $instruments_sth ->execute() or do {
    print_bug("Couldn't list instruments:".$dbh->errstr());
    return;
  };


  my @instruments;
  while (my ($id,$name) = $instruments_sth->fetchrow_array()) {
    my $selected = 0;
    $selected = 1 if (exists $matched_instrument_ids{$id});
    push @instruments, {
			ID => $id,
			NAME => $name,
			SELECTED => $selected,
		       };
  }


  $template->param(INSTRUMENTS => \@instruments);

  print $session->header();
  print $template -> output();

}

sub finish_edit_run_type {

  unless ($session -> param("is_admin")) {
    print_bug("Only admins can view this page and you don't appear to be one");
    return;
  }

  my $run_type_id = $q->param("run_type_id");

  if ($run_type_id) {
    unless ($run_type_id =~ /^\d+$/) {
      print_bug("Run type id should be an integer, not '$run_type_id'");
      return;
    }
  }

  # Get the name
  my $name = $q->param("name");
  unless ($name) {
    print_error("No name was supplied");
    return;
  }

  # Get the number of lanes
  my $lanes = $q->param("lanes");
  unless ($lanes and $lanes=~/^\d+$/) {
    print_error("No lanes supplied, or lanes was not a number");
    return;
  }

  # See if it's retired
  my $retired = $q->param("retired");
  if ($retired) {
    $retired = 1;
  }
  else {
    $retired = 0;
  }

  # Get the list of instruments which apply
  my @instruments = $q->param("instrument");

  foreach my $type (@instruments) {
    unless ($type =~ /^\d+$/) {
      print_bug("Instrument ids should be integers, not '$type'");
      return;
    }
  }

  # If we have a run type id we need to update its details
  if ($run_type_id) {
    $dbh->do("UPDATE run_type SET name=?,lanes=?,retired=? WHERE id=?",undef,($name,$lanes,$retired,$run_type_id)) or do {
      print_bug("Failed to update run type '$run_type_id'".$dbh->errstr());
      return;
    };
  }
  else {
    # We're creating a new run_type
    $dbh->do("INSERT INTO run_type (name,lanes,retired) VALUES (?,?,0)",undef,($name,$lanes)) or do {
      print_bug("Failed to create new run type:".$dbh->errstr());
      return;
    };

    ($run_type_id) = $dbh->selectrow_array("SELECT LAST_INSERT_ID()");
    unless ($run_type_id) {
      print_bug("Failed to get ID for newly created run_type: ".$dbh->errstr());
      return;
    }

  }

  # Now we can wipe out the run mappings we already have and add in the ones
  # specified
  $dbh->do("DELETE FROM run_type_instrument WHERE run_type_id=?",undef,($run_type_id)) or do {
    print_bug("Failed to delete run type mappings for run type $run_type_id:".$dbh->errstr());
    return;
  };

  my $add_run_type_sth = $dbh->prepare("INSERT INTO run_type_instrument (instrument_id,run_type_id) VALUES (?,?)");

  foreach my $instrument (@instruments) {
    $add_run_type_sth -> execute($instrument,$run_type_id) or do {
      print_bug("Couldn't create new run type mapping between $instrument and $run_type_id: ".$dbh->errstr());
      return;
    };
  }

  print $q->redirect("sierra.pl?action=configuration#run_types");

}


sub edit_adapter_type {

  unless ($session -> param("is_admin")) {
    print_bug("Only admins can view this page and you don't appear to be one");
    return;
  }

  my $template = HTML::Template -> new (filename=>'edit_adapter_type.html',associate => $session);

  my $adapter_type_id = $q->param("adapter_type_id");

  if ($adapter_type_id) {
    my ($id,$name,$retired) = $dbh->selectrow_array("SELECT id,name,retired FROM adapter WHERE id=?",undef,($adapter_type_id));
    unless ($id) {
      print_bug("Couldn't find an adapter type with id $adapter_type_id".$dbh->errstr());
      return;
    }

    $template -> param (
			ADAPTER_TYPE_ID => $adapter_type_id,
			NAME => $name,
			RETIRED => $retired,
		       );

  }
  print $session->header();
  print $template -> output();

}

sub finish_edit_adapter_type {

  unless ($session -> param("is_admin")) {
    print_bug("Only admins can view this page and you don't appear to be one");
    return;
  }

  my $adapter_type_id = $q->param("adapter_type_id");

  if ($adapter_type_id) {
    unless ($adapter_type_id =~ /^\d+$/) {
      print_bug("Adapter type id should be an integer, not '$adapter_type_id'");
      return;
    }
  }

  # Get the name
  my $name = $q->param("name");
  unless ($name) {
    print_error("No name was supplied");
    return;
  }

  # See if it's retired
  my $retired = $q->param("retired");
  if ($retired) {
    $retired = 1;
  }
  else {
    $retired = 0;
  }

  # If we have an adapter type id we need to update its details
  if ($adapter_type_id) {
    $dbh->do("UPDATE adapter SET name=?,retired=? WHERE id=?",undef,($name,$retired,$adapter_type_id)) or do {
      print_bug("Failed to update adapter type '$adapter_type_id'".$dbh->errstr());
      return;
    };
  }
  else {
    # We're creating a new run_type
    $dbh->do("INSERT INTO adapter (name,retired) VALUES (?,0)",undef,($name)) or do {
      print_bug("Failed to create new adapter type:".$dbh->errstr());
      return;
    };

    ($adapter_type_id) = $dbh->selectrow_array("SELECT LAST_INSERT_ID()");
    unless ($adapter_type_id) {
      print_bug("Failed to get ID for newly created adaptor: ".$dbh->errstr());
      return;
    }

  }

  print $q->redirect("sierra.pl?action=configuration#adaptor_types");

}

sub edit_sample_type {

  unless ($session -> param("is_admin")) {
    print_bug("Only admins can view this page and you don't appear to be one");
    return;
  }

  my $template = HTML::Template -> new (filename=>'edit_sample_type.html',associate => $session);

  my $sample_type_id = $q->param("sample_type_id");

  if ($sample_type_id) {
    my ($id,$name,$description,$retired) = $dbh->selectrow_array("SELECT id,name,description,retired FROM sample_type WHERE id=?",undef,($sample_type_id));
    unless ($id) {
      print_bug("Couldn't find a sample type with id $sample_type_id".$dbh->errstr());
      return;
    }

    $template -> param (
			SAMPLE_TYPE_ID => $sample_type_id,
			NAME => $name,
			DESCRIPTION => $description,
			RETIRED => $retired,
		       );

  }

  print $session->header();
  print $template -> output();

}

sub finish_edit_sample_type {

  unless ($session -> param("is_admin")) {
    print_bug("Only admins can view this page and you don't appear to be one");
    return;
  }

  my $sample_type_id = $q->param("sample_type_id");

  if ($sample_type_id) {
    unless ($sample_type_id =~ /^\d+$/) {
      print_bug("Sample type id should be an integer, not '$sample_type_id'");
      return;
    }
  }

  # Get the name
  my $name = $q->param("name");
  unless ($name) {
    print_error("No name was supplied");
    return;
  }

  # Get the description
  my $description = $q->param("description");
  unless ($description) {
    print_error("No description was supplied");
    return;
  }

  # See if it's retired
  my $retired = $q->param("retired");
  if ($retired) {
    $retired = 1;
  }
  else {
    $retired = 0;
  }

  # If we have a sample type id we need to update its details
  if ($sample_type_id) {
    $dbh->do("UPDATE sample_type SET name=?,description=?,retired=? WHERE id=?",undef,($name,$description,$retired,$sample_type_id)) or do {
      print_bug("Failed to update sample type '$sample_type_id'".$dbh->errstr());
      return;
    };
  }
  else {
    # We're creating a new sample_type
    $dbh->do("INSERT INTO sample_type (name,description,retired) VALUES (?,?,0)",undef,($name,$description)) or do {
      print_bug("Failed to create new sample type:".$dbh->errstr());
      return;
    };

    ($sample_type_id) = $dbh->selectrow_array("SELECT LAST_INSERT_ID()");
    unless ($sample_type_id) {
      print_bug("Failed to get ID for newly created sample_type: ".$dbh->errstr());
      return;
    }

  }

  print $q->redirect("sierra.pl?action=configuration#sample_types");

}

sub edit_database {

  unless ($session -> param("is_admin")) {
    print_bug("Only admins can view this page and you don't appear to be one");
    return;
  }

  my $template = HTML::Template -> new (filename=>'edit_database.html',associate => $session);

  my $database_id = $q->param("database_id");

  if ($database_id) {
    my ($id,$species,$assembly,$folder) = $dbh->selectrow_array("SELECT id,species,assembly,folder FROM search_database WHERE id=?",undef,($database_id));
    unless ($id) {
      print_bug("Couldn't find a database with id $database_id".$dbh->errstr());
      return;
    }

    $template -> param (
			DATABASE_ID => $database_id,
			SPECIES => $species,
			ASSEMBLY => $assembly,
			FOLDER => $folder,
		       );

  }

  print $session->header();
  print $template -> output();

}

sub finish_edit_database {

  unless ($session -> param("is_admin")) {
    print_bug("Only admins can view this page and you don't appear to be one");
    return;
  }

  my $database_id = $q->param("database_id");

  if ($database_id) {
    unless ($database_id =~ /^\d+$/) {
      print_bug("Datbase id should be an integer, not '$database_id'");
      return;
    }
  }

  # Get the species
  my $species = $q->param("species");
  unless ($species) {
    print_error("No species was supplied");
    return;
  }

  # Get the assembly
  my $assembly = $q->param("assembly");

  # Get the folder
  my $folder = $q->param("folder");


  # If we have a database id we need to update its details
  if ($database_id) {
    $dbh->do("UPDATE search_database SET species=?,assembly=?,folder=? WHERE id=?",undef,($species,$assembly,$folder,$database_id)) or do {
      print_bug("Failed to update database '$database_id'".$dbh->errstr());
      return;
    };
  }
  else {
    # We're creating a new database
    $dbh->do("INSERT INTO search_database (species,assembly,folder) VALUES (?,?,?)",undef,($species,$assembly,$folder)) or do {
      print_bug("Failed to create new database:".$dbh->errstr());
      return;
    };

    ($database_id) = $dbh->selectrow_array("SELECT LAST_INSERT_ID()");
    unless ($database_id) {
      print_bug("Failed to get ID for newly created database: ".$dbh->errstr());
      return;
    }

  }

  print $q->redirect("sierra.pl?action=configuration");

}


sub logout {

  $session -> close();
  $session -> delete();
  $session -> flush();
  print $q->redirect("sierra.pl");
}

sub show_home_page {

  my $template = HTML::Template -> new (filename=>'home_page.html',associate => $session);

  if ($Sierra::Constants::PUBLIC_QUEUE or ($session ->param("is_admin"))){


    # If the admin has chosen to make the queue public then we'll put up a summary
    # on the home page and will add a link to the toolbar to see the details

    my @queue;

    my $queue_summary_sth = $dbh->prepare("SELECT run_type.name, sample.received_date,passed_qc_date FROM sample,run_type WHERE sample.is_complete != 1 and sample.run_type_id=run_type.id");

    $queue_summary_sth -> execute() or do {
      print_bug("Failed to generate queue summary: ".$dbh->errstr());
      return;
    };

    my %queue_counts;
    while (my ($run,$received,$qc) = $queue_summary_sth->fetchrow_array()) {
      unless (exists $queue_counts{$run}) {
	$queue_counts{$run} = {registered => 0, received=>0, passed_qc => 0};
      }

      ++$queue_counts{$run}->{registered};
      ++$queue_counts{$run}->{received} if ($received);
      ++$queue_counts{$run}->{passed_qc} if ($qc);
    }

    foreach my $run (sort {$queue_counts{$b}->{registered} <=> $queue_counts{$a}->{registered}} keys %queue_counts) {

      push @queue, {
		  RUN_TYPE => $run,
		  SAMPLES_REGISTERED => $queue_counts{$run}->{registered},
		  SAMPLES_RECEIVED => $queue_counts{$run}->{received},
		  SAMPLES_PASSED_QC => $queue_counts{$run}->{passed_qc},
		 };

    }


    $template->param(QUEUE_STATUS => \@queue,
		    );

  }



  # We need to list currently active samples

  my $active_samples_sth;

  # Admins don't get this. Normal users only see their own

    $active_samples_sth = $dbh->prepare("SELECT sample.id,sample.users_sample_name,sample.lanes_required,DATE_FORMAT(sample.received_date,'%e %b %Y'),DATE_FORMAT(sample.passed_qc_date,'%e %b %Y'),run_type.name FROM sample,run_type WHERE sample.person_id=? AND sample.run_type_id=run_type.id AND sample.is_complete != 1 AND sample.is_suitable_control != 1 ORDER BY submitted_date DESC");

    $active_samples_sth -> execute($session->param("person_id")) or do {
      print_bug("Couldn't get list of active samples: ".$dbh->errstr());
      return;
    };


  my $lane_count_sth = $dbh->prepare("SELECT count(*) FROM lane WHERE sample_id=?");

  my @active_samples;
  while (my ($id,$name,$requested,$received,$passed_qc,$first_name,$last_name,$run_type)= $active_samples_sth->fetchrow_array()) {

    $lane_count_sth ->execute($id) or do {
      print_bug("Couldn't count lanes run for sample '$id': ".$dbh->errstr());
      return;
    };

    my ($lane_count) = $lane_count_sth->fetchrow_array();


    push @active_samples, {
			   SAMPLE_ID => $id,
			   NAME => $name,
			   RECEIVED => $received,
			   PASSED_QC => $passed_qc,
			   LANES_REQUESTED => $requested,
			   LANES_RUN => $lane_count,
			  };

  }

  $template -> param(ACTIVE_SAMPLES => \@active_samples);

  # We also want to list any recent results they have generated.
  # We'll show up to 10 of their most recent results

  my @recent_results;

  # Again we show normal users their own samples.  Admins can see everyones
  my $recent_results_sth;

  if ($session -> param("is_admin")) {
    $recent_results_sth = $dbh->prepare("SELECT sample.id,lane.id,sample.users_sample_name,person.first_name,person.last_name FROM sample,lane,flowcell,run,person WHERE lane.sample_id=sample.id AND flowcell.id=lane.flowcell_id AND run.flowcell_id=lane.flowcell_id AND sample.person_id=person.id ORDER BY run.date DESC LIMIT 16");


    $recent_results_sth -> execute() or do {
      print_bug("Couldn't get list of admin recent results: ".$dbh->errstr());
      return;
    };
  }

  else {
    $recent_results_sth = $dbh->prepare("SELECT sample.id,lane.id,sample.users_sample_name FROM sample,lane,flowcell,run WHERE sample.person_id=? AND lane.sample_id=sample.id AND flowcell.id=lane.flowcell_id AND run.flowcell_id=lane.flowcell_id ORDER BY run.date DESC LIMIT 16");


    $recent_results_sth -> execute($session->param("person_id")) or do {
      print_bug("Couldn't get list of recent results: ".$dbh->errstr());
      return;
    };
  }


  while (my ($sample_id,$lane_id,$name,$first_name,$last_name) = $recent_results_sth -> fetchrow_array()) {
    if ($session -> param("is_admin")) {
      push @recent_results, {
			     SAMPLE_ID => $sample_id,
			     NAME => $name,
			     LANE_ID => $lane_id,
			     OWNER => "$first_name $last_name",
			     IS_ADMIN => 1,
			    };
    }
    else {
      push @recent_results, {
			     SAMPLE_ID => $sample_id,
			     NAME => $name,
			     LANE_ID => $lane_id
			    };
    }
  }

  $template -> param(RECENT_SAMPLES => \@recent_results);

  # If they're an admin we also want to check for any flowcells which have
  # been created but not yet run.

  if ($session -> param("is_admin")) {

    # We want to show a list of recently run flowcells
    my @recent_flowcells;

    my $recent_sth = $dbh->prepare("SELECT flowcell.id,run.run_folder_name,run_type.name, DATE_FORMAT(run.date,'%e %b %Y') FROM flowcell,run_type,run WHERE flowcell.run_id IS NOT NULL AND flowcell.run_type_id=run_type.id AND flowcell.run_id=run.id ORDER BY run.date DESC LIMIT 10");
    $recent_sth -> execute() or do {
      print_bug("Couldn't get list of recent flowcells: ".$dbh->errstr());
      return;
    };

    while (my ($id,$serial,$runtype,$date) = $recent_sth->fetchrow_array()) {
      push @recent_flowcells, {
			       FLOWCELL_ID => $id,
			       SERIAL => $serial,
			       RUN_TYPE => $runtype,
			       RUN_DATE => $date,
			       };
    }


    $template->param(RECENT_FLOWCELLS => \@recent_flowcells);

    # We want to show a list of pending flowcells
    my @pending_flowcells;

    my $pending_sth = $dbh->prepare("SELECT flowcell.id,flowcell.serial_number,run_type.name FROM flowcell,run_type WHERE flowcell.run_id IS NULL AND flowcell.run_type_id=run_type.id ORDER BY flowcell.id");
    $pending_sth -> execute() or do {
      print_bug("Couldn't get list of pending flowcells: ".$dbh->errstr());
      return;
    };

    while (my ($id,$serial,$runtype) = $pending_sth->fetchrow_array()) {
      push @pending_flowcells, {
				FLOWCELL_ID => $id,
				SERIAL => $serial,
				RUN_TYPE => $runtype,
			       };
    }

    $template->param(PENDING_FLOWCELLS => \@pending_flowcells);

  }


  print $session->header();
  print $template -> output();

}


sub show_queue {

  my $template = HTML::Template -> new (filename=>'show_queue.html',associate => $session);


  if (!$Sierra::Constants::PUBLIC_QUEUE and ! $session->param("is_admin")) {
    print_bug("Queue is not publicly visible");
  }

  # We need to show the queue

  my $active_samples_sth;

  # Admins get full details. Normal users see a reduced summary

  if ($session -> param("is_admin")) {
    $active_samples_sth = $dbh->prepare("SELECT sample.id,sample.users_sample_name,sample.lanes_required,DATE_FORMAT(sample.received_date,'%e %b %Y'),DATE_FORMAT(sample.passed_qc_date,'%e %b %Y'),person.first_name,person.last_name,run_type.name FROM sample,person,run_type WHERE  sample.is_complete != 1 AND sample.person_id=person.id AND sample.run_type_id=run_type.id AND sample.is_suitable_control != 1 ORDER BY sample.submitted_date");

    $active_samples_sth -> execute() or do {
      print_bug("Couldn't get list of active admin samples: ".$dbh->errstr());
      return;
    };
  

    my $lane_count_sth = $dbh->prepare("SELECT count(*) FROM lane WHERE sample_id=?");

    # We're splitting the active samples by the first word
    # in the run type.
    my %tables;
    
    while (my ($id,$name,$requested,$received,$passed_qc,$first_name,$last_name,$run_type)= $active_samples_sth->fetchrow_array()) {

      $lane_count_sth ->execute($id) or do {
	print_bug("Couldn't count lanes run for sample '$id': ".$dbh->errstr());
	return;
      };

      my ($lane_count) = $lane_count_sth->fetchrow_array();

      my $first_word = $run_type;
      $first_word =~ s/\s.*$//;

      # We need to classify the samples.  The classification would be:

      # Ready to sequence - has passed final QC
      # Awaiting QC - received but no QC yet
      # Not received

      my $class = "";
      if ($passed_qc) {
	$class="ready";
      }
      elsif ($received) {
	$class="received";
      }

      push @{$tables{$first_word}}, {
			     SAMPLE_ID => $id,
			     NAME => $name,
			     RECEIVED => $received,
			     PASSED_QC => $passed_qc,
			     LANES_REQUESTED => $requested,
			     RUN_TYPE => $run_type,
			     LANES_RUN => $lane_count,
			     IS_ADMIN => 1,
			     OWNER => "$first_name $last_name",
			     CLASS => $class,
			    };

      
      
    }

    # Now extract the tables into an array
    my @tables;
    foreach my $table (sort keys %tables) {
      push @tables, {
	TABLE_NAME => $table,
	ACTIVE_SAMPLES => $tables{$table}
      };
    }
    
    $template -> param(TABLES => \@tables);

    
  }

  else {
    # Normal users get a reduced veiw of the queue
    # We need to show the current state of the queue
    my @queue;

    # Collect a list of the samples which are still active
    my $queue_active_samples_sth = $dbh->prepare("SELECT sample.id,sample.lanes_required,DATE_FORMAT(sample.submitted_date,'%e %b %Y'),DATE_FORMAT(sample.received_date,'%e %b %Y'),DATE_FORMAT(sample.passed_qc_date,'%e %b %Y'),run_type.name,person.first_name,person.last_name,person.anonymous FROM sample,person,run_type WHERE  sample.is_complete != 1 AND sample.run_type_id=run_type.id AND sample.person_id=person.id AND sample.is_suitable_control != 1 ORDER BY run_type.name, sample.submitted_date DESC");
    $queue_active_samples_sth -> execute() or do {
      print_bug("Failed to list active samples for queue: ".$dbh->errstr());
      return;
    };

    while (my ($sample_id,$lanes_required,$submitted,$received,$passed,$run,$first,$last,$anonymous) = $queue_active_samples_sth->fetchrow_array()) {
	
      my $owner = "$first $last";
      if ($anonymous) {
	$owner = "[Anonymous user]";
      }

      push @queue, {
		    RUN_TYPE => $run,
		    LANES_REQUESTED => $lanes_required,
		    OWNER => $owner,
		    SUBMITTED => $submitted,
		    RECEIVED => $received,
		    PASSED => $passed,
		   };
    }

    $template->param(QUEUE_STATUS => \@queue);


  }

  print $session->header();
  print $template -> output();

}


sub check_sample_edit_permission  {

  # Only sample owners and admins can edit a sample

  my ($sample_id,$person_id) = @_;

  # Check to see if they're the owner
  my ($sample_owner) = $dbh->selectrow_array("SELECT person_id FROM sample WHERE id=?",undef,($sample_id));

  if ($sample_owner and $sample_owner == $person_id) {
    return 1;
  }

  # They're still OK if they're an admin

  # Check to see if they're the owner
  my ($is_admin) = $dbh->selectrow_array("SELECT is_admin FROM person WHERE id=?",undef,($person_id));


  if (defined($is_admin) and $is_admin) {
    return 1;
  }

  return (0);

}

sub get_valid_budget_list {

  my ($person_id,$sample_id) = @_;

  # If no person id is specified then this is an admin and we give
  # them everything.
  
  # If a person_id is specified then they get the codes they have
  # access to.  However, if a sample_id is also specified then they
  # also get the code currently attached to that sample (which may have
  # been assigned by an admin), so that we don't wipe stuff out by
  # accident.

  # Check to see if there's a budget database defined
  if ($Sierra::Constants::BUDGET_DB_NAME) {

    my $email;

    if ($person_id) {
      # Get the email of the person we're looking at
      ($email) = $dbh->selectrow_array("SELECT email from person where id=?",undef,($person_id));
      unless ($email) {
	print_bug("Couldn't get email for person id $person_id");
	return;
      }
    }

    my $budget_dbh = DBI->connect("DBI:mysql:database=$Sierra::Constants::BUDGET_DB_NAME;host=$Sierra::Constants::BUDGET_DB_SERVER",$Sierra::Constants::BUDGET_DB_USERNAME,$Sierra::Constants::BUDGET_DB_PASSWORD,{RaiseError=>0,AutoCommit=>1});

    unless ($budget_dbh) {
      print_bug("Couldn't connect to budget database:".$DBI::errstr);
      exit;
    }

    # See what we can find for this email.  If we're not passed an email we return a
    # non-redundant list of every possible code
    my $sth;

    if ($email) {
      $sth = $budget_dbh->prepare("SELECT code,description FROM budget_codes WHERE email=?");

      $sth->execute($email) or do {
	print_bug("Failed to list valid budgets for $email: ".$dbh->errstr());
	exit;
      };
    }
    else {
      $sth = $budget_dbh->prepare("SELECT code,description FROM budget_codes");

      $sth->execute() or do {
	print_bug("Failed to list all valid budgets: ".$dbh->errstr());
	exit;
      };
    }

    my @valid_codes;
    my %seen_codes;

    while (my ($code,$description) = $sth->fetchrow_array()) {

      next if (exists $seen_codes{$code});
      $seen_codes{$code}++;
      push @valid_codes, {CODE => $code,
			  DESCRIPTION => $description,};

    }

    # Finally, if we have a person id and a sample id then we add in 
    # the current budget code for that sample, even if it's not normally
    # allowed for that user.

    if ($email and $sample_id) {
	# Find the code for that sample
	my $sample_budget = $dbh -> selectrow_array("SELECT budget_code FROM sample WHERE id=?",undef,($sample_id));

	if ($sample_budget and not exists $seen_codes{$sample_budget}) {
	    push @valid_codes, {CODE => $sample_budget, DESCRIPTION => 'Existing code on sample'};
	}
    }


    return @valid_codes;
  }

  return ();

}

sub check_sample_view_permission  {

  my ($sample_id,$person_id) = @_;

  # If they have an auth token then we check this first
  if ($q -> param("authkey")) {
    my ($auth_id) = $dbh->selectrow_array("SELECT id FROM sample_auth_key WHERE sample_id=? AND authkey=?",undef,($sample_id,$q->param("authkey")));

    if ($auth_id) {
      return (1);
    }
  }


  # To view a sample they simply need an entry in the permissions table
  my ($permission_id) = $dbh->selectrow_array("SELECT person_permission.id FROM sample,person_permission WHERE sample.id=? AND sample.person_id=person_permission.owner_person_id AND person_permission.permission_person_id=?",undef,($sample_id,$person_id));

  if ($permission_id) {
    return 1;
  }

  # They're still OK if they're an admin

  my ($is_admin) = $dbh->selectrow_array("SELECT is_admin FROM person WHERE id=?",undef,($person_id));

  if (defined($is_admin) and $is_admin) {
    return 1;
  }

  return (0);

}


sub print_bug {

  my ($message) = @_;

  # Put something into the logs
  warn $message;

  my $template = HTML::Template -> new (filename=>'bug.html', associate=>$session);

  $template->param(MESSAGE => $message);

  print $q->header();

  print $template -> output();

}

sub print_error {

  my ($message) = @_;

  my $template = HTML::Template -> new (filename=>'error.html', associate=>$session);

  $template->param(MESSAGE => $message);

  print $q->header();

  print $template -> output();

}

sub make_random_string {
  my ($length) = @_;

  my @string;

  my @letters = ('A'..'Z','a'..'z',0..9);

  for (1..$length) {
    push @string,$letters[int(rand(scalar @letters))];
  }

  return join("",@string);


}


sub send_email {

  my ($subject,$message,@recipiants) = @_;

  my $smtp = Net::SMTP -> new(Host => $Sierra::Constants::SMTP_SERVER,
			      Timeout => 30,
			      Debug => 0);

  unless ($smtp) {
    print_bug("Failed to connect to $Sierra::Constants::SMTP_SERVER");
    return 0;
  }


  if ($Sierra::Constants::SMTP_USERNAME) {
    $smtp->auth($Sierra::Constants::SMTP_USERNAME,$Sierra::Constants::SMTP_PASSWORD) or do {
      print_bug("Failed to authenticate with SMTP server");
      return 0;
    };
  }

  $smtp->mail("Sierra LIMS System <$Sierra::Constants::MAILS_FROM_ADDRESS>") or do {
    print_bug("Invalid from address $Sierra::Constants::MAILS_FROM_ADDRESS");
    return 0;
  };

  $smtp->to(@recipiants) or do {
    print_bug("Invalid email address in @recipiants");
    return 0;
  };

  $smtp->data();

  foreach my $recipiant (@recipiants) {
    $smtp->datasend("To: $recipiant\n");
  }

  $smtp->datasend("From: Sierra LIMS System <$Sierra::Constants::MAILS_FROM_ADDRESS>\n");
  $smtp->datasend("Subject: $subject\n");
  $smtp->datasend("\n"); # End of headers
  $smtp->datasend($message);
  $smtp->dataend();
  $smtp->quit();

  return 1;

}

sub send_bcc_email {

  my ($subject,$message,@recipiants) = @_;

  my $smtp = Net::SMTP -> new(Host => $Sierra::Constants::SMTP_SERVER,
			      Timeout => 30,
			      Debug => 0);

  unless ($smtp) {
    print_bug("Failed to connect to $Sierra::Constants::SMTP_SERVER");
    return 0;
  }


  if ($Sierra::Constants::SMTP_USERNAME) {
    $smtp->auth($Sierra::Constants::SMTP_USERNAME,$Sierra::Constants::SMTP_PASSWORD) or do {
      print_bug("Failed to authenticate with SMTP server");
      return 0;
    };
  }

  $smtp->mail("Sierra LIMS System <$Sierra::Constants::MAILS_FROM_ADDRESS>") or do {
    print_bug("Invalid from address $Sierra::Constants::MAILS_FROM_ADDRESS");
    return 0;
  };

  $smtp->to($Sierra::Constants::MAILS_FROM_ADDRESS) or do {
    print_bug("Can't set $Sierra::Constants::MAILS_FROM_ADDRESS as 'to' for emails");
    return 0;
  };

  $smtp->bcc(@recipiants) or do {
    print_bug("Invalid email address in @recipiants");
    return 0;
  };


  $smtp->data();

  $smtp->datasend("To: $Sierra::Constants::MAILS_FROM_ADDRESS\n");

  foreach my $recipiant (@recipiants) {
    $smtp->datasend("Bcc: $recipiant\n");
  }

  $smtp->datasend("From: Sierra LIMS System <$Sierra::Constants::MAILS_FROM_ADDRESS>\n");
  $smtp->datasend("Subject: $subject\n");
  $smtp->datasend("\n"); # End of headers
  $smtp->datasend($message);
  $smtp->dataend();
  $smtp->quit();

  return 1;

}
