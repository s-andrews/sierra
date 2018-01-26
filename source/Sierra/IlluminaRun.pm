#!/usr/bin/perl

##########################################################################
#                                                                        #
# Copyright 2011, Simon Andrews (simon.andrews@babraham.ac.uk)           #
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
use lib "../";
use Sierra::Constants;
use Sierra::IlluminaLane;
use Sierra::OLBResultsFolder;
use Sierra::CasavaResultsFolder;


package Sierra::IlluminaRun;


sub new {

  my ($class,$run_folder_name) = @_;



  my $obj =  bless {
		    run_folder => $run_folder_name,
		    processing_folders => [],
		   };

  foreach my $folder (@Sierra::Constants::DATA_FOLDERS) {
    if (-e "$folder/$run_folder_name") {
      $obj -> {run_folder_location} = "$folder/$run_folder_name";
      last;
    }
  }

  # It's OK to have a run folder which doesn't exist yet
  # so we'll remove this warning
#  unless ($obj->{run_folder_location}) {
#    warn "No run folder for $run_folder_name";
#  }

  _get_files($obj);

  return $obj;

}

sub _get_files {


  my ($obj) = @_;

  unless ($obj->get_run_folder()) {
    return;
  }

  # We need to find which processing results exist

  # First check for GERALD folders coming from older versions
  # of CASAVA, or from runs reprocessed with OLB

  # Check separately for Casava vs OLB patterns

  my $glob_pattern = $obj->get_run_folder()."/Data/Intensities/BaseCalls/GERALD*";
  my @processing_folders = glob($glob_pattern);

  foreach my $folder (@processing_folders) {

    # Check that there is a Summary.xml file in the folder.  If not
    # then it's not a completed run
    if (-e "$folder/Summary.xml") {
      push @{$obj->{processing_folders}}, new Sierra::OLBResultsFolder($obj,$folder);
    }

  }

  # Now do OLB patterns

  $glob_pattern = $obj->get_run_folder()."/Data/C*Firecrest*/Bustard*/GERALD*";
  @processing_folders = glob($glob_pattern);

  foreach my $folder (@processing_folders) {

    # Check that there is a Summary.xml file in the folder.  If not
    # then it's not a completed run
    if (-e "$folder/Summary.xml") {
      push @{$obj->{processing_folders}}, new Sierra::OLBResultsFolder($obj,$folder);
    }

  }

  # Also check for OLB patterns from runs which used the IPAR
  $glob_pattern = $obj->get_run_folder()."/Data/IPAR*/Bustard*/GERALD*";
  @processing_folders = glob($glob_pattern);

  foreach my $folder (@processing_folders) {

    # Check that there is a Summary.xml file in the folder.  If not
    # then it's not a completed run
    if (-e "$folder/Summary.xml") {
      push @{$obj->{processing_folders}}, new Sierra::OLBResultsFolder($obj,$folder);
    }

  }

  # Also check for OLB patterns from runs which used the default intensities but reran GERALD
  $glob_pattern = $obj->get_run_folder()."/Data/Intensities/Bustard*/GERALD*";
  @processing_folders = glob($glob_pattern);

  foreach my $folder (@processing_folders) {

    # Check that there is a Summary.xml file in the folder.  If not
    # then it's not a completed run
    if (-e "$folder/Summary.xml") {
      push @{$obj->{processing_folders}}, new Sierra::OLBResultsFolder($obj,$folder);
    }

  }



  # Also check for any newer output folders which may have
  # come from later versions of CASAVA

  $glob_pattern = $obj->get_run_folder()."/*ligned/Project_*/Sample_*";
  @processing_folders = glob($glob_pattern);

  foreach my $folder (@processing_folders) {
    push @{$obj->{processing_folders}}, new Sierra::CasavaResultsFolder($obj,$folder);
  }

}

sub get_results_folders {

  my $obj = shift;

  return @{$obj->{processing_folders}};
}



sub exists {

  my ($obj) = @_;

  return exists $obj->{run_folder_location};

}

sub get_lane_count {

  my $obj = shift;

  unless ($obj->exists()) {
    return 0;
  }

}


sub get_run_folder {

  my $obj = shift;

  return $obj->{run_folder_location};

}

sub get_lane {

  my ($obj,$lane) = @_;

  unless ($obj->exists()) {
    return undef;
  }
#
#  if (!$lane =~ /^\d+$/) {
#    die "Lane number must be a number, not '$lane'";
#  }

  return new Sierra::IlluminaLane($obj,$lane);

}



1;
