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
use Sierra::ResultFile;
use XML::Simple;


package Sierra::OLBResultsFolder;

sub new {

  my ($class,$run,$folder) = @_;

  my $relative_path = $folder;
  my $run_folder = $run->get_run_folder();
  $relative_path =~ s/^\Q$run_folder\E\/?//;

  my @path_sections = split(/\//,$relative_path);

  foreach my $section (@path_sections) {
    $section =~ s/(-\d{4})_\w+/$1/;
  }

  my $name = join(" > ",@path_sections);

  my $obj = bless {
		   folder => $folder,
		   run => $run,
		   name => $name,
		  };


  return $obj;

}

sub name {
  my $obj = shift;
  return $obj->{name};
}

sub get_attributes_for_lane {

  my $obj = shift;
  my $laneobj = shift;

  open (IN,$obj->{folder}."/Summary.xml") or die "Can't read Summary.xml file: $!";

  my $xml_string = "<?xml version=\"1.0\" ?>\n";

  my $keep = 0;
  while (<IN>) {

    if (/<ExpandedLaneSummary>/) {
      $keep = 1;
    }

    $xml_string .= $_ if ($keep);

    last if (/<\/ExpandedLaneSummary>/);


  }

  my $xml = XML::Simple::XMLin($xml_string);

  my @attributes;

  if (ref $xml->{Read} eq 'HASH') {
    $xml->{Read} = [$xml->{Read}];
  }

  foreach my $read (@{$xml->{Read}}) {

    my $read_number = $read->{readNumber};

    foreach my $lane (@{$read->{Lane}}) {

      if ($lane->{laneNumber} == $laneobj->get_lane()) {

	my $d = Data::Dumper->new([$lane]);

	if (exists $lane->{clusterCountRaw}->{mean} and exists $lane->{percentClustersPF}->{mean}) {
	  my $raw_reads = $lane->{clusterCountRaw}->{mean}*120; # We assume 120 tiles per flowcell, which isn't always true
	  push @attributes,["Read$read_number Raw Clusters", $raw_reads];
	  my $purity_percent = $lane->{percentClustersPF}->{mean};
	  push @attributes,["Read$read_number Percent Passed Purity Filter",$purity_percent];
	  push @attributes,["Read$read_number Filtered Clusters",int (($raw_reads/100)*$purity_percent)];
	}

	if (exists $lane->{percentUniquelyAlignedPF}) {
	  push @attributes,["Read$read_number Percent Aligned", $lane->{percentUniquelyAlignedPF}->{mean}];
	  push @attributes,["Read$read_number Aligned Error Percentage", $lane->{errorPF}->{mean}];
	}

      }
    }
  }

  return @attributes;

}

sub get_files_for_lane {

  my $obj = shift;
  my $lane = shift;
  my $type_filter = shift;
  my @barcodes = @_;

  # We'll initally make up a list of all files we're going to 
  # show which we'll then try to classify

  my $glob_pattern = $obj->{folder}."/s_".$lane->get_lane()."_*";
  my @files_to_show = glob($glob_pattern);

  if (@barcodes) {
    # Filter the files to show to include only those
    # which contain the barcode sequences in their names

    my @filtered_files;

    FILE: foreach my $file (@files_to_show) {
	my ($name) = (split(/\//,$file))[-1];
	foreach my $barcode (@barcodes) {
	  next FILE unless (index($name,$barcode) >=0 );
	}

	push @filtered_files,$file;
      }

    @files_to_show = @filtered_files;

  }

  # We'll then iterate through these files trying to classify them

  my @files;

  foreach my $file (@files_to_show) {

    my ($name) = (split(/\//,$file))[-1];

    # There are a couple of files we don't want to see
    next if ($name =~ /_finished\.txt$/);
    next if ($name =~ /_genomesize.xml$/);
    next if ($name =~ /_tiles.txt$/);
    next if ($name =~ /_pair.xml$/);
    next if ($name =~ /_qcalreport.txt$/);
    next if ($name =~ /_anomaly.txt$/);
    next if ($name =~ /_reanomraw.txt$/);
    next if ($name =~ /_export\.txt$/ or $name =~ /_export\.txt\.gz$/);
    next if ($name =~ /_extended\.txt$/ or $name =~ /_extended\.txt\.gz$/);
    next if ($name =~ /_calsaf\.txt$/ or $name =~ /_calsaf\.txt\.gz$/);
    next if ($name =~ /_error_pngs\.txt$/);


    # Export files
    if ($name =~ /export\.txt$/ or $name=~ /export\.txt\.gz$/) {
      push @files, new Sierra::ResultFile($name,$file,'Raw Mapped Sequence Data');
    }

    # Sorted files
    elsif ($name =~ /sorted.txt$/ or $name=~ /sorted.txt.gz$/) {
      push @files, new Sierra::ResultFile($name,$file,'Sorted Mapped Sequence Data');
    }


    # QC files
    elsif (-d $file and $file =~ /fastqc$/) {

      my $fastqc_file = "$file/fastqc_report.html";

      if (-e $fastqc_file) {
	push @files, new Sierra::ResultFile($name,$fastqc_file,'FastQC QC Report','text/html');

	# We also need to add all of the files under the fastqc
	# folder as hidden files so we can allow the user to access
	# them, but without them showing up in the list of files
	my $fastqc_folder = $file;
	$fastqc_folder =~ s/\/fastqc_report.html$//;
	my @images = glob("$fastqc_folder/Images/*png");
	foreach my $image (@images) {
	  push @files, new Sierra::ResultFile(undef,$image,'FastQC Image','image/png',1);
	}
	@images = glob("$fastqc_folder/Icons/*png");
	foreach my $image (@images) {
	  push @files, new Sierra::ResultFile(undef,$image,'FastQC Image','image/png',1);
	}
      }
    }
  

    # QC archive files
    elsif ($name =~ /fastqc.zip$/) {
      push @files, new Sierra::ResultFile($name,$file,'FastQC QC Archive');
    }

    # Screen files
    elsif ($name =~ /_screen.txt$/) {
      push @files, new Sierra::ResultFile($name,$file,'Species Screen Results','text/plain');
    }

    # Screen images
    elsif ($name =~ /_screen.png$/) {
      push @files, new Sierra::ResultFile($name,$file,'Species Screen Graph','image/png');
    }

    # Tophat files
    elsif ($name =~ /tophat/) {
      push @files, new Sierra::ResultFile($name,$file,'Tophat spliced mapped reads');
    }

    # Bowtie files
    elsif ($name =~ /bowtie/) {
      push @files, new Sierra::ResultFile($name,$file,'Bowtie mapped reads');
    }

    # Bismark report files
    elsif ($name =~ /Bismark_mapping_report.txt$/) {
      push @files, new Sierra::ResultFile($name,$file,'Bismark report file','text/plain');
    }


    # Bismark files
    elsif ($name =~ /bismark/) {
      push @files, new Sierra::ResultFile($name,$file,'Bismark results file');
    }

    # ASAP files]
    elsif ($name =~ /ASAP/ and $name =~ /report/) {
      push @files, new Sierra::ResultFile($name,$file,'ASAP differential mapping report','text/plain');
    }


    # ASAP files
    elsif ($name =~ /ASAP/) {
      push @files, new Sierra::ResultFile($name,$file,'ASAP differentially mapped reads');
    }

    # BAM files
    elsif ($name =~ /\.bam$/) {
      push @files, new Sierra::ResultFile($name,$file,'BAM format mapped reads');
    }

    # SAM files
    elsif ($name =~ /\.sam/ or $name =~ /\.sam\.gz$/) {
      push @files, new Sierra::ResultFile($name,$file,'SAM format mapped reads');
    }

    # FastQ files
    elsif ($name =~ /\.fastq$/ or $name =~ /\.fastq.gz$/ or $name=~ /_sequence.txt$/ or $name=~ /_sequence.txt.gz$/) {
      push @files, new Sierra::ResultFile($name,$file,'FastQ sequence file');
    }

    # Generic Image files (mostly to get the right mime-type)
    elsif ($name =~ /.png$/) {
      push @files, new Sierra::ResultFile($name,$file,'PNG Image','image/png');
    }

    else {
      push @files, new Sierra::ResultFile($name,$file,'Results file');
    }


  }

  # Anyone from any lane can see the Summary.xml and config.xml files.  
  # We hide this from the UI, but putting it here ensures that we will 
  # pull it down in the backup.
  if (-e $obj->{folder}."/Summary.xml") {
    push @files, new Sierra::ResultFile(undef,$obj->{folder}."/Summary.xml",'RunInfo','text/plain',1);
  }
  if (-e $obj->{folder}."/config.xml") {
    push @files, new Sierra::ResultFile(undef,$obj->{folder}."/config.xml",'RunInfo','text/plain',1);
  }

  return @files;

}



1;
