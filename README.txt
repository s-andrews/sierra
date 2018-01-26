Sierra Sequencing LIMS System
-----------------------------

Sierra is a simple LIMS system designed to be used by small sequencing facilities
who need an easy easy way to keep track of the samples submitted to them, and 
return sequencing results.

Sierra is a web based LIMS which uses a mysql database backend to keep track of
your sample metadata.  No sequence data is stored inside Sierra, instead you 
simply point it to a directory which contains the run folders created by your
sequencer and it will read the appropriate data out of there.

To get started with Sierra all you need is a computer on which you can run:

 - A webserver (the instructions assume apache, but any server could be used)

 - A mysql database server (this can be on a different machine if you prefer)

 - Perl

All of the instructions for setting up a new instance of Sierra can be found
in the manual, which is in the documentation folder of the distribution.

If you have any problems with Sierra you can report them in our bug tracking
system at:

www.bioinformatics.bbsrc.ac.uk/bugzilla/

..or you can send them directly to simon.andrews@babraham.ac.uk
