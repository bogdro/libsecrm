# LibSecRm #

LibSecRm - a library which ensures secure removing of files and clearing
memory on the system to prevent leakage of sensitive data.

The function replacements in LibSecRm first securely wipe the part of the
file which would be deleted (just like `shred`, but only rejected
parts of files get destroyed, not the whole files) to prevent leakage of
sensitive data.

After that, the original functions get called to do their job, so that the
calling program can continue working as usual.

Read the info documentation (type `info doc/libsecrm.info`) to get more
information.

Project homepage: <https://libsecrm.sourceforge.io/>.

Author: Bogdan Drozdowski, bogdro (at) users . sourceforge . net

License: GPLv3+

## WARNING ##

The `dev` branch may contain code which is a work in progress and committed
just for tests. The code here may not work properly or even compile.

The `master` branch may contain code which is committed just for quality tests.

The tags, matching the official packages on SourceForge,
should be the most reliable points.
