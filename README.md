j2ssh-fork
==========

This is a fork of the J2SSH library, mostly unchanged in terms of the SSH support, but with some tweaks, changes and bugfixes as required. There were also some important configuration files missing in the original, which I have managed to piece together by looking at the source.

This version is being compiled for Java 5.

The original project is http://sourceforge.net/projects/sshtools. At the time we created this fork, there was little activity on that project, but they have since done some cleanup and fixed a few bugs, so you might want to look at that.

There probably won't be much work on the default filesystem class since we implemented one specific to an internal application. So bugs in the provided native filesystem class may not get fixed. It does, however, mostly work as is.
