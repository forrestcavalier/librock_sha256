# librock_sha256

This is a plain .c implementation of sha256, adapted from picoSHA2,
which is a C++ header only version.

I wanted an MIT-licensed version to replace the verison I created
from LibreSSL. That came with 142 text lines of license boilerplate:
3 copies of the BSD 4-clause license, one for each copyright predecessor,
lots of confusing uses of preprocessor macros, and support for SHA224
(which is unecessary for SHA256.)

In making this adaptation, I made only mechanical and trivial changes,
which I decided are not copyrightable. I left the copyright notice from
picoSHA2.