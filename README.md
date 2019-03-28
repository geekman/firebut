firebut
========
**firebut** is short for *Firebase Upload Tool*.

It is like the official [firebase-tools](https://github.com/firebase/firebase-tools) CLI 
but very much simpler and stripped down.
It only implements an uploader for [Firebase Hosting](https://firebase.google.com/docs/hosting/),
so it's great if you want to host static pages on Firebase.
You can also avoid having to install the Node.js and npm crap
because this tool is written in Go and compiles to a single static binary.

⚠️ This project is still in beta.
I'll not be responsible if your site is destroyed by this tool.

Installation
=============

You can download pre-built binaries for your platform on the 
[releases page on GitHub](https://github.com/geekman/firebut/releases).

You will need to install [Go](https://golang.org/).

To download and compile *firebut*, use `go get`:

	go get github.com/geekman/firebut

The `firebut` executable should now be in your `$GOPATH/bin` directory.


Usage
======
You will need to run *firebut* in your project directory.
This is where the config file `.firebut` is created, 
as well as where the tool can find the files to be uploaded (deployed).
Following the firebase-tools CLI, firebut assumes that the files are in the `public` subdirectory.
*firebase-tools* allows you to configure this using the 
[`firebase.json`](https://firebase.google.com/docs/hosting/full-config) 
file but this is not supported in firebut yet.

The steps to use firebut is similar:

1. `firebut login`
2. `firebut upload -message "uploaded new version with firebut"`

You need to use `login` for the first time to authorize *firebut* to upload files.
Once the config file has been created, you can just use `upload` to deploy new versions of your site.

Optionally, you can also use `firebase diff` to see what files have changed
since your last deployed version.


Note about `diff`
=================
Note that the `diff` function retrieves gzipped content hash, 
rather than of the actual file contents, so files uploaded using the official 
*firebase-tools* will show up as "modified", even though the files may be exactly the same.

This issue is due to different gzip implementations in Go and Node.js.
It will go away once a new version has been uploaded using this Go-based tool.


License
========

**firebut is licensed under the 3-clause ("modified") BSD License.**

Copyright (C) 2019 Darell Tan

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

1. Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.
3. The name of the author may not be used to endorse or promote products
   derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR "AS IS" AND ANY EXPRESS OR
IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

