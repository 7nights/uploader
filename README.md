# uploader
A light weight file transfer.

### Command line

```bash
$ bin/uploder --help

  Usage: uploader [options] [command]


  Commands:

    send [options] [source] [target]  sends file to a remote server
    listen [options]                  start to listen file uploading
    stop                              stop listening

  Options:

    -h, --help     output usage information
    -V, --version  output the version number
```

### Node.js

```javascript
var uploader = require('uploder');

uploader.createServer();

uploader.sendFile(host, port, password, source, target);

var c = uploader.connect(host, port, password, null, function () {
    c.sendFile(source, target, false, function () {
        c.unref();
    });
});
```