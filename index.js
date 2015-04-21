var 
    net     = require('net'),
    fs      = require('fs'),
    os      = require('os'),
    Int64   = require('node-int64'),
    crypto  = require('crypto'),
    path    = require('path'),
    L       = require('./lib/linklist'),
    ptypes  = require('./ptypes.json'),
    config  = require('./config.json'),
    util    = require('./lib/util'),
    program = require('commander'),
    events  = require('./events.json');

require('colors');

var cst = {
    RUNNING_PROCESS: '.settings/running'
};
util.mkdirpSync('.settings/');

program
    .version('0.0.1')
    .command('send [source] [target]')
    .description('sends file to a remote server')
    .option('-h, --host <s>', 'target host')
    .option('-p, --port <n>', 'target port')
    .option('-w, --password <n>', 'password')
    .action(function (source, target, options) {
        exports.sendFile(options.host, options.port, options.password, source, target);
    });

program
    .command('listen')
    .description('start to listen file uploading')
    .option('-p, --port <n>', 'port to listen')
    .option('-a, --algorithm <s>', 'encryption algorithm')
    .option('-h, --hmacalgorithm <s>', 'handshake algorithm')
    .option('-k, --hmackey <s>', 'hmac key')
    .option('-b, --blocksize <b>', 'cipher block size')
    .action(function (opt) {
        if (opt.port) config.PORT = opt.port;
        if (opt.algorithm) config.CIPHER_ALGORITHM = opt.algorithm;
        if (opt.hmacalgorithm) config.HMAC_ALGORITHM = opt.hmacalgorithm;
        if (opt.hmackey) config.HMAC_KEY = opt.hmackey;
        if (opt.blocksize) config.CIPHER_BLOCK_SIZE = opt.blocksize;
        exports.createServer();
    });

program
    .command('stop')
    .description('stop listening')
    .action(function () {
        if(!fs.existsSync(cst.RUNNING_PROCESS)) return console.log('No running server.');
        var runningProcess = fs.readFileSync(cst.RUNNING_PROCESS).toString('utf-8').split('\n');
        fs.unlinkSync(cst.RUNNING_PROCESS);
        runningProcess.forEach(function (val) {
            if (!val) return;
            console.log('Exit process', val);
            require('child_process').exec('kill ' + val);   
        });
    });

exports.createServer = function () {
    var server = net.createServer(onConnection);
    server.listen(config.PORT, onListening);
};
/** clients map */
var clients = {};

var hellman = crypto.getDiffieHellman('modp14');
hellman.generateKeys();

function onListening() {
    console.log('Server established on port: ' + config.PORT);
    console.log('pid >', process.pid);
    fs.appendFileSync(cst.RUNNING_PROCESS, process.pid + '\n');
}

function onConnection(c) {
    c.on('end', onEnd);
    c.on('data', onData);

    prepareSocket(c);

    /* write hmac key */
    writePackage(c, {
        type: ptypes.AUTH.RANDOM_BYTES,
        content: c.hmacRandomBytes
    });
}
/**
 * @param {String} host Server to connect.
 * @param {Number} port
 * @param {String} password
 * @param {String} [token] Connect server with a token given by server from previous connection.
 * @param {Function} callback Triggered after handshake.
 */
exports.connect = function (host, port, password, token, callback) {
    if (arguments.length === 4) {
        callback = token;
        token = null;
    } 
    var client = net.connect({
        host: host,
        port: port
    }, function () {});

    client._userData = {
        hmac_key: password
    };

    client.on('data', onData);
    client.on('handshake', callback);
    prepareSocket(client);

    client.preToken = token;
    client.argumentsCache = [host, port, password, token, callback];
    return client;
};
exports.sendFile = function (host, port, password, source, target) {
    var c = exports.connect(host, port, password, null, function () {
        c.sendFile(source, target, false, function () {
            destroyClient(c);
            c.unref();
        });
    });
    return c;
};
function reconnect() {
    return exports.connect.apply(exports, this.argumentsCache);
}
function sendFile(source, target, inNewConnection, callback) {
    var c = this;

    if (c.destroyed) {
        console.log('Connection has closed.');
        return false;
    } 
    if (!c.getUserData('secret')) return;
    if (!inNewConnection) {
        writePackage(c, {
            type: ptypes.UPLOAD,
            file: {
                source: source,
                target: target
            }
        });
        c.on(events.FILE_WRITING_FINISHED, function (info) {
            typeof callback === 'function' && callback({source: source, target: target});
        });
    } else {
        var client = exports.connect(c.argumentsCache[0], c.argumentsCache[1], c.argumentsCache[2], c.token, function () {
            client.sendFile(source, target);
        });
        client._userData.secret = c._userData.secret;

        client.on(events.FILE_WRITING_FINISHED, function (info) {
            console.log('Close connection due to file sent finished'.bgGreen.white, info.source + ' -> ' + info.target);
            'tempPath' in info && unlinkTempFile(info.tempPath);

            destroyClient(client);
            client.unref();
            
            typeof callback === 'function' && callback({source: source, target: target});
        });
    }
    return true;
}

/**
 * initializes a socket's state
 */
function prepareSocket(c) {
    L.init(c);

    c.hmacRandomBytes = getRandomBytes(16);
    assert(c.hmacRandomBytes.length, 16);
    /* Handling data buffer. All the coming bytes belongs
     * to a new package are cached here. It's not a complete package.
     */
    c.incomingPackage = new Buffer(0);

    /* Set this to null to wait for a new package( e.g. before starting to receive a new package) */
    c.incomingPackageHeader = null;

    c.incomingPackageBodyLength = -1;

    /* package || file */
    c.incomingPackageBodyMode = 'package';
    
    /* Records how many bytes received when body mode is 'file' */
    c.incomingPackageBodyReceived = 0;
    
    /* a writeable stream */
    c.incomingPackageFd = null;

    c.getUserData = function (key, dft) {
        return key in c._userData ? c._userData[key] : dft;
    };

    /* sendFile method */
    c.sendFile = sendFile;
    c.reconnect = reconnect;

    c.pendingIncomingPackages = [];

    c.error = function (message) {
        console.log('ERROR'.bgRed.white, message);
        c.pause();
        destroyClient(c);
    };
}
function onEnd() {
    console.log('topEnd');
    destroyClient(this);
}
function onData(data) {
    var c = this;
    /* save data to buffer */
    c.incomingPackage = Buffer.concat([c.incomingPackage, data]);

    processHeader();

    function processHeader() {
        /* 80 bits header */
        if (c.incomingPackageHeader === null) {
            /* 8 bits version + 8 bits type + 64 bits body length = 10 bytes */
            if (c.incomingPackage.length > 10) {
                c.incomingPackageHeader = c.incomingPackage.slice(0, 10);
                c.incomingPackage = c.incomingPackage.slice(10);

                /* reads package type */
                if (c.incomingPackageHeader.readInt8(1) === ptypes.UPLOAD) {
                    if (!(c.token in clients)) return requestError(c, 'Auth requested');
                    c.incomingPackageBodyMode = 'file';
                    c.incomingPackageBodyReceived = 0;
                } else {
                    c.incomingPackageBodyMode = 'package';
                }

                c.incomingPackageFd = null;
                c.incomingPackageBodyLength = new Int64(c.incomingPackageHeader.slice(2)).toNumber();
                console.log('Receiving a package with length ' + c.incomingPackageBodyLength);

                return processBody();
            } else {
                return false;
            }
        } else {
            return processBody();
        }
    }

    function processBody() {
        if (c.incomingPackageBodyMode === 'file') {
            if (c.incomingPackageFd === null) {
                var filePathIndex = c.incomingPackage.toString().indexOf('\r'),
                            filePath;
                if (filePathIndex !== -1) {
                    filePath = c.incomingPackage.toString().substr(0, filePathIndex);
                    console.log('Start receiving file:'.bgBlack.white, filePath);
                    var atenCount = new Buffer(filePath + '\r').length;
                    c.incomingPackageBodyReceived += atenCount;
                    c.incomingPackage = c.incomingPackage.slice(atenCount);
                    // TODO: path check
                    if (path.dirname(filePath).indexOf('.') !== -1) return requestError(c, 'Invalid file path');
                    var realPath = path.join(config.ROOT, filePath) + '.downloading',
                        fileStream;
                    util.mkdirpSync(path.dirname(realPath));
                    fileStream = fs.createWriteStream(realPath);
                    c.incomingPackageFd = crypto.createDecipher(config.CIPHER_ALGORITHM, clients[c.token]);
                    c.incomingPackageFd
                        .on('error', function (err) {
                            requestError(c, err.message);
                            //c.error(err.message);
                        })
                        .pipe(fileStream);
                    fileStream.on('finish', function () {
                        fileWriteFinished(c, realPath);
                    });

                    return processBody();
                }
            } else {
                /* package end */
                if (c.incomingPackage.length + c.incomingPackageBodyReceived >= c.incomingPackageBodyLength) {
                    var endIndex = c.incomingPackageBodyLength - c.incomingPackageBodyReceived,
                        tmp = c.incomingPackage.slice(0, endIndex);
                    c.incomingPackage = c.incomingPackage.slice(endIndex);
                    c.incomingPackageFd.end(tmp);

                    c.incomingPackageHeader = null;
                    return processHeader();
                } else {
                    c.incomingPackageFd.write(c.incomingPackage);
                    c.incomingPackageBodyReceived += c.incomingPackage.length;
                    c.incomingPackage = new Buffer(0);
                }
            }
        } else {
            
            if (c.incomingPackage.length >= c.incomingPackageBodyLength) {
                c.pendingIncomingPackages.push(createPackage({
                    header: c.incomingPackageHeader,
                    body: c.incomingPackage.slice(0, c.incomingPackageBodyLength)
                }));
                c.incomingPackage = c.incomingPackage.slice(c.incomingPackageBodyLength);

                consumePackage(c);

                c.incomingPackageHeader = null;
                return processHeader();
            }
        }
    }
}
function fileWriteFinished(socket, filePath) {
    console.log('File write finished'.bgGreen.white, filePath);
    fs.rename(filePath, filePath.substr(0, filePath.lastIndexOf('.downloading')), function() {});
}
/**
 * Handles pending packages
 */
function consumePackage(c) {
    while (c.pendingIncomingPackages.length > 0) {
        var pkg = c.pendingIncomingPackages.shift();
        switch (pkg.type) {
            /** 服务器发来的需要验证的随机字节 */
            case ptypes.AUTH.RANDOM_BYTES:
                console.log('calculating handshake hmac...');
                var hmac = crypto.createHmac(config.HMAC_ALGORITHM, c.getUserData('hmac_key') || config.HMAC_KEY);
                hmac.update(pkg.content);
                var buf = hmac.digest();
                console.log('hmac verification sent'.bgBlack.white, buf.toString('hex').green);

                if (c.preToken) {
                    writePackage(c, {
                        type: ptypes.AUTH.SET_TOKEN,
                        content: Buffer.concat([buf, c.preToken])
                    });
                } else {
                    writePackage(c, {
                        type: ptypes.AUTH.VERIFY,
                        content: buf
                    });
                }
                break;
            case ptypes.AUTH.PUBLIC_KEY:
                c._userData.serverPublicKey = pkg.content;
                writePackage(c, {
                    type: ptypes.AUTH.EXCHANGE_PUBLIC_KEY,
                    content: hellman.getPublicKey()
                });
                break;
            case ptypes.AUTH.SET_TOKEN:
            case ptypes.AUTH.VERIFY:
                var hmac = crypto.createHmac(config.HMAC_ALGORITHM, config.HMAC_KEY);
                hmac.update(c.hmacRandomBytes);

                var localHmac = hmac.digest('hex'),
                    remoteHmac = pkg.body.toString('hex'), token;
                if (pkg.type === ptypes.AUTH.SET_TOKEN) {
                    token = remoteHmac.substr(localHmac.length);
                    remoteHmac = remoteHmac.substr(0, localHmac.length);
                }
                if (localHmac !== remoteHmac) return requestError(c, 'Auth failed');

                c.verified = true;
                console.log('hmac verification succeed'.bgBlack.white);

                if (token) {
                    if (!(token in clients)) return requestError(c, 'Token failed');
                    c.token = token;
                    writePackage(c, {
                        type: ptypes.AUTH.TOKEN_SET,
                        content: '1'
                    });
                } else sendPublicKey(c);
                break;
            case ptypes.AUTH.EXCHANGE_PUBLIC_KEY:
                if (!c.verified) return requestError(c, 'Auth not passed');
                var token = generateToken();
                clients[token.toString('hex')] = hellman.computeSecret(pkg.body);
                c.token = token.toString('hex');
                writePackage(c, {
                    type: ptypes.AUTH.PUBLIC_KEY_RECEIVED,
                    content: token
                });
                break;
            case ptypes.AUTH.PUBLIC_KEY_RECEIVED:
                c._userData.secret = hellman.computeSecret(c.getUserData('serverPublicKey'));
                c.token = pkg.content;
                console.log('Publick key received'.bgBlack.white);
                c.emit('handshake');
                break;
            case ptypes.AUTH.TOKEN_SET:
                c.emit('handshake');
                break;
            case ptypes.ERROR:
                console.log('Error'.bgRed.white, pkg.content.toString());
                break;
        }
    }
}
function sendPublicKey(c) {
    writePackage(c, {
        type: ptypes.AUTH.PUBLIC_KEY,
        content: hellman.getPublicKey()
    });
    console.log('Public key sent'.bgBlack.white, hellman.getPublicKey().toString('hex'));
}
function writePackage(c, pkg) {
    L.append(c, pkg);
    processWriting(c);
}
function processWriting(c) {
    if (c._isWriting || c.destroyed) return;
    if (L.isEmpty(c)) return c._isWriting = false;

    c._isWriting = true;
    var pkg = L.shift(c), buf;
    if (pkg.type === ptypes.CLOSE) return c.end();
    /* writes version */
    buf = new Buffer(2);
    buf.writeUInt8(config.PROTOCOL_VERSION, 0);
    /* writes package type */
    buf.writeUInt8(pkg.type, 1);
    c.write(buf);
    /* writes body length and body */
    if (pkg.content) {
        if (typeof pkg.content === 'string')
            pkg.content = new Buffer(pkg.content);
        c.write((new Int64(pkg.content.length)).buffer);
        c.write(pkg.content);

        c._isWriting = false;
        processWriting(c);
    } else if (pkg.file) {
        // TODO: We should implement stream package for large file transmission
        var 
            stream     = fs.createReadStream(pkg.file.source),
            tempPath   = getTempFile(),
            tempStream = fs.createWriteStream(tempPath);

        var cipher = crypto.createCipher(config.CIPHER_ALGORITHM, c.getUserData('secret'));

        console.log('Start to encrypt file...'.bgBlack.white, pkg.file.source, '->', pkg.file.target);

        /**
         * If we can calculate the size of encrypted file,
         * everthing will be easier.
         */
        if ('CIPHER_BLOCK_SIZE' in config) {
            console.log('known cipher_block');
            var fileSize = fs.statSync(pkg.file.source).size;
            fileSize = Math.ceil(fileSize / config.CIPHER_BLOCK_SIZE) * config.CIPHER_BLOCK_SIZE;
            c.write((new Int64(fileSize + (new Buffer(pkg.file.target + '\r')).length)).buffer);
            c.write(pkg.file.target + '\r');

            var timerFunc = function (completed) {
                var written = (c.bytesWritten / (currentWritten + fileSize)),
                    _now = + new Date;
                if (written < 1 || completed) {
                    console.log((written * 100).toFixed(2) + '% sent, avg speed: ' + formatSize( (c.bytesWritten - currentWritten) / ((_now - now) / 1000)) + '/s');
                }
            };

            var currentWritten = c.bytesWritten,
                now = + new Date,
                timer = setInterval(timerFunc, 1000);
            stream
                .pipe(cipher)
                    .on('end', function () {
                        clearInterval(timer);
                        timerFunc(1);
                        c._isWriting = false;
                        cipher.unpipe(c);
                        c.emit(events.FILE_WRITING_FINISHED, {source: pkg.file.source, target: pkg.file.target});
                        processWriting(c);
                        
                    })
                    .pipe(c, {end: false})
                        .on('end', function () {
                            console.log('client socket ends.');
                        });

            return;
        }
        stream.pipe(cipher).pipe(tempStream);
        tempStream.on('close', function () {
            console.log('File encrypted.'.bgGreen.white);
            var fileSize = fs.statSync(tempPath).size;
            /** Writes package length */
            c.write((new Int64(fileSize + (new Buffer(pkg.file.target + '\r')).length)).buffer);
            /** Writes file name */
            c.write(pkg.file.target + '\r');
            /** Writes file content */
            tempStream = fs.createReadStream(tempPath);
            tempStream.on('end', function () {
                console.log('Finished file writing'.bgGreen.white, pkg.file.source, '->', pkg.file.target);
                c._isWriting = false;
                c.emit(events.FILE_WRITING_FINISHED, {source: pkg.file.source, target: pkg.file.target, tempPath: tempPath});
                processWriting(c);                
            });
            console.log('About to write file...'.bgBlack.white, pkg.file.source, '->', pkg.file.target);
            /* Do not close socket after writing file */
            tempStream.pipe(c, {end: false});
        });
    } else {
        throw new Error('Package must have content or stream property.');
    }
}
/**
 * Try to generate random bytes at most limit attempts
 */
function getRandomBytes(length, limit, count) {
    limit = limit || 3;
    count = count || 0;
    count++;
    try {
        return crypto.randomBytes(length, limit, count);
    } catch (ex) {
        if (count <= limit) return getRandomBytes(length, limit, count);
        else throw ex;
    }
}
/**
 * @returns {Buffer} random bytes with md5
 */
function generateToken() {
    var md5 = crypto.createHash('md5');
    md5.update(+ new Date + '' + Math.random());
    return md5.digest();
}
function requestError(c, msg) {
    console.trace('ERROR'.bgRed.white, msg);
    writePackage(c, {
        type: ptypes.ERROR,
        content: msg
    });
    writePackage(c, {
        type: ptypes.CLOSE
    });
}
function assert(real, except) {
    if (real !== except) throw Error('Assert failed: ' + real + ' !== ' + except);
}
function createPackage(obj) {
    if (!obj.type) {
        obj.type = obj.header.readInt8(1);
    }
    if (!obj.body && obj.content) obj.body = obj.content;
    if (!obj.content && obj.body) obj.content = obj.body;
    return obj;
}
function formatSize(bytes) {
    var type = ['B', 'KB', 'MB', 'GB'],
        index = 0;
    while (index < type.length && bytes >= 1024) {
        bytes = bytes / 1024;
        index++;
    }
    return bytes.toFixed(2) + type[index];
}
function destroyClient(c) {
    if (!c.destroyed) {
        try {
            c.end();
        } catch (ex) {}
    }
    c.destroyed = true;
    //delete clients[c.token];
}

var tempFiles = [];
function getTempFile() {
    var p = path.join(os.tmpdir(), '' + Date.now() + parseInt(Math.random() * 10000));
    tempFiles.push(p);
    return p;
}
function unlinkTempFiles() {
    var file;
    while (file = tempFiles.shift()) {
        console.log(file, 'deleted');
        fs.unlinkSync(file);
    }
}
function unlinkTempFile(p) {
    var i = tempFiles.indexOf(p);
    if (i === -1) return false;
    fs.unlinkSync(tempFiles[i]);
    return !0;
}
process.on('error', function (e) {
    console.error(e);
});
process.on('exit', function (code) {
    unlinkTempFiles();
    if(fs.existsSync(cst.RUNNING_PROCESS)) {
        var runningProcess = fs.readFileSync(cst.RUNNING_PROCESS).toString('utf-8').split('\n'),
            i = runningProcess.indexOf(process.pid);
        if (i !== -1) {
            runningProcess = runningProcess.splice(i, 1);
            fs.writeFileSync(cst.RUNNING_PROCESS, runningProcess.join('\n'));
        }
    }
});

program.parse(process.argv);