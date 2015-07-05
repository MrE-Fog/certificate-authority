/// <reference path="../typings/tsd.d.ts"/>
var childProcess = require('child_process');
var util = require('util');
var fs = require('fs');
var mkdirp = require('mkdirp');
var Q = require('q');
var CertificateAuthority = (function () {
    /**
     * countryName: Country Name (2 letter code)
     * stateOrProvinceName: State or Province Name (full name)
     * organizationName: Organization Name (eg, company)
     * commonName: Common Name (e.g. server FQDN or YOUR name)
     * verbose: Redirect print OpenSSL stdout and stderr
     */
    function CertificateAuthority(countryName, stateOrProvinceName, organizationName, commonName, verbose) {
        var _this = this;
        this.countryName = countryName;
        this.stateOrProvinceName = stateOrProvinceName;
        this.organizationName = organizationName;
        this.commonName = commonName;
        this.verbose = verbose;
        this._caCertificate = Q.nfcall(mkdirp, CertificateAuthority.keyDir).then(function () {
            return Q.all([
                Q.nfcall(fs.stat, _this.keyFile),
                Q.nfcall(fs.stat, _this.caCertFile)
            ]);
        }).catch(function () {
            var req = childProcess.spawn('openssl', [
                'req',
                '-newkey',
                'rsa:2048',
                '-sha256',
                '-subj',
                util.format('/C=%s/ST=%s/O=%s/CN=%s', _this.countryName, _this.stateOrProvinceName, _this.organizationName, _this.commonName),
                '-nodes',
                '-keyout',
                _this.keyFile
            ], { stdio: verbose ? [null, null, process.stderr] : null });
            var sign = childProcess.spawn('openssl', ['x509', '-req', '-signkey', _this.keyFile, '-out', _this.caCertFile], { stdio: verbose ? [null, process.stdout, process.stderr] : null });
            req.stdout.pipe(sign.stdin);
            return Q.Promise(function (resolve, reject) {
                req.on('close', function (code) {
                    if (code != 0) {
                        reject(new Error('CA request process exited with code ' + code));
                    }
                });
                sign.on('close', function (code) {
                    if (code == 0) {
                        resolve(code);
                    }
                    else {
                        reject(new Error('CA signing process exited with code ' + code));
                    }
                });
            });
        }).then(function () {
            return [
                Q.nfcall(fs.readFile, _this.keyFile),
                Q.nfcall(fs.readFile, _this.caCertFile)
            ];
        }).spread(function (privateKey, certificate) {
            return {
                privateKey: '' + privateKey,
                certificate: '' + certificate
            };
        });
    }
    Object.defineProperty(CertificateAuthority.prototype, "keyFile", {
        get: function () {
            return CertificateAuthority.keyDir + this.commonName + '-key.pem';
        },
        enumerable: true,
        configurable: true
    });
    Object.defineProperty(CertificateAuthority.prototype, "caCertFile", {
        get: function () {
            return CertificateAuthority.keyDir + this.commonName + '-CA-cert.pem';
        },
        enumerable: true,
        configurable: true
    });
    Object.defineProperty(CertificateAuthority.prototype, "caCertificate", {
        get: function () {
            return this._caCertificate;
        },
        enumerable: true,
        configurable: true
    });
    CertificateAuthority.prototype._sign = function (commonName, subjectAltName) {
        var reqArgs = [
            'req',
            '-new',
            '-sha256',
            '-subj',
            util.format('/C=%s/ST=%s/O=%s/CN=%s', this.countryName, this.stateOrProvinceName, this.organizationName, commonName),
            '-key',
            this.keyFile
        ];
        var req = childProcess.spawn('openssl', reqArgs, {
            stdio: this.verbose ? [null, null, process.stderr] : null
        });
        var signArgs = [
            'x509',
            '-req',
            '-CAcreateserial',
            '-CA',
            this.caCertFile,
            '-CAkey',
            this.keyFile
        ];
        if (subjectAltName) {
            signArgs.push('-extfile', CertificateAuthority.configFile);
        }
        var sign = childProcess.spawn('openssl', signArgs, {
            env: { RANDFILE: CertificateAuthority.randFile, SAN: subjectAltName },
            stdio: this.verbose ? [null, null, process.stderr] : null
        });
        req.stdout.pipe(sign.stdin);
        var certificate = '';
        sign.stdout.on('data', function (data) {
            certificate += data;
        });
        return Q.Promise(function (resolve, reject) {
            req.on('close', function (code) {
                if (code != 0) {
                    reject(new Error('Generating request process exited with code ' + code));
                }
            });
            sign.on('close', function (code) {
                if (code == 0) {
                    resolve(certificate);
                }
                else {
                    reject(new Error('Signing process exited with code ' + code));
                }
            });
        });
    };
    CertificateAuthority.prototype.sign = function (commonName, subjectAltName) {
        var _this = this;
        return this._caCertificate.then(function (caCertificate) {
            return _this._sign(commonName, subjectAltName);
        });
    };
    CertificateAuthority.configFile = 'ssl/openssl.cnf';
    CertificateAuthority.randFile = 'ssl/.rnd';
    CertificateAuthority.keyDir = 'keys/';
    return CertificateAuthority;
})();
module.exports = CertificateAuthority;
