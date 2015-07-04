/// <reference path="../typings/node/node.d.ts"/>
/// <reference path="../typings/mkdirp/mkdirp.d.ts"/>
/// <reference path="../typings/q/Q.d.ts"/>

import childProcess = require('child_process');
import util = require('util');
import fs = require('fs');

import mkdirp = require('mkdirp');
import Q = require('q');

class CertificateAuthority {

    private static configFile = 'ssl/openssl.cnf';
    private static randFile = 'ssl/.rnd';
    private static keyDir = 'keys/';

    private get keyFile(): string {
        return CertificateAuthority.keyDir + this.commonName + '-key.pem';
    }

    private get caCertFile(): string {
        return CertificateAuthority.keyDir + this.commonName + '-CA-cert.pem';
    }

    private _caCertificate: Q.Promise<CertificateAuthority.CACertificate>;

    get caCertificate(): Q.Promise<CertificateAuthority.CACertificate> {
        return this._caCertificate;
    }

    /**
     * countryName: Country Name (2 letter code)
     * stateOrProvinceName: State or Province Name (full name)
     * organizationName: Organization Name (eg, company)
     * commonName: Common Name (e.g. server FQDN or YOUR name)
     * verbose: Redirect print OpenSSL stdout and stderr
     */
    constructor(
        private countryName: string,
        private stateOrProvinceName: string,
        private organizationName: string,
        private commonName: string,
        private verbose?: boolean) {

        this._caCertificate = Q.nfcall(mkdirp, CertificateAuthority.keyDir).then(() => {
            return Q.all([
                Q.nfcall(fs.stat, this.keyFile),
                Q.nfcall(fs.stat, this.caCertFile)
            ])
        }).catch(() => {

            var req = childProcess.spawn('openssl',
                [
                    'req', '-newkey', 'rsa:2048', '-sha256',
                    '-subj', util.format('/C=%s/ST=%s/O=%s/CN=%s',
                        this.countryName,
                        this.stateOrProvinceName,
                        this.organizationName,
                        this.commonName),
                    '-nodes', '-keyout', this.keyFile
                ], { stdio: verbose ? [null, null, process.stderr] : null });

            var sign = childProcess.spawn('openssl',
                ['x509', '-req', '-signkey', this.keyFile, '-out', this.caCertFile],
                { stdio: verbose ? [null, process.stdout, process.stderr] : null });

            req.stdout.pipe(sign.stdin);

            return Q.Promise((resolve, reject) => {
                req.on('close', (code) => {
                    if (code != 0) {
                        reject(new Error(
                            'CA request process exited with code ' + code));
                    }
                });

                sign.on('close', (code) => {
                    if (code == 0) {
                        resolve(code);
                    } else {
                        reject(new Error(
                            'CA signing process exited with code ' + code));
                    }
                });
            });

        }).then(() => {
            return [
                Q.nfcall(fs.readFile, this.keyFile),
                Q.nfcall(fs.readFile, this.caCertFile)
            ];
        }).spread<CertificateAuthority.CACertificate>((privateKey, certificate) => {
            return {
                privateKey: '' + privateKey,
                certificate: '' + certificate
            };
        });
    }

    private _sign(commonName: string, subjectAltName?: string): Q.Promise<string> {

        var reqArgs = [
            'req', '-new', '-sha256',
            '-subj', util.format('/C=%s/ST=%s/O=%s/CN=%s',
                this.countryName,
                this.stateOrProvinceName,
                this.organizationName,
                commonName),
            '-key', this.keyFile
        ]

        var req = childProcess.spawn('openssl', reqArgs, {
            stdio: this.verbose ? [null, null, process.stderr] : null
        });

        var signArgs = [
            'x509', '-req', '-CAcreateserial',
            '-CA', this.caCertFile,
            '-CAkey', this.keyFile
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
        sign.stdout.on('data', (data) => { certificate += data; });

        return Q.Promise<string>((resolve, reject) => {
            req.on('close', (code) => {
                if (code != 0) {
                    reject(new Error(
                        'Generating request process exited with code ' + code));
                }
            });

            sign.on('close', (code) => {
                if (code == 0) {
                    resolve(certificate);
                } else {
                    reject(new Error(
                        'Signing process exited with code ' + code));
                }
            });
        });
    }

    sign(commonName: string, subjectAltName?: string): Q.Promise<string> {
        return this._caCertificate.then((caCertificate) => {
            return this._sign(commonName, subjectAltName);
        });
    }
}

module CertificateAuthority {
    export interface CACertificate {
        privateKey: string;
        certificate: string;
    }
}

export = CertificateAuthority;