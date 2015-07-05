/// <reference path="../../typings/tsd.d.ts" />
import Q = require('q');
declare class CertificateAuthority {
    private countryName;
    private stateOrProvinceName;
    private organizationName;
    private commonName;
    private verbose;
    private static configFile;
    private static randFile;
    private static keyDir;
    private keyFile;
    private caCertFile;
    private _caCertificate;
    caCertificate: Q.Promise<CertificateAuthority.CACertificate>;
    /**
     * countryName: Country Name (2 letter code)
     * stateOrProvinceName: State or Province Name (full name)
     * organizationName: Organization Name (eg, company)
     * commonName: Common Name (e.g. server FQDN or YOUR name)
     * verbose: Redirect print OpenSSL stdout and stderr
     */
    constructor(countryName: string, stateOrProvinceName: string, organizationName: string, commonName: string, verbose?: boolean);
    private _sign(commonName, subjectAltName?);
    sign(commonName: string, subjectAltName?: string): Q.Promise<string>;
}
declare module CertificateAuthority {
    interface CACertificate {
        privateKey: string;
        certificate: string;
    }
}
export = CertificateAuthority;
