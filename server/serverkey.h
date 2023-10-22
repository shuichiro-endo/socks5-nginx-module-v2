/*
 * Title:  socks5 server key header (nginx module)
 * Author: Shuichiro Endo
 */

/*
openssl ecparam -genkey -name prime256v1 -out server-key-pair.pem
openssl ec -in server-key-pair.pem -text -noout

openssl ec -in server-key-pair.pem -outform PEM -out server-private.pem
cat server-private.pem | sed -e 's/^/"/g' -e 's/$/\\n"\\/g' -e 's/"-----END EC PRIVATE KEY-----\\n"\\/"-----END EC PRIVATE KEY-----\\n";/g'

openssl ec -in server-key-pair.pem -outform PEM -pubout -out server-public.pem
cat server-public.pem | sed -e 's/^/"/g' -e 's/$/\\n"\\/g' -e 's/"-----END PUBLIC KEY-----\\n"\\/"-----END PUBLIC KEY-----\\n";/g'

openssl req -new -sha256 -key server-key-pair.pem -out server.csr
openssl req -text -noout -in server.csr
openssl x509 -days 3650 -req -signkey server-private.pem < server.csr > server.crt
openssl x509 -text -noout -in server.crt
cat server.crt | sed -e 's/^/"/g' -e 's/$/\\n"\\/g' -e 's/"-----END CERTIFICATE-----\\n"\\/"-----END CERTIFICATE-----\\n";/g'
*/


char server_privatekey_socks5[] = "-----BEGIN EC PRIVATE KEY-----\n"\
"MHcCAQEEIPAB7VXkdlfWvOL1YKr+cxGLhx69g/eqUjncU1D9hkUdoAoGCCqGSM49\n"\
"AwEHoUQDQgAErAWMtToIcsL5fGF+DKZhMRy9m1WR3ViC7nrLokou9A/TMPr2DMz9\n"\
"O7kldBsGkxFXSbXcUfjk6wyrgarKndpK0A==\n"\
"-----END EC PRIVATE KEY-----\n";

char server_certificate_socks5[] = "-----BEGIN CERTIFICATE-----\n"\
"MIIBhTCCASsCFB47Pqx2Ko4ZXD5bCsGaaTP1Zjh8MAoGCCqGSM49BAMCMEUxCzAJ\n"\
"BgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5l\n"\
"dCBXaWRnaXRzIFB0eSBMdGQwHhcNMjMwMTE1MTIwODA3WhcNMzMwMTEyMTIwODA3\n"\
"WjBFMQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwY\n"\
"SW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcD\n"\
"QgAErAWMtToIcsL5fGF+DKZhMRy9m1WR3ViC7nrLokou9A/TMPr2DMz9O7kldBsG\n"\
"kxFXSbXcUfjk6wyrgarKndpK0DAKBggqhkjOPQQDAgNIADBFAiEAqknImSukXNY+\n"\
"fkuuFbDFkte9mZM3Xy/ArE7kDIMt4nwCIHdlJRn0Cf18VQbpLessgklsk/gX59uo\n"\
"jrsksbPHQ50h\n"\
"-----END CERTIFICATE-----\n";

