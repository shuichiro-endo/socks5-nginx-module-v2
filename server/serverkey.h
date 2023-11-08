/*
 * Title:  socks5 server key header (nginx module)
 * Author: Shuichiro Endo
 */

/*
openssl req -x509 -days 3650 -nodes -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -subj /CN=localhost -outform PEM -keyout server_socks5_private.key -out server_socks5.crt
openssl x509 -text -noout -in server_socks5.crt
cat server_socks5_private.key | sed -e 's/^/"/g' -e 's/$/\\n"\\/g' -e 's/"-----END PRIVATE KEY-----\\n"\\/"-----END PRIVATE KEY-----\\n";/g'
cat server_socks5.crt | sed -e 's/^/"/g' -e 's/$/\\n"\\/g' -e 's/"-----END CERTIFICATE-----\\n"\\/"-----END CERTIFICATE-----\\n";/g'
*/


char server_privatekey_socks5[] = "-----BEGIN PRIVATE KEY-----\n"\
"MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgpEIBK1hhvc+HVJRk\n"\
"QfpifIMOPxLIRJovTxjhFlnHJLihRANCAAQndxVggZiwxAQoi8ZysOmtC4U3Ufrx\n"\
"skaIMBrDIi3Myanw8NtNaVaW/CzdzeG+U5sWx5IFA4iHyhOSp2hxi1Uo\n"\
"-----END PRIVATE KEY-----\n";

char server_certificate_socks5[] = "-----BEGIN CERTIFICATE-----\n"\
"MIIBfjCCASOgAwIBAgIUWg2F5a7tuHBZcOuOQmQp7A9YEw8wCgYIKoZIzj0EAwIw\n"\
"FDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTIzMTEwODA3NTI0OFoXDTMzMTEwNTA3\n"\
"NTI0OFowFDESMBAGA1UEAwwJbG9jYWxob3N0MFkwEwYHKoZIzj0CAQYIKoZIzj0D\n"\
"AQcDQgAEJ3cVYIGYsMQEKIvGcrDprQuFN1H68bJGiDAawyItzMmp8PDbTWlWlvws\n"\
"3c3hvlObFseSBQOIh8oTkqdocYtVKKNTMFEwHQYDVR0OBBYEFBRxce8YQWc4Z1Dc\n"\
"vBgZndjGdTceMB8GA1UdIwQYMBaAFBRxce8YQWc4Z1DcvBgZndjGdTceMA8GA1Ud\n"\
"EwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSQAwRgIhALIk//w4qN3Q4iVCyNgTeP1Z\n"\
"SpiWrOcI+QYFQfgBSbAmAiEA34doDamtu1nhZXz6gka0ImX9I11HZiELVHlT3/BT\n"\
"0pY=\n"\
"-----END CERTIFICATE-----\n";

