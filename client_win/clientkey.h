/*
 * Title:  socks5 client key header (nginx module)
 * Author: Shuichiro Endo
 */

/*
openssl req -x509 -days 3650 -nodes -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -subj /CN=localhost -outform PEM -keyout client_socks5_private.key -out client_socks5.crt
openssl x509 -text -noout -in client_socks5.crt
cat client_socks5_private.key | sed -e 's/^/"/g' -e 's/$/\\n"\\/g' -e 's/"-----END PRIVATE KEY-----\\n"\\/"-----END PRIVATE KEY-----\\n";/g'
cat client_socks5.crt | sed -e 's/^/"/g' -e 's/$/\\n"\\/g' -e 's/"-----END CERTIFICATE-----\\n"\\/"-----END CERTIFICATE-----\\n";/g'
*/


char client_privatekey_socks5[] = "-----BEGIN PRIVATE KEY-----\n"\
"MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgVlI3ePznE9rDgA8t\n"\
"89jlF1ycGs3NRZxENRO3wuPvKkuhRANCAASTnYHeV4BiCybI7xQyOSS24I6np6bp\n"\
"i4rXxqVammICpvBiYNJMACzWlUUeGtFBAQzOcUim9zf9cDq/nW9o1jEg\n"\
"-----END PRIVATE KEY-----\n";

char client_certificate_socks5[] = "-----BEGIN CERTIFICATE-----\n"\
"MIIBfjCCASOgAwIBAgIUJGmCvAtce4aM07rJQ3ZzS2HTZkgwCgYIKoZIzj0EAwIw\n"\
"FDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI0MDIxOTIyMTMzMFoXDTM0MDIxNjIy\n"\
"MTMzMFowFDESMBAGA1UEAwwJbG9jYWxob3N0MFkwEwYHKoZIzj0CAQYIKoZIzj0D\n"\
"AQcDQgAEk52B3leAYgsmyO8UMjkktuCOp6em6YuK18alWppiAqbwYmDSTAAs1pVF\n"\
"HhrRQQEMznFIpvc3/XA6v51vaNYxIKNTMFEwHQYDVR0OBBYEFMcnL1L1q2KPB+7f\n"\
"4eJDoRtGxo+/MB8GA1UdIwQYMBaAFMcnL1L1q2KPB+7f4eJDoRtGxo+/MA8GA1Ud\n"\
"EwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSQAwRgIhAKZLK9oM8NbY1RMUb4LnWpIJ\n"\
"CZJbhZeupqlLaJOh9tmwAiEArEyZm8JkP0VodyQ5k/9kbOiKpwBwGseMh3UHLUb+\n"\
"jhM=\n"\
"-----END CERTIFICATE-----\n";

