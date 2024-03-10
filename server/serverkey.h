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



/*
encrypt serverkey (aes-256-cbc, base64)
key : WJS+rQbsKcj25pZtWutFbbkbbGGxOxgP533MpaFB2SU=
iv  : y4dwVIamgOkXojBYPDz3Tg==
*/

/*
char server_privatekey_socks5[] = "PqWHENzaYIeMfCAafKcOLxxXNAFXyzfzD/tcTnmrGXtpkj8M2Y4qpLdLo83NSMhNAO+FvAZSM/VnNhNGO15u1/TBPn8CT+QiUnbn4vN2284jHPMgZ+8ya+pM57Avf7u8rkLShTuAlQQzbcouazIaqu5Bw5wH6YvCKayrWsw5EUd/vb8EfTpybJD8IVpArpL42CyVyQ2hUdj/3vHceDhkzeAsHseLFmxh3k2xMpBAktA9rgnJcf/VBeRjRY3iX/Bm0INNyoBE6IGxSw/F+ayKnRUy/dN0wdUNHY1RLwBWDsYZqdS72LyC5EIVFTuBMOaTi80ICGeM/n10u9PXOhTxBg==";

char server_certificate_socks5[] = "9e4qtUjmq8FnTV0kitaM1HSXv+ECm6w9Ezq1saMkj1T6nJVu6jIGudIeGIwGNmBXhVb6stJBt2ooQJrqNbqhtaff1eLY2daGYNqA/GQMe/4jV+c7ZHH9h5iLCfoAU58msLiu7w3J9Kl+D686Q97mfdYhUXfoRkPN85CsZfYIAP21JYy5lLN09ADAgOUTJ2o+mVJkxnQI6zN1reqF68ArubK9dVxkeQOlNxaY+0MwBp62btxX48ScmoDFB1e1M4C3laPW3ZCBhV/Hndeh3sQG/VXUnKO+R/UeIfo7nK3308WDr/byzsJ2h/DuJ4c81HSCkDCYmy52gbZClCZA8xw6B9XRJPmXe2qpjoGmJ13nQmvxcJOvF6XAeFzmSS9Vuadd2FiNbVsy2n2KnStPzkcH96grr5LQR6LuNd4ofroqmukL9EadI7kXp7+DVjXujiG1iR+PNMxUv3ngIuhX7j52bVgXGH5ekPhRqFjJ4MWmhIDLFFgKAn71nsnHfLq/6YSGNeBqDy/vyhIo/RmtxaVAegtxZoZ+Zr++7ZM4sBLrA9VbJ3KVfEdyvCGFL7ZJDxgcIOoexkf3BW4iQSgIE5WlJADh7bsXgIOlJ9N+GDSFG86OjZuiaDjrzbe9eQZlyDODAcEanDLnP68+3WOE7M+zuOFrt53uCb2M7f+YkcCxOYH4TaAo7d4gSJPCYQNyQz/rzqXO3gXD2l9e+Tx4koXZgss4JABdSAADrkHev2U11Oxayoi5yU7MhgclXTQnj1RdLf2kMRNG227hC0Y07dlbSg==";
*/

