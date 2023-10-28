/*
 * Title:  ntlm header
 * Author: Shuichiro Endo
 */

/*
 * Reference:
 * https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/b38c36ed-2804-4868-a9ff-8dd3182128e4
 */

#ifndef NTLM_H
#define NTLM_H

/*
 * Reference:
 * https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/83f5e789-660d-4781-8491-5f8c6641f75e
 */
#define MsvAvEOL                0x0000
#define MsvAvNbComputerName     0x0001
#define MsvAvNbDomainName       0x0002
#define MsvAvDnsComputerName    0x0003
#define MsvAvDnsDomainName      0x0004
#define MsvAvDnsTreeName        0x0005
#define MsvAvFlags              0x0006
#define MsvAvTimestamp          0x0007
#define MsvAvSingleHost         0x0008
#define MsvAvTargetName         0x0009
#define MsvAvChannelBindings    0x000A

struct av_pair
{
    uint16_t av_id;
    uint16_t av_len;
    char value;
    // variable
};


/*
 * Reference:
 * https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/f221c061-cc40-4471-95da-d2ff71c85c5b
 */
struct single_host_data
{
    uint32_t size;
    int32_t z4;
    unsigned char custom_data[8];
    unsigned char machine_id[32];
};


/*
 * Reference:
 * https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/e3fee6d1-0d93-4020-84ab-ca4dc5405fc9
 */
struct lm_response
{
    unsigned char response[24];
};


/*
 * Reference:
 * https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/8659238f-f5a9-44ad-8ee7-f37d3a172e56
 */
struct lmv2_response
{
    unsigned char response[16];
    unsigned char challenge_from_client[8];
};


/*
 * Reference:
 * https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/99d90ff4-957f-4c8a-80e4-5bfe5a9a9832
 */
struct negotiate_flags
{
    uint32_t negotiate_unicode:1;                   // 31:A
    uint32_t negotiate_oem:1;                       // 30:B
    uint32_t request_target:1;                      // 29:C
    uint32_t request_0x00000008:1;                  // 28:r10
    uint32_t negotiate_sign:1;                      // 27:D
    uint32_t negotiate_seal:1;                      // 26:E
    uint32_t negotiate_datagram:1;                  // 25:F
    uint32_t negotiate_lan_manager_key:1;           // 24:G
    uint32_t negotiate_0x00000100:1;                // 23:r9
    uint32_t negotiate_ntlm_key:1;                  // 22:H
    uint32_t negotiate_nt_only:1;                   // 21:r8
    uint32_t negotiate_anonymous:1;                 // 20:J
    uint32_t negotiate_oem_domain_supplied:1;       // 19:K
    uint32_t negotiate_oem_workstation_supplied:1;  // 18:L
    uint32_t negotiate_0x00004000:1;                // 17:r7
    uint32_t negotiate_always_sign:1;               // 16:M
    uint32_t target_type_domain:1;                  // 15:N
    uint32_t target_type_server:1;                  // 14:O
    uint32_t target_type_share:1;                   // 13:r6
    uint32_t negotiate_extended_security:1;         // 12:P
    uint32_t negotiate_identify:1;                  // 11:Q
    uint32_t negotiate_0x00200000:1;                // 10:r5
    uint32_t request_non_nt_session:1;              //  9:R
    uint32_t negotiate_target_info:1;               //  8:S
    uint32_t negotiate_0x01000000:1;                //  7:r4
    uint32_t negotiate_version:1;                   //  6:T
    uint32_t negotiate_0x04000000:1;                //  5:r3
    uint32_t negotiate_0x08000000:1;                //  4:r2
    uint32_t negotiate_0x10000000:1;                //  3:r1
    uint32_t negotiate_128:1;                       //  2:U
    uint32_t negotiate_key_exchange:1;              //  1:V
    uint32_t negotiate_56:1;                        //  0:W
};


/*
 * Reference:
 * https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/b88739c6-1266-49f7-9d22-b13923bd8d66
 */
struct ntlm_response
{
    unsigned char response[24];
};


/*
 * Reference:
 * https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/aee311d6-21a7-4470-92a5-c4ecb022a87b
 */
struct ntlmv2_client_challenge
{
    unsigned char resp_type;
    unsigned char hi_resp_type;
    uint16_t reserved1;
    uint32_t reserved2;
    uint64_t time_stamp;
    unsigned char challenge_from_client[8];
    uint32_t reserved3;
    struct av_pair av_pair;
    // variable
};


/*
 * Reference:
 * https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/d43e2224-6fc3-449d-9f37-b90b55a29c80
 */
struct ntlmv2_response
{
    unsigned char response[16];
    struct ntlmv2_client_challenge ntlmv2_client_challenge;
    // variable
};


/*
 * Reference:
 * https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/b1a6ceb2-f8ad-462b-b5af-f18527c48175
 */
#define NTLMSSP_REVISION_W2K3 0x0F

struct version
{
    unsigned char product_major_version;
    unsigned char product_minor_version;
    uint16_t product_build;
    unsigned char reserved[3];
    unsigned char ntlm_revision_current;
};


/*
 * Reference:
 * https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/83fbd0e7-8ab0-4873-8cbe-795249b46b8a
 */
struct ntlmssp_message_signature
{
    struct version version;
    unsigned char random_pad[4];
    unsigned char checksum[4];
    uint32_t seq_num;
};


/*
 * Reference:
 * https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/2c3b4689-d6f1-4dc6-85c9-0bf01ea34d9f
 */
struct ntlmssp_message_signature_extended_session_security
{
    struct version version;
    unsigned char checksum[8];
    uint32_t seq_num;
};


/*
 * Reference:
 * https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/b34032e5-3aae-4bc6-84c3-c6d80eadf7f2
 */
#define NtLmNegotiate       0x00000001
#define NtLmChallenge       0x00000002
#define NtLmAuthenticate    0x00000003


struct domain_name_fields
{
    uint16_t domain_name_len;
    uint16_t domain_name_max_len;
    uint32_t domain_name_buffer_offset;
};


struct workstation_fields
{
    uint16_t workstation_len;
    uint16_t workstation_max_len;
    uint32_t workstation_buffer_offset;
};


struct negotiate_message
{
    char signature[8];
    uint32_t message_type;
    struct negotiate_flags negotiate_flags;
    struct domain_name_fields domain_name_fields;
    struct workstation_fields workstation_fields;
    struct version version;
    char payload;
    // variable
};


/*
 * Reference:
 * https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/801a4681-8809-4be9-ab0d-61dcfe762786
 */
struct target_name_fields
{
    uint16_t target_name_len;
    uint16_t target_name_max_len;
    uint32_t target_name_buffer_offset;
};


struct target_info_fields
{
    uint16_t target_info_len;
    uint16_t target_info_max_len;
    uint32_t target_info_buffer_offset;
};


struct challenge_message
{
    char signature[8];
    uint32_t message_type;
    struct target_name_fields target_name_fields;
    struct negotiate_flags negotiate_flags;
    unsigned char server_challenge[8];
    unsigned char reserved[8];
    struct target_info_fields target_info_fields;
    struct version version;
    char payload;
    // variable
};


/*
 * Reference:
 * https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/033d32cc-88f9-4483-9bf2-b273055038ce
 */
struct lm_challenge_response_fields
{
    uint16_t lm_challenge_response_len;
    uint16_t lm_challenge_response_max_len;
    uint32_t lm_challenge_response_buffer_offset;
};


struct nt_challenge_response_fields
{
    uint16_t nt_challenge_response_len;
    uint16_t nt_challenge_response_max_len;
    uint32_t nt_challenge_response_buffer_offset;
};


struct user_name_fields
{
    uint16_t user_name_len;
    uint16_t user_name_max_len;
    uint32_t user_name_buffer_offset;
};


struct encrypted_random_session_key_fields
{
    uint16_t encrypted_random_session_key_len;
    uint16_t encrypted_random_session_key_max_len;
    uint32_t encrypted_random_session_key_buffer_offset;
};


struct authenticate_message
{
    char signature[8];
    uint32_t message_type;
    struct lm_challenge_response_fields lm_challenge_response_fields;
    struct nt_challenge_response_fields nt_challenge_response_fields;
    struct domain_name_fields domain_name_fields;
    struct user_name_fields user_name_fields;
    struct workstation_fields workstation_fields;
    struct encrypted_random_session_key_fields encrypted_random_session_key_fields;
    struct negotiate_flags negotiate_flags;
    struct version version;
    unsigned char mic[16];
    char payload;
    // variable
};


#endif /* NTLM_H */
