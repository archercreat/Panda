//
// Created by Archer on 4/16/2021.
//

#ifndef PANDA_MSV_HPP
#define PANDA_MSV_HPP

#include <Windows.h>

#define MSV1_0_CREDENTIAL_KEY_LENGTH 20
#define MSV1_0_CHALLENGE_LENGTH 8
#define MSV1_0_RESPONSE_LENGTH 24
#define MSV1_0_NTLM3_RESPONSE_LENGTH 16
#define MSV1_0_USER_SESSION_KEY_LENGTH 16

typedef struct _NT_CHALLENGE{
    UCHAR Data[MSV1_0_CHALLENGE_LENGTH];
} NT_CHALLENGE, *PNT_CHALLENGE;

typedef struct _NT_RESPONSE{
    UCHAR Data[MSV1_0_RESPONSE_LENGTH];
} NT_RESPONSE, *PNT_RESPONSE;

typedef struct {
    UCHAR Response[MSV1_0_NTLM3_RESPONSE_LENGTH];
    UCHAR ChallengeFromClient[MSV1_0_CHALLENGE_LENGTH];
} MSV1_0_LM3_RESPONSE, *PMSV1_0_LM3_RESPONSE;

typedef struct {
    UCHAR Data[MSV1_0_USER_SESSION_KEY_LENGTH];
} USER_SESSION_KEY, *PUSER_SESSION_KEY;

typedef NT_CHALLENGE LM_SESSION_KEY;

typedef enum _MSV1_0_CREDENTIAL_KEY_TYPE{
    InvalidCredKey,        // reserved
    IUMCredKey,            // reserved
    DomainUserCredKey,
    LocalUserCredKey,      // For internal use only - should never be present in
    ExternallySuppliedCredKey // reserved
} MSV1_0_CREDENTIAL_KEY_TYPE;

typedef struct _MSV1_0_CREDENTIAL_KEY {
    UCHAR Data[MSV1_0_CREDENTIAL_KEY_LENGTH];
} MSV1_0_CREDENTIAL_KEY, *PMSV1_0_CREDENTIAL_KEY;

typedef struct _MSV1_0_NTLM3_RESPONSE {
    UCHAR       Response[MSV1_0_NTLM3_RESPONSE_LENGTH];
    UCHAR       RespType;
    UCHAR       HiRespType;
    USHORT      Flags;
    ULONG       MsgWord;
    ULONGLONG   TimeStamp;
    UCHAR       ChallengeFromClient[MSV1_0_CHALLENGE_LENGTH];
    ULONG       AvPairsOff;
} MSV1_0_NTLM3_RESPONSE, *PMSV1_0_NTLM3_RESPONSE, **PPMSV1_0_NTLM3_RESPONSE;

typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWCHAR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

#endif //PANDA_MSV_HPP
