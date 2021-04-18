//
// Created by Archer on 4/16/2021.
//

#ifndef PANDA_HOOKS_HPP
#define PANDA_HOOKS_HPP

#include <cstdint>
#include "logger.hpp"
#include "msv.hpp"

// Hook function rva's based on my msv1_0.dll version
//
#define LM20GetNtlm3ChallengeResponseRva    0x60a10
#define SsprMakeSessionKeyRva               0x5b470

// Hook function rva's based on my NtlmShared.dll version
//
#define MsvpCalculateNtlm3OwfRva            0x018C0
#define MsvpNtlm3ResponseRva                0x01c30


// Prototypes
//
typedef DWORD ( *LM20GetNtlm3ChallengeResponseTy )(
        void* a1,
        void* a2 ,
        PUNICODE_STRING UString1,
        PUNICODE_STRING UString2,
        PUNICODE_STRING UString3,
        void* a6,
        void* a7,
        PPMSV1_0_NTLM3_RESPONSE NTLM3Response,
        PMSV1_0_LM3_RESPONSE LM3Response,
        PVOID SessionKey,
        void* a11
);

typedef PVOID ( *MsvpCalculateNtlm3OwfTy ) (
        IN PUCHAR           pNtOwfPassword,
        IN PUNICODE_STRING  pUserName,
        IN PUNICODE_STRING  pLogonDomainName,
        OUT PUCHAR          Ntlm3Owf
);

typedef PVOID ( *MsvpNtlm3ResponseTy ) (
        IN PUCHAR                   pNtOwfPassword,
        IN PUNICODE_STRING          pUserName,
        IN PUNICODE_STRING          pLogonDomainName,
        IN ULONG                    ServerNameLength,
        IN PUCHAR                   ChallengeToClient,
        IN PMSV1_0_NTLM3_RESPONSE   pNtlm3Response,
        OUT PUCHAR                  Response,
        OUT PUSER_SESSION_KEY       UserSessionKey,
        OUT PUSER_SESSION_KEY       LmSessionKey
);

typedef DWORD ( *SsprMakeSessionKeyTy ) (
        IN  PUCHAR          Context,
        IN  PUNICODE_STRING LmChallengeResponse,
        IN  PUCHAR          NtUserSessionKey,
        IN  PUCHAR          LanmanSessionKey,
        IN  PUNICODE_STRING DatagramSessionKey
);


int initialize_hooks();
void disable_hooks();
#endif //PANDA_HOOKS_HPP
