#include <Windows.h>

#include "library.h"
#include "hooks.hpp"


BOOL WINAPI DllMain( HINSTANCE hinstance, DWORD fwdReason, LPVOID lpReserved )
{
    DisableThreadLibraryCalls( hinstance );

    if ( fwdReason == DLL_PROCESS_ATTACH )
    {
        auto output = get_logger(R"(C:\Users\Administrator\Desktop\log.txt)" );

        output->log("[+] Panda online\n" );
        output->log("[*] Setting up hooks\n" );

        if ( initialize_hooks() == -1 )
        {
            output->log("[-] Failed to setup hooks\n" );
            return FALSE;
        }
        output->log("[+] Done setting up hooks\n" );
    }
    else if ( fwdReason == DLL_PROCESS_DETACH )
    {
        get_logger()->log( "[+] Exiting..\n" );
        disable_hooks();
        delete get_logger();

    return TRUE;
}