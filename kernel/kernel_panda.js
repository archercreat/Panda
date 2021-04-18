 /// <reference path="JSProvider.d.ts" />
"use strict";

const log  = x => host.diagnostics.debugLog(x+'\n');
const ok   = x => log(`[+] ${x}`);
const warn = x => log(`[!] ${x}`);
const err  = x => log(`[-] ${x}`);

const  u8 = x => host.memory.readMemoryValues(x, 1, 1)[0];
const u16 = x => host.memory.readMemoryValues(x, 1, 2)[0];
const u32 = x => host.memory.readMemoryValues(x, 1, 4)[0];
const u64 = x => host.memory.readMemoryValues(x, 1, 8)[0];

const mem_read_array   = (x, y) => host.memory.readMemoryValues(x, y);
const mem_read_string  = x => host.memory.readString(x);
const mem_read_wstring = x => host.memory.readWideString(x);

function hex(arr) {
    return Array.from(arr, function(byte) {
      return ('0' + (byte & 0xFF).toString(16)).slice(-2);
    }).join('')
}

function handle_create_cipher_keys() {
    ok('mrxsmb!SmbCryptoCreateCipherKeys hit!');
    let regs = host.currentThread.Registers.User;
    let args = [regs.rcx, regs.rdx, regs.r8, regs.r9];
    let session_key = mem_read_array(args[1], 16);
    let method = mem_read_string(args[3]);
    ok('Method: ' + method + ', SessionKey: ' + hex(session_key));
}

function handle_create_application_key() {
    ok('mrxsmb!SmbCryptoCreateApplicationKey hit!');
    let regs = host.currentThread.Registers.User;
    let app_key_ptr = u64(host.parseInt64(regs.rsp).add(0x30));
    let app_key     = mem_read_array(app_key_ptr, 16);
    ok('ApplicationKey: ' + hex(app_key));
}

function invokeScript() {
    let control = host.namespace.Debugger.Utility.Control;
    // Hook SmbCryptoCreateCipherKeys
    let bp_1 = control.SetBreakpointAtOffset("SmbCryptoCreateCipherKeys", 0, "mrxsmb");
    bp_1.Command = '.echo "[+] panda hook"; dx @$scriptContents.handle_create_cipher_keys(); gc';
    // Hook SmbCryptoCreateApplicationKey
    let bp_2 = control.SetBreakpointAtOffset("SmbCryptoCreateApplicationKey", 107, "mrxsmb");
    bp_2.Command = '.echo "[+] panda hook"; dx @$scriptContents.handle_create_application_key(); gc';
    ok('Press "g" to run the target.');
}