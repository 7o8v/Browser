#../v8/out/x64.debug/d8  --shell ./poc.js --allow-natives-syntax #--trace-turbo #--trace-representation #
./krautflare_task/d8 --shell ./poc.js --allow-natives-syntax
#../v8/out/x64.debug/d8  --shell ./poc.js --allow-natives-syntax --trace-representation --trace-turbo-graph --trace-turbo-path /tmp/out --trace-turbo