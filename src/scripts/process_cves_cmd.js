var pcves = require('./process_cves.js');
var args = process.argv.slice(2);
if(args.length<1){
	console.log("Usage: process_cves_cmd <vulnerability list in json format> ") 
        process.exit(0);
}
pcves.process_cves(args[0]);
