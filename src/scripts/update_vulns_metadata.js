var request = require('request');
var args = process.argv.slice(2);

if(args.length<1){
	console.log("Usage: update_vulns_metadata.js <vulnerability list file in json format> ") 
        process.exit(0);
}
var vuln_file =  args[0];
var app_id  =  args[1];

//console.log(vuln_file);
fs = require('fs');
var vuln_list = {}; 
vuln_list = JSON.parse(fs.readFileSync(vuln_file, 'utf8'));
vuln_list.metadata.component.name = app_id;
console.log(vuln_list.metadata.component.name);
fs.writeFileSync(vuln_file, JSON.stringify(vuln_list,0,2));
