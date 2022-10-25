var request = require('request');
var args = process.argv.slice(2);
var sbom_file =  args[0];
var app_id  =  args[1];

console.log(sbom_file);
fs = require('fs');
var sbom = {}; 
sbom = JSON.parse(fs.readFileSync(sbom_file, 'utf8'));
sbom.name = app_id; 
console.log(sbom.name);
fs.writeFileSync(sbom_file, JSON.stringify(sbom,0,2));
