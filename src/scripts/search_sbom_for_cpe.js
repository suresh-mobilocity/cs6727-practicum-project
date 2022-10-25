var request = require('request');
var args = process.argv.slice(2);
var sbom_file =  args[0];
var vendor  =  args[1];
var product  =  args[2];
var version  =  args[3];
var found = "false"
fs = require('fs');
var sbom = {}; 
if(args.length<4){
	console.log("Usage: search_sbom_for_cve  <sbomfile> <vendor> <product> <version> ") 
        process.exit(0);
}


sbom = JSON.parse(fs.readFileSync(sbom_file, 'utf8'));
var dependency_pkgs = sbom.packages;

for (var i = 0, len = dependency_pkgs.length; i < len; i++){
	if(( dependency_pkgs[i].name == product || dependency_pkgs[i].name == vendor ) && (dependency_pkgs[i].versionInfo == version )){
		console.log("vulnerabie pakage: " + product +  " veriosn: " + version + " is found in SBOM: " + sbom_file);
		found = "true"
		break;
	}
}
if ( found == "false" ) console.log("vulnerabie pakage: " + product +  "veriosn: " + version + " is NOT found in SBOM" + sbom_file);
