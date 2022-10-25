var request = require('request');

var args = process.argv.slice(2);
if(args.length<1){
	console.log("Usage: read_sbom_file <filename> ") 
        process.exit(0);
}
var sbom_file = './'+ args[0];
console.log('sbom_file:'+ sbom_file);

fs = require('fs')
fs.readFile(sbom_file, 'utf8', function (err,data) {
  if (err) {
    return console.log(err);
  }
  console.log(JSON.stringify(data));
});
