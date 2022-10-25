var request = require('request');
var args = process.argv.slice(2);
var sbom_file =  args[0];

if(args.length<1){
	console.log("Usage:  query_app_profile <app name> ") 
        process.exit(0);
}
fs = require('fs')
var sbom = {}; 
fs.readFile(sbom_file, 'utf8', function (err,sbom) {
  if (err) {
    return console.log(err);
  }
  console.log(sbom);

var options = {
  'method': 'POST',
  'url': 'https://data.mongodb-api.com/app/data-ilixv/endpoint/data/v1/action/insertOne',
  'headers': {
    'Content-Type': 'application/json',
    'Access-Control-Request-Headers': '*',
    'api-key': ''
  },
  body: JSON.stringify({
    "dataSource": "risqexpert-db",
    "database": "risqexpertdb",
    "collection": "sbom_inventory",
    "document": JSON.parse(sbom) 
  })
};
console.log(options.body);
request(options, function (error, response) {
  if (error) throw new Error(error);
  console.log(response.body);
});

});
