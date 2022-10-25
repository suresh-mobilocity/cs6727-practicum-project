var request = require('request');
fs = require('fs')

var args = process.argv.slice(2);
if(args.length<1){
	console.log("Usage: add_app_profile <profile file in json format> ") 
        process.exit(0);
}

var filename =  args[0];
var app_profile = {}; 
fs.readFile(filename, 'utf8', function (err,app_profile) {
  if (err) {
    return console.log(err);
  }
  console.log(app_profile);

var options = {
  'method': 'POST',
  'url': 'https://data.mongodb-api.com/app/data-ilixv/endpoint/data/v1/action/insertOne',
  'headers': {
    'Content-Type': 'application/json',
    'Access-Control-Request-Headers': '*',
    'api-key': '6354352e863169c99771a650'
  },
  body: JSON.stringify({
    "dataSource": "risqexpert-db",
    "database": "risqexpertdb",
    "collection": "app_inventory",
    "document": JSON.parse(app_profile) 
  })
};
console.log(options.body);
request(options, function (error, response) {
  if (error) throw new Error(error);
  console.log(response.body);
});

});
