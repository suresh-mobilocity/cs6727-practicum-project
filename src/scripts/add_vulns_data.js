var request = require('request');
var args = process.argv.slice(2);
var vuln_file =  args[0];

fs = require('fs')
var vuln_list = {}; 
fs.readFile(vuln_file, 'utf8', function (err,vuln_list) {
  if (err) {
    return console.log(err);
  }
  console.log(vuln_list);

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
    "collection": "app_vulnerabilities",
    "document": JSON.parse(vuln_list) 
  })
};
console.log(options.body);
request(options, function (error, response) {
  if (error) throw new Error(error);
  console.log(response.body);
});

});
