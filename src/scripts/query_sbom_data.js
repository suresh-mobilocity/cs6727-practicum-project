var request = require('request');
var args = process.argv.slice(2);

if(args.length<1){
	console.log("Usage: query_sbom <name in SBOM> ") 
        process.exit(0);
}
var options = {
  'method': 'POST',
  'url': 'https://data.mongodb-api.com/app/data-ilixv/endpoint/data/v1/action/findOne',
  'headers': {
    'Content-Type': 'application/json',
    'Access-Control-Request-Headers': '*',
    'api-key': ''
  },
  body: JSON.stringify({
    "dataSource": "risqexpert-db",
    "database": "risqexpertdb",
    "collection": "sbom_inventory",
    "filter": {
      "name": args[0]
    }
  })

};
request(options, function (error, response) {
  if (error) throw new Error(error);
  console.log(response.body);
});

