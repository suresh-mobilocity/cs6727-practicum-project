var request = require('request');

function query_app_vulns(app_id, callback){
 var options = {
  'method': 'POST',
  'url': 'https://data.mongodb-api.com/app/data-ilixv/endpoint/data/v1/action/findOne',
  'headers': {
    'Content-Type': 'application/json',
    'Access-Control-Request-Headers': '*',
    'api-key': '6354352e863169c99771a650'
  },
  body: JSON.stringify({
    "dataSource": "risqexpert-db",
    "database": "risqexpertdb",
    "collection": "app_vulnerabilities",
    "filter": {
      "metadata.component.name": app_id
    },
    "projection": { "metadata.component.name": 1,  "vulnerabilities.id":1},
  })

 };
 request(options, function (error, response) {
  var vuln_list=[];
  var ret={};
  if (error) throw new Error(error);
  var result=JSON.parse(response.body);
  if( result.document === 'undefined' || result.document === null || result.document.length == 0){ 
 	console.log("Could not find application or no vulnerabilities found");
  }
  else
  {
	console.log("List of Vulnerabilities - Count " + result.document.vulnerabilities.length);
	for ( i=0, count = result.document.vulnerabilities.length; i < count; i++){
		vuln_list.push( result.document.vulnerabilities[i].id);
	}
	ret = { "app_id": result.document.metadata.name, "vulnerabilities": vuln_list } ;
   }
   return(callback(ret));
 });
}
module.exports = {query_app_vulns}
