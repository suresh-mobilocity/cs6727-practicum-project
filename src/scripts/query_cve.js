var request = require('request');
var fs = require('fs');
var args = process.argv.slice(2);
var CVE =  args[0];

if(args.length<1){
	console.log("Usage: query_cve <CVE> ") 
        process.exit(0);
}
var options = {
  'method': 'GET',
  'url': 'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=' + CVE ,
  'json': 'true',
  'headers': {
  }
};
request(options, function (error, response) {
  if (error) throw new Error(error);
   fs.writeFileSync(CVE+".txt" , JSON.stringify(response.body,0,2));
   //console.log(response.body);
});
