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
   var cve_obj = response.body;
   if(cve_obj){
  	var cpelist=[];
   	var vulns = cve_obj.vulnerabilities;
   	var cve_rec = vulns[0].cve; 
   	var configs = cve_rec.configurations;
   	console.log("CVE Rec" + cve_rec.id);
   	for (var i = 0, len = configs.length; i < len; i++){
	   var nodes = configs[i].nodes;
	   for (var j =0, numofnodes=nodes.length; j < numofnodes; j++){
		cpe_matches = nodes[j].cpeMatch;	
		   for ( var k =0, cpe_count = cpe_matches.length; k < cpe_count; k++){
			if (cpe_matches[k].vulnerable){
			   var criteria = cpe_matches[k].criteria;
			   var cpe = criteria.split(":");			   
                           console.log( "vendor:" + cpe[3] + "product:" + cpe[4] + "version:" + cpe[5] );  
			   cpelist.push([cpe[3],cpe[4],cpe[5]]);
			}
	           }
	   }
   }
   //console.log(response.body);
   for(var i = 0; i < cpelist.length; i++) {
       console.log("vendor: " + cpelist[i][0] + " product: " +  cpelist[i][1] + " version: "+ cpelist[i][2]);
   }
	   console.log(cve_rec.id + " is found in " + cpelist.length + " package versions..");
 } else console.log("No such CVE");
});
