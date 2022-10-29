fs = require('fs');
var args = process.argv.slice(2);
var cve_list_filename =  args[0];

if(args.length<1){
	console.log("Usage: process_cves <filename> ") 
        process.exit(0);
}
console.log("Reading CVE data from file: " + cve_list_filename);

var vuln_list = {}; 
vuln_list = JSON.parse(fs.readFileSync(cve_list_filename, 'utf8'));
console.log("Found total " + vuln_list.resultsPerPage + " of CVEs");
var vulns = vuln_list.vulnerabilities;
//console.log("vulnerabilities lenght" + vulns.length);
for (var i = 0, len = vulns.length; i < len; i++){
      cve = vulns[i].cve;
      //console.log("checking CVE: " + cve.id + ", vulnStatus: " + cve.vulnStatus);
      switch(cve.vulnStatus)
	{
		case 'Analyzed':
			var cpes=get_cpes_from_cve(cve);
			//for (var n=0, len = cpes.length; n < len; n++)
			// {
			//	var cpe=cpes[n]; 
			//	console.log(cve.id + " impacted package - "+ "Vendor: " + cpe[0] + "; Product: " + cpe[1] + ";  Version: " + cpe[2]); 
			// }
			// search each cpe in SBOM
			search_cpes_in_sbom_inventory(cve.id, cpes);
			break;
		case 'Awaiting Analyis':
			//console.log("Can't process CVE due to Awaiting Analysis Status");
			break;
		case 'Undergoing Analysis':
			//console.log("Can't process CVE due to Undergoting Analysis Status");
			break;
		default:
			//console.log("Can't process CVE due to " + cve.vulnStatus);
			break;
        }
	//console.log("Finished processng - " + cve.id);
}
function get_cpes_from_cve(cve)
{
  	var cpelist=[];
	configs = cve.configurations;
	for (var i = 0, len = configs.length; i < len; i++){
           var nodes = configs[i].nodes;
           for (var j =0, numofnodes=nodes.length; j < numofnodes; j++){
                cpe_matches = nodes[j].cpeMatch;
                   for ( var k =0, cpe_count = cpe_matches.length; k < cpe_count; k++){
                        if (cpe_matches[k].vulnerable){
                           var criteria = cpe_matches[k].criteria;
                           var cpe = criteria.split(":");
                           //console.log( "vendor:" + cpe[3] + "product:" + cpe[4] + "version:" + cpe[5] );
                           cpelist.push([cpe[3],cpe[4],cpe[5]]);
                        }
                   }
           }
	}
	return cpelist;
}
function search_cpes_in_sbom_inventory(cve_id, cpes)
{
	// Search SBOM Inventory DB

	var search_cpes = [];
	for (var i = 0, len = cpes.length; i < len; i++){
		var cpe = cpes[i];
		var search={};
		search["packages.name"] = cpe[1];
		search["packages.versionInfo"] = cpe[2];
		//console.log(search["packages.name"] );
		//console.log(search["packages.versionInfo"] );

		search_cpes.push(search);
	}
	var request = require('request');
	var options = {
		'method': 'POST',
		'url': 'https://data.mongodb-api.com/app/data-ilixv/endpoint/data/v1/action/find',
		//'url': 'https://data.mongodb-api.com/app/data-ilixv/endpoint/data/v1/action/findOne',
  			'headers': {
    			'Content-Type': 'application/json',
    			'Access-Control-Request-Headers': '*',
    			'api-key': '6354352e863169c99771a650'
  			},
  		body: JSON.stringify({
    			"dataSource": "risqexpert-db",
    			"database": "risqexpertdb",
    			"collection": "sbom_inventory",
    			"filter":  { $or: search_cpes},
			"projection": {"name": 1, "_id":1}
  		})

	};
	request(options, function (error, response) {
  		if (error) throw new Error(error); 
		var result=JSON.parse(response.body);
		console.log(result);
  		if( result.documents === 'undefined' || result.documents === null || result.documents.length == 0)
  		{
			console.log("No SBOM is found that is impacted by - " + cve_id);
			return;
  		}
		else {
                        for ( var i =0, doc_count = result.documents.length; i < doc_count; i++){
				console.log("Found SBOM " + result.documents[i].name + " impacted by " + cve_id);
			}
		}
		return;
	});
}
//fs.writeFileSync(sbom_file, JSON.stringify(sbom,0,2));
