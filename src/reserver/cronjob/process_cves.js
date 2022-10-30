//
//
// Processes new CVEs returned by NVD API reponse saved in a JSON file. 
// For each CVE listed in the  JSON file, check CVE status
// For CVEs with status "Analyzed" gets cpe (package name and version) list  
// Checks SBOM inventory if any of the dependencis are matching with cpes in the CVE
// if match, then lists the App using those packages as impacted and 
// updates application vulnerability list by adding the new CVE to it.
//
//
//

fs = require('fs');

function process_cves(cve_list_filename){

	console.log("Reading CVE data from file: " + cve_list_filename);
        var cve_count_analyzed = 0;
        var cve_count_undergoing = 0;
        var cve_count_waiting = 0;
	var impacted_app_count = 0;
	var impacted_apps_by_cve={};
	var vuln_list = {}; 
	vuln_list = JSON.parse(fs.readFileSync(cve_list_filename, 'utf8'));
	console.log("Found total of " + vuln_list.resultsPerPage + " new CVEs");
	var vulns = vuln_list.vulnerabilities;
	//console.log("vulnerabilities lenght" + vulns.length);
	for (var i = 0, len = vulns.length; i < len; i++){
      	cve = vulns[i].cve;
      //console.log("checking CVE: " + cve.id + ", vulnStatus: " + cve.vulnStatus);
      		switch(cve.vulnStatus)
		{
			case 'Analyzed':
        			cve_count_analyzed++ ;
				var cpes=get_cpes_from_cve(cve);
			//for (var n=0, len = cpes.length; n < len; n++)
			// {
			//	var cpe=cpes[n]; 
			//	console.log(cve.id + " impacted package - "+ "Vendor: " + cpe[0] + "; Product: " + cpe[1] + ";  Version: " + cpe[2]); 
			// }
			// search each cpe in SBOM
				search_cpes_in_sbom_inventory(cve.id, cpes, function(result){
					console.log( result.impacted_apps.length + "SBOMS/Apps are impacted by "+  result.cve);
					impacted_app_count = impacted_app_count + result.impacted_apps.length;
				});
				break;
			case 'Awaiting Analyis':
        			cve_count_waiting++;
			//console.log("Can't process CVE due to Awaiting Analysis Status");
				break;
			case 'Undergoing Analysis':
			//console.log("Can't process CVE due to Undergoting Analysis Status");
        			cve_count_undergoing++;
				break;
			default:
			//console.log("Can't process CVE due to " + cve.vulnStatus);
				break;
        	}
	//console.log("Finished processng - " + cve.id);
	}
	console.log("Impacted " + impacted_app_count + " apps ");
}

//  Function returns list of cpes in the CVE object

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

// Function searchs SBOM inventory and return App_IDs affected by the CVE

function search_cpes_in_sbom_inventory(cve_id, cpes,callback)
{
	// Search SBOM Inventory DB
	var impacted_apps=[];
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
  		}
		else {
                        for ( var i =0, doc_count = result.documents.length; i < doc_count; i++){
				console.log("Found SBOM " + result.documents[i].name + " impacted by " + cve_id);
				impacted_apps.push(result.documents[i].name);
			}
		}
		return callback({ "cve": cve_id, "impacted_apps": impacted_apps});
	});
}

// Export process_cve function

module.exports = {process_cves};
