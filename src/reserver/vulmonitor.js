//
//
// Vulnerability Monitor App Server run a cron job
// Retrieves new vulnerabilities fron NVD and write to a file
// Process  new Vulnerabilities listed in the file 
// extracts cpe or affected packages and versions
// Searchs SBOM inventory for affected packages and list our Application Builds impacted by CVEs.
//
//


var express = require("express");
var app = express();

require('../scripts/nvd_vuln_monitor_cronjob.js');
qv = require('../scripts/query_app_vulns.js');

app.get("/about", function(req, res,next) {
 res.json("Vulnerability Monitor Server Application");
});

app.get("/vulnerabilities", function(req, res,next) {
 	console.log("getting vulnerabilities for " + req.query.appid);
 	var result = qv.query_app_vulns(req.query.appid,function(result){
 		res.send(result);
 	});
});


app.listen(3000, function() {
 console.log("Vulnerability Monitor Server running on port 3000");
});

