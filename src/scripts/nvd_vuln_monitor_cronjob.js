var CronJob = require('cron').CronJob;
var request = require('request');
var fs = require('fs');
var pcve = require ('../scripts/process_cves.js');


console.log("Cron Job to check NVD for new Vulnerabilities every 5 minutes");
var checkNVDJob = new CronJob({
        cronTime: '0 */1 * * * *',
        onTick: function() {
            try{
                startCheckNVDJob(function(result){
		    if(result != null ) {
                    //console.log(result.file);
                    //console.log(result.message);
		    	pcve.process_cves(result.file)
		    }
                });
            }catch(err)
            {console.log( err.message);}
        },
	onComplete: function() {
            try{
                    console.log("Completed processing CVEs");
            }catch(err)
            {console.log( err.message);}
	},
        start: false
        // timeZone: "America/Los_Angeles"
 });
checkNVDJob.start();
function startCheckNVDJob(callback){

	var current_time = new Date();
	var prev_scanned_time = new Date(current_time.getTime() - (24*60*60*1000));
	var dd = String(current_time.getDate()).padStart(2, '0');
	var mm = String(current_time.getMonth() + 1).padStart(2, '0'); //January is 0!
	var yyyy = current_time.getFullYear();
	var HH = String(current_time.getHours()).padStart(2,"0"); 
	var MI = String(current_time.getMinutes()).padStart(2,"0"); 
	var SS = String(current_time.getSeconds()).padStart(2,"0");; 
	var MS = String(current_time.getMilliseconds()).padStart(3,"0"); 

	var prev_dd = String(prev_scanned_time.getDate()).padStart(2,0);
	var prev_mm = String(prev_scanned_time.getMonth() + 1).padStart(2, '0'); //January is 0!
	var prev_yyyy = prev_scanned_time.getFullYear();
	var prev_HH = String(prev_scanned_time.getHours()).padStart(2,"0");
	var prev_MI = String(prev_scanned_time.getMinutes()).padStart(2,"0");
	var prev_SS = String(prev_scanned_time.getSeconds()).padStart(2,"0");
	var prev_MS = String(prev_scanned_time.getMilliseconds()).padStart(3,"0");


	var params = "pubStartDate=" + prev_yyyy + "-" + prev_mm + "-" + prev_dd + "T" + prev_HH + ":" + prev_MI + ":" + prev_SS + "." +  prev_MS + "-05:00";

	//console.log('API params: ' + params);

	var current_time_string = yyyy + "-" + mm + "-" + dd + "T" + HH + ":" + MI + ":" + SS + "." + MS + "-05:00" ;
	params = params+ "&pubEndDate=" + current_time_string;
	//params = "pubStartDate=2022-10-26T00:00:00.000-05:00&pubEndDate=2022-10-27T23:59:59.999-05:00";

	//console.log("API params: " + params);
	var new_vulns_file = current_time_string.split(".")[0] + "-" + "new_vulns.json"
	console.log("new vulnerability file:" + new_vulns_file); 

	var options = {
  		'method': 'GET',
  		'url': 'https://services.nvd.nist.gov/rest/json/cves/2.0/?' + params ,
  		'json': 'true',
  		'headers': {
  		}
	};
	request(options, function (error, response) {
		var result = {};
  		if (error){
			callback({
				result: "Fail",
				message: "Cron Job CheckNVD Failed.." +  new Date()
			});
		}
		if(response){
			//console.log("got response");
   			//console.log(JSON.stringify(response.body,0,2));
			//console.log(JSON.stringify(response.body,0,2));
   			fs.writeFileSync(new_vulns_file, JSON.stringify(response.body,0,2));
			result={"file" : new_vulns_file, "message" : "success"};
		}
		else{
			console.log("No new vulnerabilities found ... ");
		}
		return callback(result)
	});
 }
