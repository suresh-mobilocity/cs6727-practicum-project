
var request = require('request');
var fs = require('fs');


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

//console.log("API params: " + params);
var new_vulns_file = current_time_string + "-" + "new_vulns.json"

var options = {
  'method': 'GET',
  'url': 'https://services.nvd.nist.gov/rest/json/cves/2.0/?' + params ,
	// pubStartDate=2022-09-30T00:00:00.000-05:00&pubEndDate=2022-09-30T23:59:59.999-05:00',
  'json': 'true',
  'headers': {
  }
};
request(options, function (error, response) {
  if (error) throw new Error(error);
   console.log(JSON.stringify(response.body,0,2));
   fs.writeFileSync(new_vulns_file, JSON.stringify(response.body,0,2));
});
