# cs6727-practicum-project
The project goal is to demonstrate a solution and a prototype of the solution to manage the risks with open source software vulnerabilities effectively and efficiently. 
The solution will use Software Composition Analysis (SCA), and dependency tracking techniques used in SCA to generate SBOM (Software Bill of Matrials). 
The solution ties SBOMs generated during application build process with Application profiles and the hsot/server inventory where the applications are deployed and run. 
The solution taps into NVD database and other vulnerabilitiy databases to monitor and track new vulnerabilities added to the databses, 
and then search SBOM invenotry for affected dependency packages listed in CVEs. When a new vulnerability is identified in open source components, 
the solution identifies all the impacted applications and host inventory where the applications are running using a simple search into mapped AppProfile - SBOM - Server Addresses Database.
The prototype implementation leverages one of the SCA tools such as syft, grype in SDLC CI/CD pipelines to create an inventory of software components (SBOM Software Bill of Materials). 
The prototype implementation uses NVD API to monitor new CVEs.

# dependencies
Node 10.x
MongoDB Data API

# Run From the sources:

cd src/reserver
npm install
node ./vulmonitor.js
