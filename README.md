
Below are **step-by-step, up-to-date commands** for both CTI-WEB (manager) and CTI-DB (worker), including best practices from the latest official documentation.
Please note that scripts are only being used for the first time when we do the deployment, and after that, in the environment we can change the version if we need to update it.

---

1. **Uninstall Old Docker and Portainer (Both Nodes)**

   ```bash
   sudo docker swarm leave --force
   sudo docker stop portainer_agent
   dpkg -l | grep -i docker
   sudo apt-get purge -y docker-engine docker docker.io docker-ce docker-ce-cli docker-compose-plugin
   dpkg -l | grep -i docker
   sudo apt-get autoremove -y --purge docker-engine docker docker.io docker-ce docker-compose-plugin
   sudo rm -rf /var/lib/docker /etc/docker
   sudo rm /etc/apparmor.d/docker
   sudo groupdel docker
   sudo rm -rf /var/run/docker.sock
   sudo find / -name '*portainer*'
   sudo find / -name '*portainer*' -exec rm -rf {} \;
   ```

---

2. **Install Latest Docker Engine & Compose Plugin (Both Nodes)**

   ```bash
   sudo apt-get update
   sudo apt-get install apt-transport-https ca-certificates curl gnupg-agent software-properties-common
   sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
   sudo apt-key fingerprint 0EBFCD88
   sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu \
      $(lsb_release -cs) \
      stable"
   sudo apt-get update

   sudo apt-get install docker-ce docker-ce-cli containerd.io docker-compose

   # Add your user to the docker group
   sudo usermod -aG docker $USER

   # Verify Docker and Compose
   docker --version
   docker compose version

   ```

---

3. **Swarm Initialization**
   a. **CTI-WEB (Manager Node):**

      ```bash
      # Initialize Swarm (replace with your manager node IP)
      docker swarm init --advertise-addr <CTI-WEB-IP>

      ```

      - Copy the `docker swarm join ...` command output for use on the worker node

   b. **CTI-DB (Worker Node):**

      ```bash
      # Use the join command from CTI-WEB output
      docker swarm join --token <WORKER_TOKEN> <CTI-WEB-IP>:2377

      ```

---

4. **Prepare for OpenCTI & Elasticsearch (Both Nodes)**

   ```bash
   # Set sysctl for Elasticsearch
   sudo sysctl -w vm.max_map_count=1048575
   echo "vm.max_map_count=1048575" | sudo tee -a /etc/sysctl.conf

   ```

---

5. **Deploy Portainer Business Edition (Manager Node Only)**

   ```bash
   # Create Portainer deployment directory
   sudo mkdir -p /opt/portainer && cd /opt/portainer

   # Download the latest Portainer agent stack file
   sudo curl -L <https://downloads.portainer.io/portainer-agent-stack.yml> -o portainer-agent-stack.yml

   # Edit the compose file if needed
   sudo nano portainer-agent-stack.yml

   # Deploy Portainer stack
   sudo docker stack deploy --compose-file=portainer-agent-stack.yml portainer

   ```

---

6. **Deploy OpenCTI (Manager Node, via Portainer)**
   - First we’ll fetch the latest base compose file from official repo using the below script base_compose.py
     ```python
     import requests
     from ruamel.yaml import YAML

     # URL of the yml file
     url = "https://raw.githubusercontent.com/OpenCTI-Platform/docker/refs/heads/master/docker-compose.yml"

     # Send a GET request to the URL
     response = requests.get(url)

     # Check if the request was successful
     if response.status_code == 200:
         # Save the content to a file named 'base-compose.yml'
         with open("base-compose.yml", "w") as file:
             file.write(response.text)
         print("YML file has been successfully downloaded and saved as base-compose.yml")

         # Load the YAML content
         yaml = YAML()
         yaml.preserve_quotes = True  # Preserve quotes in the YAML output
         yaml.indent(mapping=2, sequence=4, offset=2)  # Set indentation for better readability
         with open("base-compose.yml", "r") as file:
             compose_data = yaml.load(file)

         # Update the depends_on sections
         for service in compose_data['services']:
             if 'depends_on' in compose_data['services'][service]:
                 depends_on = compose_data['services'][service]['depends_on']
                 if isinstance(depends_on, dict):
                     compose_data['services'][service]['depends_on'] = list(depends_on.keys())

         # Save the updated YAML content
         with open("updated-compose.yml", "w") as file:
             yaml.dump(compose_data, file)
         print("YML file has been successfully updated and saved as updated-compose.yml")
     else:
         print(f"Failed to download the YML file. Status code: {response.status_code}")
     ```
     There are two outputs we’ll get from above script “base-compose.yml” and “updated-compose.yml”, but we’re only interested in updated yaml file, which will probably lools like below as per current git updates on the repo:
     ```yaml
     services:
       redis:
         image: redis:7.4.2
         restart: always
         volumes:
           - redisdata:/data
         healthcheck:
           test: ["CMD", "redis-cli", "ping"]
           interval: 10s
           timeout: 5s
           retries: 3
       elasticsearch:
         image: docker.elastic.co/elasticsearch/elasticsearch:8.18.0
         volumes:
           - esdata:/usr/share/elasticsearch/data
         environment:
           # Comment-out the line below for a cluster of multiple nodes
           - discovery.type=single-node
           # Uncomment the line below below for a cluster of multiple nodes
           # - cluster.name=docker-cluster
           - xpack.ml.enabled=false
           - xpack.security.enabled=false
           - thread_pool.search.queue_size=5000
           - logger.org.elasticsearch.discovery="ERROR"
           - "ES_JAVA_OPTS=-Xms${ELASTIC_MEMORY_SIZE} -Xmx${ELASTIC_MEMORY_SIZE}"
         restart: always
         ulimits:
           memlock:
             soft: -1
             hard: -1
           nofile:
             soft: 65536
             hard: 65536
         healthcheck:
           test: curl -s http://elasticsearch:9200 >/dev/null || exit 1
           interval: 30s
           timeout: 10s
           retries: 50
       minio:
         image: minio/minio:RELEASE.2024-05-28T17-19-04Z # Use "minio/minio:RELEASE.2024-05-28T17-19-04Z-cpuv1" to troubleshoot compatibility issues with CPU
         volumes:
           - s3data:/data
         ports:
           - "9000:9000"
         environment:
           MINIO_ROOT_USER: ${MINIO_ROOT_USER}
           MINIO_ROOT_PASSWORD: ${MINIO_ROOT_PASSWORD}
         command: server /data
         restart: always
         healthcheck:
           test: ["CMD", "mc", "ready", "local"]
           interval: 10s
           timeout: 5s
           retries: 3
       rabbitmq:
         image: rabbitmq:4.1-management
         environment:
           - RABBITMQ_DEFAULT_USER=${RABBITMQ_DEFAULT_USER}
           - RABBITMQ_DEFAULT_PASS=${RABBITMQ_DEFAULT_PASS}
           - RABBITMQ_NODENAME=rabbit01@localhost
         volumes:
           - type: bind
             source: ./rabbitmq.conf
             target: /etc/rabbitmq/rabbitmq.conf
           - amqpdata:/var/lib/rabbitmq
         restart: always
         healthcheck:
           test: rabbitmq-diagnostics -q ping
           interval: 30s
           timeout: 30s
           retries: 3
       opencti:
         image: opencti/platform:6.6.7
         environment:
           - NODE_OPTIONS=--max-old-space-size=8096
           - APP__PORT=8080
           - APP__BASE_URL=${OPENCTI_BASE_URL}
           - APP__ADMIN__EMAIL=${OPENCTI_ADMIN_EMAIL}
           - APP__ADMIN__PASSWORD=${OPENCTI_ADMIN_PASSWORD}
           - APP__ADMIN__TOKEN=${OPENCTI_ADMIN_TOKEN}
           - APP__APP_LOGS__LOGS_LEVEL=error
           - REDIS__HOSTNAME=redis
           - REDIS__PORT=6379
           - ELASTICSEARCH__URL=http://elasticsearch:9200
           - ELASTICSEARCH__NUMBER_OF_REPLICAS=0
           - MINIO__ENDPOINT=minio
           - MINIO__PORT=9000
           - MINIO__USE_SSL=false
           - MINIO__ACCESS_KEY=${MINIO_ROOT_USER}
           - MINIO__SECRET_KEY=${MINIO_ROOT_PASSWORD}
           - RABBITMQ__HOSTNAME=rabbitmq
           - RABBITMQ__PORT=5672
           - RABBITMQ__PORT_MANAGEMENT=15672
           - RABBITMQ__MANAGEMENT_SSL=false
           - RABBITMQ__USERNAME=${RABBITMQ_DEFAULT_USER}
           - RABBITMQ__PASSWORD=${RABBITMQ_DEFAULT_PASS}
           - SMTP__HOSTNAME=${SMTP_HOSTNAME}
           - SMTP__PORT=25
           - PROVIDERS__LOCAL__STRATEGY=LocalStrategy
           - APP__HEALTH_ACCESS_KEY=${OPENCTI_HEALTHCHECK_ACCESS_KEY}
         ports:
           - "8080:8080"
         depends_on:
           - redis
           - elasticsearch
           - minio
           - rabbitmq
         restart: always
         healthcheck:
           test: ["CMD", "wget", "-qO-", "http://opencti:8080/health?health_access_key=${OPENCTI_HEALTHCHECK_ACCESS_KEY}"]
           interval: 10s
           timeout: 5s
           retries: 20
       worker:
         image: opencti/worker:6.6.7
         environment:
           - OPENCTI_URL=http://opencti:8080
           - OPENCTI_TOKEN=${OPENCTI_ADMIN_TOKEN}
           - WORKER_LOG_LEVEL=info
         depends_on:
           - opencti
         deploy:
           mode: replicated
           replicas: 3
         restart: always
       connector-export-file-stix:
         image: opencti/connector-export-file-stix:6.6.7
         environment:
           - OPENCTI_URL=http://opencti:8080
           - OPENCTI_TOKEN=${OPENCTI_ADMIN_TOKEN}
           - CONNECTOR_ID=${CONNECTOR_EXPORT_FILE_STIX_ID} # Valid UUIDv4
           - CONNECTOR_TYPE=INTERNAL_EXPORT_FILE
           - CONNECTOR_NAME=ExportFileStix2
           - CONNECTOR_SCOPE=application/json
           - CONNECTOR_LOG_LEVEL=info
         restart: always
         depends_on:
           - opencti
       connector-export-file-csv:
         image: opencti/connector-export-file-csv:6.6.7
         environment:
           - OPENCTI_URL=http://opencti:8080
           - OPENCTI_TOKEN=${OPENCTI_ADMIN_TOKEN}
           - CONNECTOR_ID=${CONNECTOR_EXPORT_FILE_CSV_ID} # Valid UUIDv4
           - CONNECTOR_TYPE=INTERNAL_EXPORT_FILE
           - CONNECTOR_NAME=ExportFileCsv
           - CONNECTOR_SCOPE=text/csv
           - CONNECTOR_LOG_LEVEL=info
         restart: always
         depends_on:
           - opencti
       connector-export-file-txt:
         image: opencti/connector-export-file-txt:6.6.7
         environment:
           - OPENCTI_URL=http://opencti:8080
           - OPENCTI_TOKEN=${OPENCTI_ADMIN_TOKEN}
           - CONNECTOR_ID=${CONNECTOR_EXPORT_FILE_TXT_ID} # Valid UUIDv4
           - CONNECTOR_TYPE=INTERNAL_EXPORT_FILE
           - CONNECTOR_NAME=ExportFileTxt
           - CONNECTOR_SCOPE=text/plain
           - CONNECTOR_LOG_LEVEL=info
         restart: always
         depends_on:
           - opencti
       connector-import-file-stix:
         image: opencti/connector-import-file-stix:6.6.7
         environment:
           - OPENCTI_URL=http://opencti:8080
           - OPENCTI_TOKEN=${OPENCTI_ADMIN_TOKEN}
           - CONNECTOR_ID=${CONNECTOR_IMPORT_FILE_STIX_ID} # Valid UUIDv4
           - CONNECTOR_TYPE=INTERNAL_IMPORT_FILE
           - CONNECTOR_NAME=ImportFileStix
           - CONNECTOR_VALIDATE_BEFORE_IMPORT=true # Validate any bundle before import
           - CONNECTOR_SCOPE=application/json,text/xml
           - CONNECTOR_AUTO=true # Enable/disable auto-import of file
           - CONNECTOR_LOG_LEVEL=info
         restart: always
         depends_on:
           - opencti
       connector-import-document:
         image: opencti/connector-import-document:6.6.7
         environment:
           - OPENCTI_URL=http://opencti:8080
           - OPENCTI_TOKEN=${OPENCTI_ADMIN_TOKEN}
           - CONNECTOR_ID=${CONNECTOR_IMPORT_DOCUMENT_ID} # Valid UUIDv4
           - CONNECTOR_TYPE=INTERNAL_IMPORT_FILE
           - CONNECTOR_NAME=ImportDocument
           - CONNECTOR_VALIDATE_BEFORE_IMPORT=true # Validate any bundle before import
           - CONNECTOR_SCOPE=application/pdf,text/plain,text/html
           - CONNECTOR_AUTO=true # Enable/disable auto-import of file
           - CONNECTOR_ONLY_CONTEXTUAL=false # Only extract data related to an entity (a report, a threat actor, etc.)
           - CONNECTOR_CONFIDENCE_LEVEL=15 # From 0 (Unknown) to 100 (Fully trusted)
           - CONNECTOR_LOG_LEVEL=info
           - IMPORT_DOCUMENT_CREATE_INDICATOR=true
         restart: always
         depends_on:
           - opencti
       connector-analysis:
         image: opencti/connector-import-document:6.6.7
         environment:
           - OPENCTI_URL=http://opencti:8080
           - OPENCTI_TOKEN=${OPENCTI_ADMIN_TOKEN}
           - CONNECTOR_ID=${CONNECTOR_ANALYSIS_ID} # Valid UUIDv4
           - CONNECTOR_TYPE=INTERNAL_ANALYSIS
           - CONNECTOR_NAME=ImportDocumentAnalysis
           - CONNECTOR_VALIDATE_BEFORE_IMPORT=false # Validate any bundle before import
           - CONNECTOR_SCOPE=application/pdf,text/plain,text/html
           - CONNECTOR_AUTO=true # Enable/disable auto-import of file
           - CONNECTOR_ONLY_CONTEXTUAL=false # Only extract data related to an entity (a report, a threat actor, etc.)
           - CONNECTOR_CONFIDENCE_LEVEL=15 # From 0 (Unknown) to 100 (Fully trusted)
           - CONNECTOR_LOG_LEVEL=info
         restart: always
         depends_on:
           - opencti
     volumes:
       esdata:
       s3data:
       redisdata:
       amqpdata:
     ```
     > Notice the version info on connectors “6.6.7” we will manually change it later, when we create final docker compose file.
   - Then we’ll fetch the connectors we’re interested in for our OpenCTI from script called fetch_connectors.py
     ```python
     import requests
     import uuid

     # Define the base URLs for the repositories
     base_urls = {
         "external-import": "https://raw.githubusercontent.com/OpenCTI-Platform/connectors/master/external-import",
         "internal-enrichment": "https://raw.githubusercontent.com/OpenCTI-Platform/connectors/master/internal-enrichment"
     }

     # List of connectors to fetch (order matters)
     connectors_to_fetch = ["abuseipdb", "abuseipdb-ipblacklist", "abuse-ssl", "alienvault", "cisa-known-exploited-vulnerabilities", "cve", "cyber-campaign-collection", "disarm-framework", "google-dns", "hygiene", "ipinfo", "mitre", "opencti", "threatfox", "urlhaus", "urlhaus-recent-payloads", "virustotal", "yara"]

     # Function to fetch docker-compose.yml content for a given connector
     def fetch_docker_compose_content(connector):
         for repo, base_url in base_urls.items():
             url = f"{base_url}/{connector}/docker-compose.yml"
             response = requests.get(url)
             if response.status_code == 200:
                 return repo, response.text
         return None, None

     # Function to clean and modify the content while preserving indentation
     def clean_and_modify_content(content, connector_id):
         lines = content.split('\n')
         cleaned_lines = []
         for line in lines:
             if line.strip().startswith("version:") or line.strip().startswith("services:"):
                 continue
             if "- OPENCTI_URL" in line:
                 indent = line[:line.index("- OPENCTI_URL")]
                 line = f"{indent}- OPENCTI_URL=http://opencti:8080"
             if "- OPENCTI_TOKEN" in line:
                 indent = line[:line.index("- OPENCTI_TOKEN")]
                 line = f"{indent}- OPENCTI_TOKEN=${{OPENCTI_ADMIN_TOKEN}}"
             if "- CONNECTOR_ID" in line:
                 indent = line[:line.index("- CONNECTOR_ID")]
                 line = f"{indent}- CONNECTOR_ID={connector_id}"
             if "restart: always" in line:
                 indent = line[:line.index("restart: always")]
                 cleaned_lines.append(line)
                 cleaned_lines.append(f"{indent}depends_on:")
                 cleaned_lines.append(f"{indent}  - opencti")
             else:
                 cleaned_lines.append(line)
         return '\n'.join(cleaned_lines)

     # Function to increment UUID
     def increment_uuid(uuid_str):
         uuid_int = int(uuid.UUID(uuid_str))
         incremented_uuid_int = uuid_int + 1
         incremented_uuid_str = str(uuid.UUID(int=incremented_uuid_int))
         return incremented_uuid_str

     # Initial CONNECTOR_ID value
     connector_id = "aaa00000-0000-4aa0-8000-000000000000"

     # Combine docker-compose.yml content
     combined_content = ""
     for connector in connectors_to_fetch:
         repo, content = fetch_docker_compose_content(connector)
         if content:
             cleaned_content = clean_and_modify_content(content, connector_id)
             combined_content += f"# Connector: {connector} (Repo: {repo})\n{cleaned_content}"
             connector_id = increment_uuid(connector_id)

     # Write combined content to a file
     with open('latest_docker-compose.yml', 'w') as file:
         file.write(combined_content)

     ```
     The output from above script will look like below as per recent git updates from there:
     ```yaml
     # Connector: abuseipdb (Repo: internal-enrichment)
       connector-abuseipdb:
         image: opencti/connector-abuseipdb:6.6.7
         environment:
           - OPENCTI_URL=http://opencti:8080
           - OPENCTI_TOKEN=${OPENCTI_ADMIN_TOKEN}
           - CONNECTOR_ID=aaa00000-0000-4aa0-8000-000000000000
           - CONNECTOR_NAME=AbuseIPDB
           - CONNECTOR_SCOPE=IPv4-Addr
           - CONNECTOR_AUTO=true
           - CONNECTOR_CONFIDENCE_LEVEL=15 # From 0 (Unknown) to 100 (Fully trusted)
           - CONNECTOR_LOG_LEVEL=error
           - ABUSEIPDB_API_KEY=ChangeMe
           - ABUSEIPDB_MAX_TLP=TLP:AMBER
         restart: always
         depends_on:
           - opencti
     # Connector: abuseipdb-ipblacklist (Repo: external-import)
       connector-abuseipdb-ipblacklist:
         image: opencti/connector-abuseipdb-ipblacklist:6.6.7
         environment:
           - OPENCTI_URL=http://opencti:8080
           - OPENCTI_TOKEN=${OPENCTI_ADMIN_TOKEN}
           - CONNECTOR_ID=aaa00000-0000-4aa0-8000-000000000001
           - "CONNECTOR_NAME=AbuseIPDB IP Blacklist"
           - CONNECTOR_SCOPE=abuseipdb
           - CONNECTOR_LOG_LEVEL=error
           - ABUSEIPDB_URL=https://api.abuseipdb.com/api/v2/blacklist
           - ABUSEIPDB_API_KEY=ChangeMe
           - ABUSEIPDB_SCORE=100
           - ABUSEIPDB_LIMIT=10000
           - ABUSEIPDB_INTERVAL=2 #Day
         restart: always
         depends_on:
           - opencti
     # Connector: abuse-ssl (Repo: external-import)
       connector-abuse-ssl:
         image: opencti/connector-abuse-ssl:6.6.7
         environment:
           - OPENCTI_URL=http://opencti:8080
           - OPENCTI_TOKEN=${OPENCTI_ADMIN_TOKEN}
           - CONNECTOR_ID=aaa00000-0000-4aa0-8000-000000000002
           - "CONNECTOR_NAME=Abuse.ch SSL Blacklist"
           - CONNECTOR_SCOPE=abusessl
           - CONNECTOR_LOG_LEVEL=error
           - ABUSESSL_URL=https://sslbl.abuse.ch/blacklist/sslipblacklist.csv
           - ABUSESSL_INTERVAL=360 # Time to wait in minutes between subsequent requests
         restart: always
         depends_on:
           - opencti
     # Connector: alienvault (Repo: external-import)
       connector-alienvault:
         image: opencti/connector-alienvault:6.6.7
         environment:
           - OPENCTI_URL=http://opencti:8080
           - OPENCTI_TOKEN=${OPENCTI_ADMIN_TOKEN}
           - CONNECTOR_ID=aaa00000-0000-4aa0-8000-000000000003
           - CONNECTOR_NAME=AlienVault
           - CONNECTOR_SCOPE=alienvault
           - CONNECTOR_LOG_LEVEL=error
           - CONNECTOR_DURATION_PERIOD=PT30M # In ISO8601 Format starting with "P" for Period ex: "PT30M" = Period time of 30 minutes
           - ALIENVAULT_BASE_URL=https://otx.alienvault.com
           - ALIENVAULT_API_KEY=ChangeMe
           - ALIENVAULT_TLP=White
           - ALIENVAULT_CREATE_OBSERVABLES=true
           - ALIENVAULT_CREATE_INDICATORS=true
           - ALIENVAULT_PULSE_START_TIMESTAMP=2022-05-01T00:00:00                  # BEWARE! Could be a lot of pulses!
           - ALIENVAULT_REPORT_TYPE=threat-report
           - ALIENVAULT_REPORT_STATUS=New
           - ALIENVAULT_GUESS_MALWARE=false                                        # Use tags to guess malware.
           - ALIENVAULT_GUESS_CVE=false                                            # Use tags to guess CVE.
           - ALIENVAULT_EXCLUDED_PULSE_INDICATOR_TYPES=FileHash-MD5,FileHash-SHA1  # Excluded Pulse indicator types.
           - ALIENVAULT_ENABLE_RELATIONSHIPS=true                                  # Enable/Disable relationship creation between SDOs.
           - ALIENVAULT_ENABLE_ATTACK_PATTERNS_INDICATES=false                     # Enable/Disable "indicates" relationships between indicators and attack patterns
           - ALIENVAULT_INTERVAL_SEC=1800
           - ALIENVAULT_DEFAULT_X_OPENCTI_SCORE=50
           - ALIENVAULT_X_OPENCTI_SCORE_IP=60
           - ALIENVAULT_X_OPENCTI_SCORE_DOMAIN=70
           - ALIENVAULT_X_OPENCTI_SCORE_HOSTNAME=75
           - ALIENVAULT_X_OPENCTI_SCORE_EMAIL=70
           - ALIENVAULT_X_OPENCTI_SCORE_FILE=85
           - ALIENVAULT_X_OPENCTI_SCORE_URL=80
           - ALIENVAULT_X_OPENCTI_SCORE_MUTEX=60
           - ALIENVAULT_X_OPENCTI_SCORE_CRYPTOCURRENCY_WALLET=80
         restart: always
         depends_on:
           - opencti
     # Connector: cisa-known-exploited-vulnerabilities (Repo: external-import)
       connector-cisa-known-exploited-vulnerabilities:
         image: opencti/connector-cisa-known-exploited-vulnerabilities:6.6.7
         environment:
           - OPENCTI_URL=http://opencti:8080
           - OPENCTI_TOKEN=${OPENCTI_ADMIN_TOKEN}
           - CONNECTOR_ID=aaa00000-0000-4aa0-8000-000000000004
           - "CONNECTOR_NAME=CISA Known Exploited Vulnerabilities"
           - CONNECTOR_SCOPE=cisa
           - CONNECTOR_RUN_AND_TERMINATE=false
           - CONNECTOR_LOG_LEVEL=error
           - CONNECTOR_DURATION_PERIOD=P2D
           - CISA_CATALOG_URL=https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
           - CISA_CREATE_INFRASTRUCTURES=false
           - CISA_TLP=TLP:CLEAR
         restart: always
         depends_on:
           - opencti
     # Connector: cve (Repo: external-import)
       connector-cve:
         image: opencti/connector-cve:6.6.7
         environment:
           - OPENCTI_URL=http://opencti:8080
           - OPENCTI_TOKEN=${OPENCTI_ADMIN_TOKEN}
           - CONNECTOR_ID=aaa00000-0000-4aa0-8000-000000000005
           - CONNECTOR_NAME=Common Vulnerabilities and Exposures
           - CONNECTOR_SCOPE=identity,vulnerability
           - CONNECTOR_RUN_AND_TERMINATE=false
           - CONNECTOR_LOG_LEVEL=error
           - CVE_BASE_URL=https://services.nvd.nist.gov/rest/json/cves
           - CVE_API_KEY=ChangeMe # Required
           - CVE_INTERVAL=2 # Required, in hours advice min 2
           - CVE_MAX_DATE_RANGE=120 # In days, max 120
           - CVE_MAINTAIN_DATA=true # Required, retrieve only updated data
           - CVE_PULL_HISTORY=false # If true, CVE_HISTORY_START_YEAR is required
           - CVE_HISTORY_START_YEAR=2019 # Required if pull_history is True, min 2019 (see documentation CVE and CVSS base score V3.1)
         restart: always
         depends_on:
           - opencti
     # Connector: cyber-campaign-collection (Repo: external-import)
       connector-cyber-campaign-collection:
         image: opencti/connector-cyber-campaign-collection:6.6.7
         environment:
           - OPENCTI_URL=http://opencti:8080
           - OPENCTI_TOKEN=${OPENCTI_ADMIN_TOKEN}
           - CONNECTOR_ID=aaa00000-0000-4aa0-8000-000000000006
           - "CONNECTOR_NAME=APT & Cybercriminals Campaign Collection"
           - CONNECTOR_SCOPE=report
           - CONNECTOR_RUN_AND_TERMINATE=false
           - CONNECTOR_LOG_LEVEL=error
           - CYBER_MONITOR_GITHUB_TOKEN= # If not provided, rate limit will be very low
           - CYBER_MONITOR_FROM_YEAR=2018
           - CYBER_MONITOR_INTERVAL=4 # In days, must be strictly greater than 1
         restart: always
         depends_on:
           - opencti
     # Connector: disarm-framework (Repo: external-import)
       connector-disarm-framework:
         image: opencti/connector-disarm-framework:6.6.7
         environment:
           - OPENCTI_URL=http://opencti:8080
           - OPENCTI_TOKEN=${OPENCTI_ADMIN_TOKEN}
           - CONNECTOR_ID=aaa00000-0000-4aa0-8000-000000000007
           - "CONNECTOR_NAME=DISARM Framework"
           - CONNECTOR_SCOPE=marking-definition,identity,attack-pattern,course-of-action,intrusion-set,campaign,malware,tool,report,narrative,event,channel
           - CONNECTOR_RUN_AND_TERMINATE=false
           - CONNECTOR_LOG_LEVEL=error
           - DISARM_FRAMEWORK_URL=https://raw.githubusercontent.com/DISARMFoundation/DISARMframeworks/main/generated_files/DISARM_STIX/DISARM.json
           - DISARM_FRAMEWORK_INTERVAL=7 # In days, must be strictly greater than 1
         restart: always
         depends_on:
           - opencti
     # Connector: google-dns (Repo: internal-enrichment)
       connector-google-dns:
         image: opencti/connector-google-dns:6.6.7
         environment:
           - OPENCTI_URL=http://opencti:8080
           - OPENCTI_TOKEN=${OPENCTI_ADMIN_TOKEN}
           - CONNECTOR_ID=aaa00000-0000-4aa0-8000-000000000008
           - CONNECTOR_NAME=Google DNS
           - CONNECTOR_SCOPE=Domain-Name,Hostname # MIME type or Stix Object
           - CONNECTOR_AUTO=false
           - CONNECTOR_CONFIDENCE_LEVEL=100 # From 0 (Unknown) to 100 (Fully trusted)
           - CONNECTOR_LOG_LEVEL=error
         restart: always
         depends_on:
           - opencti
     # Connector: hygiene (Repo: internal-enrichment)
       connector-hygiene:
         image: opencti/connector-hygiene:6.6.7
         environment:
           - OPENCTI_URL=http://opencti:8080
           - OPENCTI_TOKEN=${OPENCTI_ADMIN_TOKEN}
           - CONNECTOR_ID=aaa00000-0000-4aa0-8000-000000000009
           - CONNECTOR_NAME=Hygiene
           - CONNECTOR_SCOPE=IPv4-Addr,IPv6-Addr,Domain-Name,StixFile,Artifact
           - CONNECTOR_AUTO=true
           - CONNECTOR_LOG_LEVEL=error
           - HYGIENE_WARNINGLISTS_SLOW_SEARCH=false # Enable warning lists slow search mode
           - HYGIENE_ENRICH_SUBDOMAINS=false # Enrich subdomains with hygiene_parent label if the parents are found in warninglists
         restart: always
         depends_on:
           - opencti
     # Connector: ipinfo (Repo: internal-enrichment)
       connector-ipinfo:
         image: opencti/connector-ipinfo:6.6.7
         environment:
           - OPENCTI_URL=http://opencti:8080
           - OPENCTI_TOKEN=${OPENCTI_ADMIN_TOKEN}
           - CONNECTOR_ID=aaa00000-0000-4aa0-8000-00000000000a
           - CONNECTOR_NAME=IpInfo
           - CONNECTOR_SCOPE=IPv4-Addr,IPv6-Addr
           - CONNECTOR_AUTO=true
           - CONNECTOR_CONFIDENCE_LEVEL=75 # From 0 (Unknown) to 100 (Fully trusted)
           - CONNECTOR_LOG_LEVEL=error
           - IPINFO_TOKEN=ChangeMe
           - IPINFO_MAX_TLP=TLP:AMBER
           - IPINFO_USE_ASN_NAME=true      # Set false if you want ASN name to be just the number e.g. AS8075
         restart: always
         depends_on:
           - opencti
     # Connector: mitre (Repo: external-import)
       connector-mitre:
         image: opencti/connector-mitre:6.6.7
         environment:
           - OPENCTI_URL=http://opencti:8080
           - OPENCTI_TOKEN=${OPENCTI_ADMIN_TOKEN}
           - CONNECTOR_ID=aaa00000-0000-4aa0-8000-00000000000b
           - "CONNECTOR_NAME=MITRE Datasets"
           - CONNECTOR_SCOPE=tool,report,malware,identity,campaign,intrusion-set,attack-pattern,course-of-action,x-mitre-data-source,x-mitre-data-component,x-mitre-matrix,x-mitre-tactic,x-mitre-collection
           - CONNECTOR_RUN_AND_TERMINATE=false
           - CONNECTOR_LOG_LEVEL=error
           - MITRE_REMOVE_STATEMENT_MARKING=true
           - MITRE_INTERVAL=7 # In days
         restart: always
         depends_on:
           - opencti
     # Connector: opencti (Repo: external-import)
       connector-opencti:
         image: opencti/connector-opencti:6.6.7
         environment:
           - OPENCTI_URL=http://opencti:8080
           - OPENCTI_TOKEN=${OPENCTI_ADMIN_TOKEN}
           - CONNECTOR_ID=aaa00000-0000-4aa0-8000-00000000000c
           - "CONNECTOR_NAME=OpenCTI Datasets"
           - CONNECTOR_SCOPE=marking-definition,identity,location
           - CONNECTOR_UPDATE_EXISTING_DATA=true
           - CONNECTOR_RUN_AND_TERMINATE=false
           - CONNECTOR_LOG_LEVEL=error
           - CONFIG_SECTORS_FILE_URL=https://raw.githubusercontent.com/OpenCTI-Platform/datasets/master/data/sectors.json
           - CONFIG_GEOGRAPHY_FILE_URL=https://raw.githubusercontent.com/OpenCTI-Platform/datasets/master/data/geography.json
           - CONFIG_COMPANIES_FILE_URL=https://raw.githubusercontent.com/OpenCTI-Platform/datasets/master/data/companies.json
           - CONFIG_REMOVE_CREATOR=false
           - CONFIG_INTERVAL=7 # In days
         restart: always
         depends_on:
           - opencti
     # Connector: threatfox (Repo: external-import)
       connector-threatfox:
         image: opencti/connector-threatfox:6.6.7
         environment:
           - OPENCTI_URL=http://opencti:8080
           - OPENCTI_TOKEN=${OPENCTI_ADMIN_TOKEN}
           - CONNECTOR_ID=aaa00000-0000-4aa0-8000-00000000000d
           - "CONNECTOR_NAME=Abuse.ch | ThreatFox"
           - CONNECTOR_SCOPE=ThreatFox
           - CONNECTOR_LOG_LEVEL=error
           - THREATFOX_CSV_URL=https://threatfox.abuse.ch/export/csv/recent/
           - THREATFOX_IMPORT_OFFLINE=true
           - THREATFOX_CREATE_INDICATORS=true
           - THREATFOX_DEFAULT_X_OPENCTI_SCORE=50
           - THREATFOX_X_OPENCTI_SCORE_IP=60
           - THREATFOX_X_OPENCTI_SCORE_DOMAIN=70
           - THREATFOX_X_OPENCTI_SCORE_URL=75
           - THREATFOX_X_OPENCTI_SCORE_HASH=80
           - THREATFOX_INTERVAL=3 # In days, must be strictly greater than 1
           - THREATFOX_IOC_TO_IMPORT=ip:port,domain,url # List of IOC types to import
         restart: always
         depends_on:
           - opencti
     # Connector: urlhaus (Repo: external-import)
       connector-urlhaus:
         image: opencti/connector-urlhaus:6.6.7
         environment:
           - OPENCTI_URL=http://opencti:8080
           - OPENCTI_TOKEN=${OPENCTI_ADMIN_TOKEN}
           - CONNECTOR_ID=aaa00000-0000-4aa0-8000-00000000000e
           - "CONNECTOR_NAME=Abuse.ch URLhaus"
           - CONNECTOR_SCOPE=urlhaus
           - CONNECTOR_LOG_LEVEL=error
           - URLHAUS_CSV_URL=https://urlhaus.abuse.ch/downloads/csv_recent/
           - URLHAUS_DEFAULT_X_OPENCTI_SCORE=80 # Optional: Defaults to 80.
           - URLHAUS_IMPORT_OFFLINE=true
           - URLHAUS_THREATS_FROM_LABELS=true
           - URLHAUS_INTERVAL=3 # In days, must be strictly greater than 1
         restart: always
         depends_on:
           - opencti
     # Connector: urlhaus-recent-payloads (Repo: external-import)
       connector-urlhaus-recent-payloads:
         image: opencti/connector-urlhaus-recent-payloads:6.6.7
         environment:
           - OPENCTI_URL=http://opencti:8080
           - OPENCTI_TOKEN=${OPENCTI_ADMIN_TOKEN}
           - CONNECTOR_ID=aaa00000-0000-4aa0-8000-00000000000f
           - "CONNECTOR_NAME=URLhaus Recent Payloads"
           - CONNECTOR_LOG_LEVEL=error
           - URLHAUS_RECENT_PAYLOADS_API_URL=https://urlhaus-api.abuse.ch/v1/
           - URLHAUS_RECENT_PAYLOADS_COOLDOWN_SECONDS=300 # Time to wait in seconds between subsequent requests
           - URLHAUS_RECENT_PAYLOADS_INCLUDE_FILETYPES=exe,dll,docm,docx,doc,xls,xlsx,xlsm,js,xll # (Optional) Only download files if any tag matches. (Comma separated)
           - URLHAUS_RECENT_PAYLOADS_INCLUDE_SIGNATURES= # (Optional) Only download files matching these Yara rules. (Comma separated)
           - URLHAUS_RECENT_PAYLOADS_SKIP_UNKNOWN_FILETYPES=true # Skip files with an unknown file type
           - URLHAUS_RECENT_PAYLOADS_SKIP_NULL_SIGNATURE=true # Skip files that didn't match known Yara rules
           - URLHAUS_RECENT_PAYLOADS_LABELS=urlhaus # (Optional) Labels to apply to uploaded Artifacts. (Comma separated)
           - URLHAUS_RECENT_PAYLOADS_LABELS_COLOR=#54483b
           - URLHAUS_RECENT_PAYLOADS_SIGNATURE_LABEL_COLOR=#0059f7 # Color for Yara rule match label
           - URLHAUS_RECENT_PAYLOADS_FILETYPE_LABEL_COLOR=#54483b # Color to use for filetype label
         restart: always
         depends_on:
           - opencti
     # Connector: virustotal (Repo: internal-enrichment)
       connector-virustotal:
         image: opencti/connector-virustotal:6.6.7
         environment:
           - OPENCTI_URL=http://opencti:8080
           - OPENCTI_TOKEN=${OPENCTI_ADMIN_TOKEN}
           - CONNECTOR_ID=aaa00000-0000-4aa0-8000-000000000010
           - CONNECTOR_NAME=VirusTotal
           - CONNECTOR_SCOPE=StixFile,Artifact,IPv4-Addr,Domain-Name,Url,Hostname
           - CONNECTOR_AUTO=true # Enable/disable auto-enrichment of observables
           - CONNECTOR_LOG_LEVEL=error
           - CONNECTOR_EXPOSE_METRICS=false
           - VIRUSTOTAL_TOKEN=ChangeMe
           - VIRUSTOTAL_MAX_TLP=TLP:AMBER
           - VIRUSTOTAL_REPLACE_WITH_LOWER_SCORE=true # Whether to keep the higher of the VT or existing score (false) or force the score to be updated with the VT score even if its lower than existing score (true).
           # File/Artifact specific config settings
           - VIRUSTOTAL_FILE_CREATE_NOTE_FULL_REPORT=true # Whether or not to include the full report as a Note
           - VIRUSTOTAL_FILE_UPLOAD_UNSEEN_ARTIFACTS=true # Whether to upload artifacts (smaller than 32MB) that VirusTotal has no record of
           - VIRUSTOTAL_FILE_INDICATOR_CREATE_POSITIVES=10 # Create an indicator for File/Artifact based observables once this positive theshold is reached. Note: specify 0 to disable indicator creation
           - VIRUSTOTAL_FILE_INDICATOR_VALID_MINUTES=2880 # How long the indicator is valid for in minutes
           - VIRUSTOTAL_FILE_INDICATOR_DETECT=true # Whether or not to set detection for the indicator to true
           - VIRUSTOTAL_FILE_IMPORT_YARA=true # Whether or not import Crowdsourced YARA rules
           # IP specific config settings
           - VIRUSTOTAL_IP_INDICATOR_CREATE_POSITIVES=10 # Create an indicator for IPv4 based observables once this positive theshold is reached. Note: specify 0 to disable indicator creation
           - VIRUSTOTAL_IP_INDICATOR_VALID_MINUTES=2880 # How long the indicator is valid for in minutes
           - VIRUSTOTAL_IP_INDICATOR_DETECT=true # Whether or not to set detection for the indicator to true
           - VIRUSTOTAL_IP_ADD_RELATIONSHIPS=true # Whether or not to add ASN and location resolution relationships
           # Domain specific config settings
           - VIRUSTOTAL_DOMAIN_INDICATOR_CREATE_POSITIVES=10 # Create an indicator for Domain based observables once this positive theshold is reached. Note: specify 0 to disable indicator creation
           - VIRUSTOTAL_DOMAIN_INDICATOR_VALID_MINUTES=2880 # How long the indicator is valid for in minutes
           - VIRUSTOTAL_DOMAIN_INDICATOR_DETECT=true # Whether or not to set detection for the indicator to true
           - VIRUSTOTAL_DOMAIN_ADD_RELATIONSHIPS=true # Whether or not to add IP resolution relationships
           # URL specific config settings
           - VIRUSTOTAL_URL_UPLOAD_UNSEEN=true # Whether to upload URLs that VirusTotal has no record of for analysis
           - VIRUSTOTAL_URL_INDICATOR_CREATE_POSITIVES=10 # Create an indicator for Url based observables once this positive theshold is reached. Note: specify 0 to disable indicator creation
           - VIRUSTOTAL_URL_INDICATOR_VALID_MINUTES=2880 # How long the indicator is valid for in minutes
           - VIRUSTOTAL_URL_INDICATOR_DETECT=true # Whether or not to set detection for the indicator to true
         deploy:
           mode: replicated
           replicas: 1
         restart: always
         depends_on:
           - opencti
     # Connector: yara (Repo: internal-enrichment)
       connector-yara:
         image: opencti/connector-yara:6.6.7
         environment:
           - OPENCTI_URL=http://opencti:8080
           - OPENCTI_TOKEN=${OPENCTI_ADMIN_TOKEN}
           - CONNECTOR_ID=aaa00000-0000-4aa0-8000-000000000011
           - CONNECTOR_NAME=YARA
           - CONNECTOR_SCOPE=Artifact # MIME type or Stix Object
           - CONNECTOR_AUTO=true
           - CONNECTOR_CONFIDENCE_LEVEL=100 # From 0 (Unknown) to 100 (Fully trusted)
           - CONNECTOR_LOG_LEVEL=error
         restart: always
         depends_on:
           - opencti
     ```
     > Notice the version info on connectors “6.6.7” we will manually change it later, when we create final docker compose file.
   - Now we’ll try to merge these files, with some customization, which I couldn’t figure out the logic to do in python, like using the env variable instead of hardcoding version info. And to merge files in such a way, that output from second script should be appended in between the output of first script, anyway this is how it’ll look:
     ```yaml
     services:
       redis:
         image: redis:7.4.2
         restart: always
         volumes:
           - redisdata:/data
         healthcheck:
           test: ["CMD", "redis-cli", "ping"]
           interval: 10s
           timeout: 5s
           retries: 3
       elasticsearch:
         image: docker.elastic.co/elasticsearch/elasticsearch:8.18.0
         volumes:
           - esdata:/usr/share/elasticsearch/data
         environment:
           # Comment-out the line below for a cluster of multiple nodes
           - discovery.type=single-node
           # Uncomment the line below below for a cluster of multiple nodes
           # - cluster.name=docker-cluster
           - xpack.ml.enabled=false
           - xpack.security.enabled=false
           - thread_pool.search.queue_size=5000
           - logger.org.elasticsearch.discovery="ERROR"
           - "ES_JAVA_OPTS=-Xms${ELASTIC_MEMORY_SIZE} -Xmx${ELASTIC_MEMORY_SIZE}"
         restart: always
         ulimits:
           memlock:
             soft: -1
             hard: -1
           nofile:
             soft: 65536
             hard: 65536
         healthcheck:
           test: curl -s http://elasticsearch:9200 >/dev/null || exit 1
           interval: 30s
           timeout: 10s
           retries: 50
       minio:
         image: minio/minio:RELEASE.2024-05-28T17-19-04Z # Use "minio/minio:RELEASE.2024-05-28T17-19-04Z-cpuv1" to troubleshoot compatibility issues with CPU
         volumes:
           - s3data:/data
         ports:
           - "9000:9000"
         environment:
           MINIO_ROOT_USER: ${MINIO_ROOT_USER}
           MINIO_ROOT_PASSWORD: ${MINIO_ROOT_PASSWORD}
         command: server /data
         restart: always
         healthcheck:
           test: ["CMD", "mc", "ready", "local"]
           interval: 10s
           timeout: 5s
           retries: 3
       rabbitmq:
         image: rabbitmq:4.1-management
         environment:
           - RABBITMQ_DEFAULT_USER=${RABBITMQ_DEFAULT_USER}
           - RABBITMQ_DEFAULT_PASS=${RABBITMQ_DEFAULT_PASS}
           - RABBITMQ_NODENAME=rabbit01@localhost
         volumes:
           - type: bind
             source: ./rabbitmq.conf
             target: /etc/rabbitmq/rabbitmq.conf
           - amqpdata:/var/lib/rabbitmq
         restart: always
         healthcheck:
           test: rabbitmq-diagnostics -q ping
           interval: 30s
           timeout: 30s
           retries: 3
       opencti:
         image: opencti/platform:${OPENCTI_VERSION}
         environment:
           - NODE_OPTIONS=--max-old-space-size=8096
           - APP__PORT=8080
           - APP__BASE_URL=${OPENCTI_BASE_URL}
           - APP__ADMIN__EMAIL=${OPENCTI_ADMIN_EMAIL}
           - APP__ADMIN__PASSWORD=${OPENCTI_ADMIN_PASSWORD}
           - APP__ADMIN__TOKEN=${OPENCTI_ADMIN_TOKEN}
           - APP__APP_LOGS__LOGS_LEVEL=error
           - REDIS__HOSTNAME=redis
           - REDIS__PORT=6379
           - ELASTICSEARCH__URL=http://elasticsearch:9200
           - ELASTICSEARCH__NUMBER_OF_REPLICAS=0
           - MINIO__ENDPOINT=minio
           - MINIO__PORT=9000
           - MINIO__USE_SSL=false
           - MINIO__ACCESS_KEY=${MINIO_ROOT_USER}
           - MINIO__SECRET_KEY=${MINIO_ROOT_PASSWORD}
           - RABBITMQ__HOSTNAME=rabbitmq
           - RABBITMQ__PORT=5672
           - RABBITMQ__PORT_MANAGEMENT=15672
           - RABBITMQ__MANAGEMENT_SSL=false
           - RABBITMQ__USERNAME=${RABBITMQ_DEFAULT_USER}
           - RABBITMQ__PASSWORD=${RABBITMQ_DEFAULT_PASS}
           - SMTP__HOSTNAME=${SMTP_HOSTNAME}
           - SMTP__PORT=25
           - PROVIDERS__LOCAL__STRATEGY=LocalStrategy
           - APP__HEALTH_ACCESS_KEY=${OPENCTI_HEALTHCHECK_ACCESS_KEY}
         ports:
           - "8080:8080"
         depends_on:
           - redis
           - elasticsearch
           - minio
           - rabbitmq
         restart: always
         healthcheck:
           test: ["CMD", "wget", "-qO-", "http://opencti:8080/health?health_access_key=${OPENCTI_HEALTHCHECK_ACCESS_KEY}"]
           interval: 10s
           timeout: 5s
           retries: 20
       worker:
         image: opencti/worker:${OPENCTI_VERSION}
         environment:
           - OPENCTI_URL=http://opencti:8080
           - OPENCTI_TOKEN=${OPENCTI_ADMIN_TOKEN}
           - WORKER_LOG_LEVEL=info
         depends_on:
           - opencti
         deploy:
           mode: replicated
           replicas: 3
         restart: always
       connector-export-file-stix:
         image: opencti/connector-export-file-stix:${OPENCTI_VERSION}
         environment:
           - OPENCTI_URL=http://opencti:8080
           - OPENCTI_TOKEN=${OPENCTI_ADMIN_TOKEN}
           - CONNECTOR_ID=${CONNECTOR_EXPORT_FILE_STIX_ID} # Valid UUIDv4
           - CONNECTOR_TYPE=INTERNAL_EXPORT_FILE
           - CONNECTOR_NAME=ExportFileStix2
           - CONNECTOR_SCOPE=application/json
           - CONNECTOR_LOG_LEVEL=info
         restart: always
         depends_on:
           - opencti
       connector-export-file-csv:
         image: opencti/connector-export-file-csv:${OPENCTI_VERSION}
         environment:
           - OPENCTI_URL=http://opencti:8080
           - OPENCTI_TOKEN=${OPENCTI_ADMIN_TOKEN}
           - CONNECTOR_ID=${CONNECTOR_EXPORT_FILE_CSV_ID} # Valid UUIDv4
           - CONNECTOR_TYPE=INTERNAL_EXPORT_FILE
           - CONNECTOR_NAME=ExportFileCsv
           - CONNECTOR_SCOPE=text/csv
           - CONNECTOR_LOG_LEVEL=info
         restart: always
         depends_on:
           - opencti
       connector-export-file-txt:
         image: opencti/connector-export-file-txt:${OPENCTI_VERSION}
         environment:
           - OPENCTI_URL=http://opencti:8080
           - OPENCTI_TOKEN=${OPENCTI_ADMIN_TOKEN}
           - CONNECTOR_ID=${CONNECTOR_EXPORT_FILE_TXT_ID} # Valid UUIDv4
           - CONNECTOR_TYPE=INTERNAL_EXPORT_FILE
           - CONNECTOR_NAME=ExportFileTxt
           - CONNECTOR_SCOPE=text/plain
           - CONNECTOR_LOG_LEVEL=info
         restart: always
         depends_on:
           - opencti
       connector-import-file-stix:
         image: opencti/connector-import-file-stix:${OPENCTI_VERSION}
         environment:
           - OPENCTI_URL=http://opencti:8080
           - OPENCTI_TOKEN=${OPENCTI_ADMIN_TOKEN}
           - CONNECTOR_ID=${CONNECTOR_IMPORT_FILE_STIX_ID} # Valid UUIDv4
           - CONNECTOR_TYPE=INTERNAL_IMPORT_FILE
           - CONNECTOR_NAME=ImportFileStix
           - CONNECTOR_VALIDATE_BEFORE_IMPORT=true # Validate any bundle before import
           - CONNECTOR_SCOPE=application/json,text/xml
           - CONNECTOR_AUTO=true # Enable/disable auto-import of file
           - CONNECTOR_LOG_LEVEL=info
         restart: always
         depends_on:
           - opencti
       connector-import-document:
         image: opencti/connector-import-document:${OPENCTI_VERSION}
         environment:
           - OPENCTI_URL=http://opencti:8080
           - OPENCTI_TOKEN=${OPENCTI_ADMIN_TOKEN}
           - CONNECTOR_ID=${CONNECTOR_IMPORT_DOCUMENT_ID} # Valid UUIDv4
           - CONNECTOR_TYPE=INTERNAL_IMPORT_FILE
           - CONNECTOR_NAME=ImportDocument
           - CONNECTOR_VALIDATE_BEFORE_IMPORT=true # Validate any bundle before import
           - CONNECTOR_SCOPE=application/pdf,text/plain,text/html
           - CONNECTOR_AUTO=true # Enable/disable auto-import of file
           - CONNECTOR_ONLY_CONTEXTUAL=false # Only extract data related to an entity (a report, a threat actor, etc.)
           - CONNECTOR_CONFIDENCE_LEVEL=15 # From 0 (Unknown) to 100 (Fully trusted)
           - CONNECTOR_LOG_LEVEL=info
           - IMPORT_DOCUMENT_CREATE_INDICATOR=true
         restart: always
         depends_on:
           - opencti
       connector-analysis:
         image: opencti/connector-import-document:${OPENCTI_VERSION}
         environment:
           - OPENCTI_URL=http://opencti:8080
           - OPENCTI_TOKEN=${OPENCTI_ADMIN_TOKEN}
           - CONNECTOR_ID=${CONNECTOR_ANALYSIS_ID} # Valid UUIDv4
           - CONNECTOR_TYPE=INTERNAL_ANALYSIS
           - CONNECTOR_NAME=ImportDocumentAnalysis
           - CONNECTOR_VALIDATE_BEFORE_IMPORT=false # Validate any bundle before import
           - CONNECTOR_SCOPE=application/pdf,text/plain,text/html
           - CONNECTOR_AUTO=true # Enable/disable auto-import of file
           - CONNECTOR_ONLY_CONTEXTUAL=false # Only extract data related to an entity (a report, a threat actor, etc.)
           - CONNECTOR_CONFIDENCE_LEVEL=15 # From 0 (Unknown) to 100 (Fully trusted)
           - CONNECTOR_LOG_LEVEL=info
         restart: always
         depends_on:
           - opencti
     # Connector: abuseipdb (Repo: internal-enrichment)
       connector-abuseipdb:
         image: opencti/connector-abuseipdb:${OPENCTI_VERSION}
         environment:
           - OPENCTI_URL=http://opencti:8080
           - OPENCTI_TOKEN=${OPENCTI_ADMIN_TOKEN}
           - CONNECTOR_ID=aaa00000-0000-4aa0-8000-000000000000
           - CONNECTOR_NAME=AbuseIPDB
           - CONNECTOR_SCOPE=IPv4-Addr
           - CONNECTOR_AUTO=true
           - CONNECTOR_CONFIDENCE_LEVEL=15 # From 0 (Unknown) to 100 (Fully trusted)
           - CONNECTOR_LOG_LEVEL=error
           - ABUSEIPDB_API_KEY=${ABUSEIPDB_API_KEY}
           - ABUSEIPDB_MAX_TLP=TLP:AMBER
         restart: always
         depends_on:
           - opencti
     # Connector: abuseipdb-ipblacklist (Repo: external-import)
       connector-abuseipdb-ipblacklist:
         image: opencti/connector-abuseipdb-ipblacklist:${OPENCTI_VERSION}
         environment:
           - OPENCTI_URL=http://opencti:8080
           - OPENCTI_TOKEN=${OPENCTI_ADMIN_TOKEN}
           - CONNECTOR_ID=aaa00000-0000-4aa0-8000-000000000001
           - "CONNECTOR_NAME=AbuseIPDB IP Blacklist"
           - CONNECTOR_SCOPE=abuseipdb
           - CONNECTOR_LOG_LEVEL=error
           - ABUSEIPDB_URL=https://api.abuseipdb.com/api/v2/blacklist
           - ABUSEIPDB_API_KEY=${ABUSEIPDB_API_KEY}
           - ABUSEIPDB_SCORE=100
           - ABUSEIPDB_LIMIT=10000
           - ABUSEIPDB_INTERVAL=2 #Day
         restart: always
         depends_on:
           - opencti
     # Connector: abuse-ssl (Repo: external-import)
       connector-abuse-ssl:
         image: opencti/connector-abuse-ssl:${OPENCTI_VERSION}
         environment:
           - OPENCTI_URL=http://opencti:8080
           - OPENCTI_TOKEN=${OPENCTI_ADMIN_TOKEN}
           - CONNECTOR_ID=aaa00000-0000-4aa0-8000-000000000002
           - "CONNECTOR_NAME=Abuse.ch SSL Blacklist"
           - CONNECTOR_SCOPE=abusessl
           - CONNECTOR_LOG_LEVEL=error
           - ABUSESSL_URL=https://sslbl.abuse.ch/blacklist/sslipblacklist.csv
           - ABUSESSL_INTERVAL=360 # Time to wait in minutes between subsequent requests
         restart: always
         depends_on:
           - opencti
     # Connector: alienvault (Repo: external-import)
       connector-alienvault:
         image: opencti/connector-alienvault:${OPENCTI_VERSION}
         environment:
           - OPENCTI_URL=http://opencti:8080
           - OPENCTI_TOKEN=${OPENCTI_ADMIN_TOKEN}
           - CONNECTOR_ID=aaa00000-0000-4aa0-8000-000000000003
           - CONNECTOR_NAME=AlienVault
           - CONNECTOR_SCOPE=alienvault
           - CONNECTOR_LOG_LEVEL=error
           - CONNECTOR_DURATION_PERIOD=PT30M # In ISO8601 Format starting with "P" for Period ex: "PT30M" = Period time of 30 minutes
           - ALIENVAULT_BASE_URL=https://otx.alienvault.com
           - ALIENVAULT_API_KEY=${ALIENVAULT_API_KEY}
           - ALIENVAULT_TLP=White
           - ALIENVAULT_CREATE_OBSERVABLES=true
           - ALIENVAULT_CREATE_INDICATORS=true
           - ALIENVAULT_PULSE_START_TIMESTAMP=2022-05-01T00:00:00                  # BEWARE! Could be a lot of pulses!
           - ALIENVAULT_REPORT_TYPE=threat-report
           - ALIENVAULT_REPORT_STATUS=New
           - ALIENVAULT_GUESS_MALWARE=false                                        # Use tags to guess malware.
           - ALIENVAULT_GUESS_CVE=false                                            # Use tags to guess CVE.
           - ALIENVAULT_EXCLUDED_PULSE_INDICATOR_TYPES=FileHash-MD5,FileHash-SHA1  # Excluded Pulse indicator types.
           - ALIENVAULT_ENABLE_RELATIONSHIPS=true                                  # Enable/Disable relationship creation between SDOs.
           - ALIENVAULT_ENABLE_ATTACK_PATTERNS_INDICATES=false                     # Enable/Disable "indicates" relationships between indicators and attack patterns
           - ALIENVAULT_INTERVAL_SEC=1800
           - ALIENVAULT_DEFAULT_X_OPENCTI_SCORE=50
           - ALIENVAULT_X_OPENCTI_SCORE_IP=60
           - ALIENVAULT_X_OPENCTI_SCORE_DOMAIN=70
           - ALIENVAULT_X_OPENCTI_SCORE_HOSTNAME=75
           - ALIENVAULT_X_OPENCTI_SCORE_EMAIL=70
           - ALIENVAULT_X_OPENCTI_SCORE_FILE=85
           - ALIENVAULT_X_OPENCTI_SCORE_URL=80
           - ALIENVAULT_X_OPENCTI_SCORE_MUTEX=60
           - ALIENVAULT_X_OPENCTI_SCORE_CRYPTOCURRENCY_WALLET=80
         restart: always
         depends_on:
           - opencti
     # Connector: cisa-known-exploited-vulnerabilities (Repo: external-import)
       connector-cisa-known-exploited-vulnerabilities:
         image: opencti/connector-cisa-known-exploited-vulnerabilities:${OPENCTI_VERSION}
         environment:
           - OPENCTI_URL=http://opencti:8080
           - OPENCTI_TOKEN=${OPENCTI_ADMIN_TOKEN}
           - CONNECTOR_ID=aaa00000-0000-4aa0-8000-000000000004
           - "CONNECTOR_NAME=CISA Known Exploited Vulnerabilities"
           - CONNECTOR_SCOPE=cisa
           - CONNECTOR_RUN_AND_TERMINATE=false
           - CONNECTOR_LOG_LEVEL=error
           - CONNECTOR_DURATION_PERIOD=P2D
           - CISA_CATALOG_URL=https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
           - CISA_CREATE_INFRASTRUCTURES=false
           - CISA_TLP=TLP:CLEAR
         restart: always
         depends_on:
           - opencti
     # Connector: cve (Repo: external-import)
       connector-cve:
         image: opencti/connector-cve:${OPENCTI_VERSION}
         environment:
           - OPENCTI_URL=http://opencti:8080
           - OPENCTI_TOKEN=${OPENCTI_ADMIN_TOKEN}
           - CONNECTOR_ID=aaa00000-0000-4aa0-8000-000000000005
           - CONNECTOR_NAME=Common Vulnerabilities and Exposures
           - CONNECTOR_SCOPE=identity,vulnerability
           - CONNECTOR_RUN_AND_TERMINATE=false
           - CONNECTOR_LOG_LEVEL=error
           - CVE_BASE_URL=https://services.nvd.nist.gov/rest/json/cves
           - CVE_API_KEY=${CVE_API_KEY} # Required
           - CVE_INTERVAL=2 # Required, in hours advice min 2
           - CVE_MAX_DATE_RANGE=120 # In days, max 120
           - CVE_MAINTAIN_DATA=true # Required, retrieve only updated data
           - CVE_PULL_HISTORY=false # If true, CVE_HISTORY_START_YEAR is required
           - CVE_HISTORY_START_YEAR=2019 # Required if pull_history is True, min 2019 (see documentation CVE and CVSS base score V3.1)
         restart: always
         depends_on:
           - opencti
     # Connector: cyber-campaign-collection (Repo: external-import)
       connector-cyber-campaign-collection:
         image: opencti/connector-cyber-campaign-collection:${OPENCTI_VERSION}
         environment:
           - OPENCTI_URL=http://opencti:8080
           - OPENCTI_TOKEN=${OPENCTI_ADMIN_TOKEN}
           - CONNECTOR_ID=aaa00000-0000-4aa0-8000-000000000006
           - "CONNECTOR_NAME=APT & Cybercriminals Campaign Collection"
           - CONNECTOR_SCOPE=report
           - CONNECTOR_RUN_AND_TERMINATE=false
           - CONNECTOR_LOG_LEVEL=error
           - CYBER_MONITOR_GITHUB_TOKEN= # If not provided, rate limit will be very low
           - CYBER_MONITOR_FROM_YEAR=2018
           - CYBER_MONITOR_INTERVAL=4 # In days, must be strictly greater than 1
         restart: always
         depends_on:
           - opencti
     # Connector: disarm-framework (Repo: external-import)
       connector-disarm-framework:
         image: opencti/connector-disarm-framework:${OPENCTI_VERSION}
         environment:
           - OPENCTI_URL=http://opencti:8080
           - OPENCTI_TOKEN=${OPENCTI_ADMIN_TOKEN}
           - CONNECTOR_ID=aaa00000-0000-4aa0-8000-000000000007
           - "CONNECTOR_NAME=DISARM Framework"
           - CONNECTOR_SCOPE=marking-definition,identity,attack-pattern,course-of-action,intrusion-set,campaign,malware,tool,report,narrative,event,channel
           - CONNECTOR_RUN_AND_TERMINATE=false
           - CONNECTOR_LOG_LEVEL=error
           - DISARM_FRAMEWORK_URL=https://raw.githubusercontent.com/DISARMFoundation/DISARMframeworks/main/generated_files/DISARM_STIX/DISARM.json
           - DISARM_FRAMEWORK_INTERVAL=7 # In days, must be strictly greater than 1
         restart: always
         depends_on:
           - opencti
     # Connector: google-dns (Repo: internal-enrichment)
       connector-google-dns:
         image: opencti/connector-google-dns:${OPENCTI_VERSION}
         environment:
           - OPENCTI_URL=http://opencti:8080
           - OPENCTI_TOKEN=${OPENCTI_ADMIN_TOKEN}
           - CONNECTOR_ID=aaa00000-0000-4aa0-8000-000000000008
           - CONNECTOR_NAME=Google DNS
           - CONNECTOR_SCOPE=Domain-Name,Hostname # MIME type or Stix Object
           - CONNECTOR_AUTO=false
           - CONNECTOR_CONFIDENCE_LEVEL=100 # From 0 (Unknown) to 100 (Fully trusted)
           - CONNECTOR_LOG_LEVEL=error
         restart: always
         depends_on:
           - opencti
     # Connector: hygiene (Repo: internal-enrichment)
       connector-hygiene:
         image: opencti/connector-hygiene:${OPENCTI_VERSION}
         environment:
           - OPENCTI_URL=http://opencti:8080
           - OPENCTI_TOKEN=${OPENCTI_ADMIN_TOKEN}
           - CONNECTOR_ID=aaa00000-0000-4aa0-8000-000000000009
           - CONNECTOR_NAME=Hygiene
           - CONNECTOR_SCOPE=IPv4-Addr,IPv6-Addr,Domain-Name,StixFile,Artifact
           - CONNECTOR_AUTO=true
           - CONNECTOR_LOG_LEVEL=error
           - HYGIENE_WARNINGLISTS_SLOW_SEARCH=false # Enable warning lists slow search mode
           - HYGIENE_ENRICH_SUBDOMAINS=false # Enrich subdomains with hygiene_parent label if the parents are found in warninglists
         restart: always
         depends_on:
           - opencti
     # Connector: ipinfo (Repo: internal-enrichment)
       connector-ipinfo:
         image: opencti/connector-ipinfo:${OPENCTI_VERSION}
         environment:
           - OPENCTI_URL=http://opencti:8080
           - OPENCTI_TOKEN=${OPENCTI_ADMIN_TOKEN}
           - CONNECTOR_ID=aaa00000-0000-4aa0-8000-00000000000a
           - CONNECTOR_NAME=IpInfo
           - CONNECTOR_SCOPE=IPv4-Addr,IPv6-Addr
           - CONNECTOR_AUTO=true
           - CONNECTOR_CONFIDENCE_LEVEL=75 # From 0 (Unknown) to 100 (Fully trusted)
           - CONNECTOR_LOG_LEVEL=error
           - IPINFO_TOKEN=${IPINFO_TOKEN}
           - IPINFO_MAX_TLP=TLP:AMBER
           - IPINFO_USE_ASN_NAME=true      # Set false if you want ASN name to be just the number e.g. AS8075
         restart: always
         depends_on:
           - opencti
     # Connector: mitre (Repo: external-import)
       connector-mitre:
         image: opencti/connector-mitre:${OPENCTI_VERSION}
         environment:
           - OPENCTI_URL=http://opencti:8080
           - OPENCTI_TOKEN=${OPENCTI_ADMIN_TOKEN}
           - CONNECTOR_ID=aaa00000-0000-4aa0-8000-00000000000b
           - "CONNECTOR_NAME=MITRE Datasets"
           - CONNECTOR_SCOPE=tool,report,malware,identity,campaign,intrusion-set,attack-pattern,course-of-action,x-mitre-data-source,x-mitre-data-component,x-mitre-matrix,x-mitre-tactic,x-mitre-collection
           - CONNECTOR_RUN_AND_TERMINATE=false
           - CONNECTOR_LOG_LEVEL=error
           - MITRE_REMOVE_STATEMENT_MARKING=true
           - MITRE_INTERVAL=7 # In days
         restart: always
         depends_on:
           - opencti
     # Connector: opencti (Repo: external-import)
       connector-opencti:
         image: opencti/connector-opencti:${OPENCTI_VERSION}
         environment:
           - OPENCTI_URL=http://opencti:8080
           - OPENCTI_TOKEN=${OPENCTI_ADMIN_TOKEN}
           - CONNECTOR_ID=aaa00000-0000-4aa0-8000-00000000000c
           - "CONNECTOR_NAME=OpenCTI Datasets"
           - CONNECTOR_SCOPE=marking-definition,identity,location
           - CONNECTOR_UPDATE_EXISTING_DATA=true
           - CONNECTOR_RUN_AND_TERMINATE=false
           - CONNECTOR_LOG_LEVEL=error
           - CONFIG_SECTORS_FILE_URL=https://raw.githubusercontent.com/OpenCTI-Platform/datasets/master/data/sectors.json
           - CONFIG_GEOGRAPHY_FILE_URL=https://raw.githubusercontent.com/OpenCTI-Platform/datasets/master/data/geography.json
           - CONFIG_COMPANIES_FILE_URL=https://raw.githubusercontent.com/OpenCTI-Platform/datasets/master/data/companies.json
           - CONFIG_REMOVE_CREATOR=false
           - CONFIG_INTERVAL=7 # In days
         restart: always
         depends_on:
           - opencti
     # Connector: threatfox (Repo: external-import)
       connector-threatfox:
         image: opencti/connector-threatfox:${OPENCTI_VERSION}
         environment:
           - OPENCTI_URL=http://opencti:8080
           - OPENCTI_TOKEN=${OPENCTI_ADMIN_TOKEN}
           - CONNECTOR_ID=aaa00000-0000-4aa0-8000-00000000000d
           - "CONNECTOR_NAME=Abuse.ch | ThreatFox"
           - CONNECTOR_SCOPE=ThreatFox
           - CONNECTOR_LOG_LEVEL=error
           - THREATFOX_CSV_URL=https://threatfox.abuse.ch/export/csv/recent/
           - THREATFOX_IMPORT_OFFLINE=true
           - THREATFOX_CREATE_INDICATORS=true
           - THREATFOX_DEFAULT_X_OPENCTI_SCORE=50
           - THREATFOX_X_OPENCTI_SCORE_IP=60
           - THREATFOX_X_OPENCTI_SCORE_DOMAIN=70
           - THREATFOX_X_OPENCTI_SCORE_URL=75
           - THREATFOX_X_OPENCTI_SCORE_HASH=80
           - THREATFOX_INTERVAL=3 # In days, must be strictly greater than 1
           - THREATFOX_IOC_TO_IMPORT=ip:port,domain,url # List of IOC types to import
         restart: always
         depends_on:
           - opencti
     # Connector: urlhaus (Repo: external-import)
       connector-urlhaus:
         image: opencti/connector-urlhaus:${OPENCTI_VERSION}
         environment:
           - OPENCTI_URL=http://opencti:8080
           - OPENCTI_TOKEN=${OPENCTI_ADMIN_TOKEN}
           - CONNECTOR_ID=aaa00000-0000-4aa0-8000-00000000000e
           - "CONNECTOR_NAME=Abuse.ch URLhaus"
           - CONNECTOR_SCOPE=urlhaus
           - CONNECTOR_LOG_LEVEL=error
           - URLHAUS_CSV_URL=https://urlhaus.abuse.ch/downloads/csv_recent/
           - URLHAUS_DEFAULT_X_OPENCTI_SCORE=80 # Optional: Defaults to 80.
           - URLHAUS_IMPORT_OFFLINE=true
           - URLHAUS_THREATS_FROM_LABELS=true
           - URLHAUS_INTERVAL=3 # In days, must be strictly greater than 1
         restart: always
         depends_on:
           - opencti
     # Connector: urlhaus-recent-payloads (Repo: external-import)
       connector-urlhaus-recent-payloads:
         image: opencti/connector-urlhaus-recent-payloads:${OPENCTI_VERSION}
         environment:
           - OPENCTI_URL=http://opencti:8080
           - OPENCTI_TOKEN=${OPENCTI_ADMIN_TOKEN}
           - CONNECTOR_ID=aaa00000-0000-4aa0-8000-00000000000f
           - "CONNECTOR_NAME=URLhaus Recent Payloads"
           - CONNECTOR_LOG_LEVEL=error
           - URLHAUS_RECENT_PAYLOADS_API_URL=https://urlhaus-api.abuse.ch/v1/
           - URLHAUS_RECENT_PAYLOADS_COOLDOWN_SECONDS=300 # Time to wait in seconds between subsequent requests
           - URLHAUS_RECENT_PAYLOADS_INCLUDE_FILETYPES=exe,dll,docm,docx,doc,xls,xlsx,xlsm,js,xll # (Optional) Only download files if any tag matches. (Comma separated)
           - URLHAUS_RECENT_PAYLOADS_INCLUDE_SIGNATURES= # (Optional) Only download files matching these Yara rules. (Comma separated)
           - URLHAUS_RECENT_PAYLOADS_SKIP_UNKNOWN_FILETYPES=true # Skip files with an unknown file type
           - URLHAUS_RECENT_PAYLOADS_SKIP_NULL_SIGNATURE=true # Skip files that didn't match known Yara rules
           - URLHAUS_RECENT_PAYLOADS_LABELS=urlhaus # (Optional) Labels to apply to uploaded Artifacts. (Comma separated)
           - URLHAUS_RECENT_PAYLOADS_LABELS_COLOR=#54483b
           - URLHAUS_RECENT_PAYLOADS_SIGNATURE_LABEL_COLOR=#0059f7 # Color for Yara rule match label
           - URLHAUS_RECENT_PAYLOADS_FILETYPE_LABEL_COLOR=#54483b # Color to use for filetype label
         restart: always
         depends_on:
           - opencti
     # Connector: virustotal (Repo: internal-enrichment)
       connector-virustotal:
         image: opencti/connector-virustotal:${OPENCTI_VERSION}
         environment:
           - OPENCTI_URL=http://opencti:8080
           - OPENCTI_TOKEN=${OPENCTI_ADMIN_TOKEN}
           - CONNECTOR_ID=aaa00000-0000-4aa0-8000-000000000010
           - CONNECTOR_NAME=VirusTotal
           - CONNECTOR_SCOPE=StixFile,Artifact,IPv4-Addr,Domain-Name,Url,Hostname
           - CONNECTOR_AUTO=true # Enable/disable auto-enrichment of observables
           - CONNECTOR_LOG_LEVEL=error
           - CONNECTOR_EXPOSE_METRICS=false
           - VIRUSTOTAL_TOKEN=${VIRUSTOTAL_TOKEN}
           - VIRUSTOTAL_MAX_TLP=TLP:AMBER
           - VIRUSTOTAL_REPLACE_WITH_LOWER_SCORE=true # Whether to keep the higher of the VT or existing score (false) or force the score to be updated with the VT score even if its lower than existing score (true).
           # File/Artifact specific config settings
           - VIRUSTOTAL_FILE_CREATE_NOTE_FULL_REPORT=true # Whether or not to include the full report as a Note
           - VIRUSTOTAL_FILE_UPLOAD_UNSEEN_ARTIFACTS=true # Whether to upload artifacts (smaller than 32MB) that VirusTotal has no record of
           - VIRUSTOTAL_FILE_INDICATOR_CREATE_POSITIVES=10 # Create an indicator for File/Artifact based observables once this positive theshold is reached. Note: specify 0 to disable indicator creation
           - VIRUSTOTAL_FILE_INDICATOR_VALID_MINUTES=2880 # How long the indicator is valid for in minutes
           - VIRUSTOTAL_FILE_INDICATOR_DETECT=true # Whether or not to set detection for the indicator to true
           - VIRUSTOTAL_FILE_IMPORT_YARA=true # Whether or not import Crowdsourced YARA rules
           # IP specific config settings
           - VIRUSTOTAL_IP_INDICATOR_CREATE_POSITIVES=10 # Create an indicator for IPv4 based observables once this positive theshold is reached. Note: specify 0 to disable indicator creation
           - VIRUSTOTAL_IP_INDICATOR_VALID_MINUTES=2880 # How long the indicator is valid for in minutes
           - VIRUSTOTAL_IP_INDICATOR_DETECT=true # Whether or not to set detection for the indicator to true
           - VIRUSTOTAL_IP_ADD_RELATIONSHIPS=true # Whether or not to add ASN and location resolution relationships
           # Domain specific config settings
           - VIRUSTOTAL_DOMAIN_INDICATOR_CREATE_POSITIVES=10 # Create an indicator for Domain based observables once this positive theshold is reached. Note: specify 0 to disable indicator creation
           - VIRUSTOTAL_DOMAIN_INDICATOR_VALID_MINUTES=2880 # How long the indicator is valid for in minutes
           - VIRUSTOTAL_DOMAIN_INDICATOR_DETECT=true # Whether or not to set detection for the indicator to true
           - VIRUSTOTAL_DOMAIN_ADD_RELATIONSHIPS=true # Whether or not to add IP resolution relationships
           # URL specific config settings
           - VIRUSTOTAL_URL_UPLOAD_UNSEEN=true # Whether to upload URLs that VirusTotal has no record of for analysis
           - VIRUSTOTAL_URL_INDICATOR_CREATE_POSITIVES=10 # Create an indicator for Url based observables once this positive theshold is reached. Note: specify 0 to disable indicator creation
           - VIRUSTOTAL_URL_INDICATOR_VALID_MINUTES=2880 # How long the indicator is valid for in minutes
           - VIRUSTOTAL_URL_INDICATOR_DETECT=true # Whether or not to set detection for the indicator to true
         deploy:
           mode: replicated
           replicas: 1
         restart: always
         depends_on:
           - opencti
     # Connector: yara (Repo: internal-enrichment)
       connector-yara:
         image: opencti/connector-yara:${OPENCTI_VERSION}
         environment:
           - OPENCTI_URL=http://opencti:8080
           - OPENCTI_TOKEN=${OPENCTI_ADMIN_TOKEN}
           - CONNECTOR_ID=aaa00000-0000-4aa0-8000-000000000011
           - CONNECTOR_NAME=YARA
           - CONNECTOR_SCOPE=Artifact # MIME type or Stix Object
           - CONNECTOR_AUTO=true
           - CONNECTOR_CONFIDENCE_LEVEL=100 # From 0 (Unknown) to 100 (Fully trusted)
           - CONNECTOR_LOG_LEVEL=error
         restart: always
         depends_on:
           - opencti

     volumes:
       esdata:
       s3data:
       redisdata:
       amqpdata:
     ```
   - Now we need to use the portainer, to create opencti stack and use the above docker compose file. And we’ll also include env variables file, which will look like below:
     ```yaml
     OPENCTI_VERSION=<opencti_version>
     ABUSEIPDB_API_KEY=<your_api_key_here>
     ALIENVAULT_API_KEY=<your_api_key_here>
     CROWDSEC_KEY=<your_api_key_here>
     CVE_API_KEY=<your_api_key_here>
     IPINFO_TOKEN=<your_api_key_here>
     VIRUSTOTAL_TOKEN=<your_api_key_here>

     OPENCTI_ADMIN_EMAIL=first.last@domain.com
     OPENCTI_ADMIN_PASSWORD=<your_password_here>
     OPENCTI_ADMIN_TOKEN=aaa00000-0000-2aa0-8000-000000000000
     OPENCTI_BASE_URL=http://localhost:8080
     OPENCTI_HEALTHCHECK_ACCESS_KEY=aaa00000-0000-2aa0-8000-000000000001
     MINIO_ROOT_USER=opencti
     MINIO_ROOT_PASSWORD=<your_password_here>
     RABBITMQ_DEFAULT_USER=opencti
     RABBITMQ_DEFAULT_PASS=<your_password_here>
     CONNECTOR_EXPORT_FILE_STIX_ID=aaa00000-0000-2aa0-8000-000000000003
     CONNECTOR_EXPORT_FILE_CSV_ID=aaa00000-0000-2aa0-8000-000000000004
     CONNECTOR_EXPORT_FILE_TXT_ID=aaa00000-0000-2aa0-8000-000000000005
     CONNECTOR_IMPORT_FILE_STIX_ID=aaa00000-0000-2aa0-8000-000000000006
     CONNECTOR_IMPORT_DOCUMENT_ID=aaa00000-0000-2aa0-8000-000000000007
     CONNECTOR_ANALYSIS_ID=aaa00000-0000-2aa0-8000-000000000008
     SMTP_HOSTNAME=localhost
     ELASTIC_MEMORY_SIZE=4G
     ```
