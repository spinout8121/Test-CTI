Below are **step-by-step, up-to-date commands** for both CTI-WEB (manager) and CTI-DB (worker), including best practices from the latest official documentation.

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

1. **Install Latest Docker Engine & Compose Plugin (Both Nodes)**

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

1. **Swarm Initialization**
   1. **CTI-WEB (Manager Node):**

      ```bash
      # Initialize Swarm (replace with your manager node IP)
      docker swarm init --advertise-addr <CTI-WEB-IP>

      ```

      - Copy the `docker swarm join ...` command output for use on the worker node

   2. **CTI-DB (Worker Node):**

      ```bash
      # Use the join command from CTI-WEB output
      docker swarm join --token <WORKER_TOKEN> <CTI-WEB-IP>:2377

      ```

---

1. **Prepare for OpenCTI & Elasticsearch (Both Nodes)**

   ```bash
   # Set sysctl for Elasticsearch
   sudo sysctl -w vm.max_map_count=1048575
   echo "vm.max_map_count=1048575" | sudo tee -a /etc/sysctl.conf

   ```

---

1. **Deploy Portainer Business Edition (Manager Node Only)**

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

1. **Deploy OpenCTI (Manager Node, via Portainer)**
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
     There are two outputs we’ll get from above script “base-compose.yml” and “updated-compose.yml”, but we’re only interested in updated yaml file, which we will use to spin up the opencti UI
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
   - Now once we fetch the connectors yml files from their repo, we will include it in our base file to spin up the final opencti with all our connectors that can start populating the data
   - To spin up OpenCTI, we’ll portainer, to create opencti stack and use the above docker compose file. And we’ll also include env variables file, which will look like below:
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
