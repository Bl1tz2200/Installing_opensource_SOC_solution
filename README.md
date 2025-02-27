# Installing_opensource_SOC_solution
I've made the instruction, that will help you with installing your own Security Operations Center consisting of opensourse systems. 

SOC's solution made by these opensource systems:
- SIEM (Security Information and Event Management) as ELK Stack (Elasticsearch, Kibana, Logstash) + Suricata
- NTA (Network Traffic Analysis) as Opensearch + Arkime
- EDR (Endpoint Detection and Response) as OSSEC
- Other utilites, such as filebeat, logrotate, iptables to make SOC more useful


# Select the host operating system
I'll be using Ubuntu 22.04, but you can take any other version. In the installation I'll be using packages, that's actual for ubuntu 22.04. 

If you want to install other operating system, please check the official's installing pages of the systems that are used in this instruction:
- ELK Stack and filebeat - https://www.elastic.co/guide/en/elastic-stack/current/installing-elastic-stack.html
- Suricata - https://suricata.io/download/
- Arkime - https://arkime.com/install
- OSSEC - https://habr.com/ru/articles/192800/


# Time to start
First install updates and some utilites
```bash
sudo apt update -y
sudo apt upgrade -y
sudo apt install -y wget curl ca-certificates
```
As the text editor I'll be using **vi**


# Suricata
Let's install Suricata
```bash
sudo apt install -y software-properties-common
sudo add-apt-repository -y ppa:oisf/suricata-stable
sudo apt update
sudo apt install -y suricata
```
Now configure configuration file to add your network in Suricata
```bash
sudo cp /etc/suricata/suricata.yaml /etc/suricata/suricata.yaml.bak # Making backup of config file
sudo vi /etc/suricata/suricata.yaml #edit HOME_NET with your params
```
And run Suricata with entering interface that it will listen to
```bash
sudo suricata -c /etc/suricata/suricata.yaml -i <your_interface> # Runs suricata
```


# Elasticsearch
Let's install Elasticsearch
```bash
wget https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-8.17.2-amd64.deb
wget https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-8.17.2-amd64.deb.sha512
shasum -a 512 -c elasticsearch-8.17.2-amd64.deb.sha512 
sudo dpkg -i elasticsearch-8.17.2-amd64.deb
```
After the correct installing in the console you can see the password of superuser named elastic. You should add it to the environtment.
```bash
export ES_PASSWORD="YOUR_superuser_OUTPUT_PASSWORD" # Password for elastic will be shown after first start
```
Then enable elasticsearch and start it
```bash
sudo /bin/systemctl daemon-reload
sudo /bin/systemctl enable elasticsearch.service
sudo systemctl start elasticsearch.service
```
Then let's create elasticsearch sertificates to work with the https protocol. I'll unzip certs in the `/etc/elasticsearch` after creating them
```bash
sudo /usr/share/elasticsearch/bin/elasticsearch-certutil http # creating SSL certs
sudo mkdir /etc/elasticcerts/
sudo unzip /usr/share/elasticsearch/elasticsearch-ssl-http.zip -d /etc/elasticcerts/
sudo cp /etc/elasticcerts/ca/ca.p12 /etc/elasticsearch/elastic-stack-ca.p12 # Add center of authentication cert to the elasticsearch folder
```
Then add self-signed certs to know
```bash
sudo openssl s_client -showcerts -connect localhost:9200 < /dev/null | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' > ca.crt # Adding certs
sudo cp ca.crt /usr/local/share/ca-certificates/
sudo update-ca-certificates
```
Let's configure rollover to update old indexes, that's reaches 2 GB size or older, that 1 day
```bash
curl -X PUT -u elastic:"${ES_PASSWORD}" "https://localhost:9200/_ilm/policy/stream_policy?pretty" -H 'Content-Type: application/json' -d'
{
  "policy": {                       
    "phases": {
      "hot": {                      
        "actions": {                             
          "rollover": {             
            "max_size": "2GB",
            "max_age": "1d"
          }
        }
      },
      "delete": {
        "min_age": "1d",           
        "actions": {
          "delete": {}              
        }
      }
    }
  }
}'
```
And I'll configure watermark limits to make more space for logs
```bash
curl -X PUT -u elastic:"${ES_PASSWORD}" "https://localhost:9200/_cluster/settings?pretty" -H 'Content-Type: application/json' -d'
{
  "persistent": {
    "cluster.routing.allocation.disk.watermark.low": "90%",
    "cluster.routing.allocation.disk.watermark.low.max_headroom": "100GB",
    "cluster.routing.allocation.disk.watermark.high": "95%",
    "cluster.routing.allocation.disk.watermark.high.max_headroom": "20GB",
    "cluster.routing.allocation.disk.watermark.flood_stage": "97%",
    "cluster.routing.allocation.disk.watermark.flood_stage.max_headroom": "5GB",
    "cluster.routing.allocation.disk.watermark.flood_stage.frozen": "97%",
    "cluster.routing.allocation.disk.watermark.flood_stage.frozen.max_headroom": "5GB"
  }
}'
```
To remove writing block if you've reached watermark you should set read_only_allow_delete to null, but if you haven't cleared your storage, elasticsearch will return read_only_allow_delete to true state
```bash
curl -X PUT -u elastic:"${ES_PASSWORD}" "https://localhost:9200/*/_settings?expand_wildcards=all&pretty" -H 'Content-Type: application/json' -d'
{                                                                                                           
  "index.blocks.read_only_allow_delete": null                                                               
}'
```


# Kibana
Installing Kibana
```bash
wget https://artifacts.elastic.co/downloads/kibana/kibana-8.17.2-amd64.deb
shasum -a 512 kibana-8.17.2-amd64.deb 
sudo dpkg -i kibana-8.17.2-amd64.deb
```
Then configure kibana.yml
```bash
sudo cp /etc/kibana/kibana.yml /etc/kibana/kibana.yml.bak # Making backup of config file
sudo vi /etc/kibana/kibana.yml # Configure host IP address
```
After configuring kibana, auth it inside elasticsearch by enrollment token
```bash
sudo /usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s kibana # Getting auth token
sudo /usr/share/kibana/bin/kibana-setup # Enter here your token, that you've got from the previous command
```
In the end enable and start kibana
```bash
sudo /bin/systemctl daemon-reload
sudo /bin/systemctl enable kibana.service
sudo systemctl start kibana.service
```
If you want to add ssl for kibana web you should create ssl certificate using elasticsearch by next command

Don't forget to enter your kibana's ip address
```bash
sudo /usr/share/elasticsearch/bin/elasticsearch-certutil cert  -ca /etc/elasticsearch/elastic-stack-ca.p12 -name kibana-certificate -dns kibana01,<your_kibana_ip>,127.0.0.1,localhost -ip <your_kibana_ip> # Here we'll generate kibana certs to host kibana by https.
sudo cp /usr/share/elasticsearch/kibana-certificate.p12 /usr/share/kibana/ # Copy certificate to the kibana's dir
```
Then in the end of the `/etc/kibana/kibana.yml` add your certification info:
```bash
server.ssl.enabled: true
server.ssl.keystore.path: "/etc/kibana/kibana-certificate.p12"
server.ssl.truststore.path: "/etc/elasticsearch/elastic-stack-ca.p12"
```
After all add cert's passwords to kibana keystorage and restart kibana
```bash
sudo /usr/share/kibana/bin/kibana-keystore add server.ssl.keystore.password
sudo /usr/share/kibana/bin/kibana-keystore add server.ssl.truststore.password
sudo systemctl restart kibana.service
```


# Logstash
Now install logstash and add elasticsearch cert
```bash
wget https://artifacts.elastic.co/downloads/logstash/logstash-8.17.2-amd64.deb
sudo dpkg -i logstash-8.17.2-amd64.deb
sudo cp /etc/elasticcerts/kibana/elasticsearch-ca.pem /etc/logstash/
```
Then create logstash conf files, that will create pipelines to the elasticsearch

Here will be created filebeat input and elasticsearch output files. After that logstash will start
```bash
cat << EOF | sudo tee /etc/logstash/conf.d/beats_input.conf  # Creating filebeat input configuration 
input {
 beats {
   port => 5044

 }
}
EOF

cat << EOF | sudo tee /etc/logstash/conf.d/elasticsearch-output.conf # Creating elasticsearch output configuration
output {

  if [@metadata][pipeline] {

         elasticsearch {

         hosts => ["localhost:9200"]

         manage_template => false

         index => "%{[@metadata][beat]}-%{[@metadata][version]}-%{+YYYY.MM.dd}"

         pipeline => "%{[@metadata][pipeline]}"

	 ssl => true
	 ssl_certificate_verification => false
    	 cacert => '/etc/elasticcerts/kibana/elasticsearch-ca.pem'

	 user => "elastic"
   	 password => "${ES_PASSWORD}"

         }

  } else {

         elasticsearch {

         hosts => ["localhost:9200"]

         manage_template => false

         index => "%{[@metadata][beat]}-%{[@metadata][version]}-%{+YYYY.MM.dd}"

	 ssl => true
	 ssl_certificate_verification => false
    	 cacert => '/etc/elasticcerts/kibana/elasticsearch-ca.pem'

	 user => "elastic"
   	 password => "${ES_PASSWORD}"

         }

  }

}
EOF

sudo systemctl start logstash
```


# Filebeat
Install filebeat
```bash
curl -L -O https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-8.17.2-amd64.deb
sudo dpkg -i filebeat-8.17.2-amd64.deb
```
Now let's configure modules that will be used in filebeat. As for me it is system and suricata. Each module should be enabled and have created pipeline

Enable module system
```bash
sudo filebeat modules enable system
sudo vi /etc/filebeat/modules.d/system.yml # Set true on enabled of syslog and auth if it's not
```
Create pipeline for system
```bash
sudo filebeat setup --pipelines --modules system
```
Enable module suricata
```bash
sudo filebeat modules enable suricata
sudo vi /etc/filebeat/modules.d/suricata.yml # Set true on enabled of eve and add var.paths: ["/var/log/suricata/eve.json"]
```
Create pipeline for suricata
```bash
sudo filebeat setup --pipelines --modules suricata
```
After enabling module suricata you'll need to configure filebeat.yml to add suricata's log. You should add in `filebeat.inputs` part in `paths` var these lines:
```bash
- /var/log/suricata/eve.json
- /var/log/*.log.*
```
To add filebeat's dashboards to kibana first configure filebeat.yml
```bash
sudo cp /etc/filebeat/filebeat.yml /etc/filebeat/filebeat.yml.bak # Making backup of config file
sudo vi /etc/filebeat/filebeat.yml # Configure Elasticksearch Output with entering hosts, username: elastic and password that you can check with echo $ES_PASSWORD.
# Don't forget to uncomment protocol: https
```
Then upload index and dashboards

Don't forget to enter your kibana's ip address
```bash
sudo filebeat setup --index-management #Upload index templates
sudo filebeat setup --dashboards -E setup.kibana.host=<your_kibana_ip>:5601
```
After setting up dashboard reconfigure filebeat.yml to work with logstash
```bash
sudo vi /etc/filebeat/filebeat.yml # Go back, comment all, what you've configured in Elasticksearch Output and uncomment Logstash Output with hosts
```
In the end enable and start filebeat. After starting in kibana's web you can see dashboards, check if \[Filebeat System\] Syslog dashboard ECS works
```bash
sudo filebeat setup -e
sudo systemctl start filebeat
sudo systemctl enable filebeat
```
**To make your graphics and other visualisation work in elasticsearch you should add .keyword to all field param inside setting of the element (ex. host.hostname => host.hostname.keyword).**


# Arkime
Before installing opensearch for arkime set **OPENSEARCH_INITIAL_ADMIN_PASSWORD** in `/etc/variable`. 
You should change this password, if it isn't strong enough install will fail. 
Minimum 10 character password and must contain at least one uppercase letter, one lowercase letter, one digit, and one special character.

Then install opensearch for arkime
```bash
wget https://artifacts.opensearch.org/releases/bundle/opensearch/2.13.0/opensearch-2.13.0-linux-x64.deb
sudo dpkg -i opensearch-2.13.0-linux-x64.deb
```
When installing is done configure opensearch
```bash
sudo cp /etc/opensearch/opensearch.yml /etc/opensearch/opensearch.yml.bak # Making backup of config file
sudo vi /etc/opensearch/opensearch.yml # Change http port to 9100 (9200 is already Elasticsearch)
```
Now enable and run opensearch
```bash
sudo systemctl enable opensearch
sudo systemctl start opensearch
```
If opensearch have started correct install arkime
```bash
sudo apt update -y
sudo apt install -y wget iproute2 ethtool
wget https://github.com/arkime/arkime/releases/download/v5.4.0/arkime_5.4.0-1.ubuntu2204_amd64.deb
sudo apt install -y ./arkime_5.4.0-1.ubuntu2204_amd64.deb
```
Then configure arkime from console
```bash
sudo /opt/arkime/bin/Configure # Make arkime configuration, opensearch user is admin
```
After configuration erase opensearch db
```bash
/opt/arkime/db/db.pl --esuser admin https://localhost:9100 init # Init db, enter opensearch password
```
And then add admin user with entered password

Don't forget to enter your admin's password
```bash
/opt/arkime/bin/arkime_add_user.sh admin "Admin User" <enter_here_your_password> --admin # Add admin user for web-interface
```
Update geo and start arkime
```bash
sudo /opt/arkime/bin/arkime_update_geo.sh # Updating geo (If don't it would't start)
sudo systemctl enable --now arkimecapture # Start arkime capture service
sudo systemctl enable --now arkimeviewer # Start arkime traffic viewer service
```


# OSSEC
Install OSSEC
```bash
sudo apt install libz-dev libssl-dev libpcre2-dev build-essential libsystemd-dev make gcc libssl-dev -y
wget https://github.com/ossec/ossec-hids/archive/3.8.0.tar.gz
tar xzvf 3.8.0.tar.gz
```
Then run installation. I'll install OSSEC server at the first computer and agents on other
```bash
sudo ./ossec-hids-3.8.0/install.sh # First installing server
```

I'll recommend to add inside <syscheck> in `/var/ossec/etc/ossec.conf` 2 lines: scan files on startup and alert when new file created:
```bash
<scan_on_start>yes</scan_on_start>
<alert_new_files>yes</alert_new_files>
```

And I'll recomend to change remove 1003 syslog rule, that checks number of chars in one line of the log in /var/log/syslog. It can cause syslog spam because logstash often creates long logs. I'll recoment to change BAD_WORDS var in rule 1002 too because it checks if $BAD_WORDS appears inside syslog file and can be mistakenly triggered.

Rules to remove is in `/var/ossec/rules/syslog_rules.xml` and it looks like that:
```
<rule id="1003" level="13" maxsize="1025">
    <description>Non standard syslog message (size too large).</description>
</rule>
```

To add agent you'll need to get their tokens first:
```bash
sudo /var/ossec/bin/manage_agents # A for adding new agent (ip should be with subnet mask ex: 192.168.1.117/24) then E for extracting key
```
After adding agents restart OSSEC
```bash
sudo /var/ossec/bin/ossec-control restart # Restart after
sudo systemctl enable ossec
```

Now let's move to the agent's computers
```
sudo ./ossec-hids-3.8.0/install.sh # Installing agent
```
Then creating sender. OSSEC removes previous sender and if there won't be removable file there will be ERROR: Cannot unlink /queue/rids/sender: No such file or directory, that's why creating empty file because it's first start
```bash
sudo touch /var/ossec/queue/rids/sender 
```
Now import key from OSSEC server
```bash
sudo /var/ossec/bin/manage_agents # Importing key from OSSEC-server
```
After importing key configure connection to the OSSEC server
```bash
sudo vi /var/ossec/etc/ossec.conf # Changing OSSEC server ip address to your
```
And start OSSEC
```bash
sudo /var/ossec/bin/ossec-control start
sudo systemctl start ossec # then service
sudo systemctl enable ossec # Adding service start on power on
```
**If you want to change OSSEC server token you should stop ossec and ossec-control, delete in `/var/ossec/queue/rids` number of your agent and then do all steps again**

To check if agent works check connection in the OSSEC server by:
```bash
sudo /var/ossec/bin/agent_control -l
```
Now let's add OSSEC logs to ELK

First in `/var/ossec/etc/ossec.conf` in <ossec_config> add log stream:
```
<syslog_output>
                <server>127.0.0.1</server>
                <port>5001</port>
                <format>default</format>
</syslog_output>
```
Now run commands below to create logstash OSSEC's config files and restart it
```
cat << EOF | sudo tee /etc/logstash/conf.d/OSSEC-logstash.conf # Creating OSSEC input conf for logstash
input {

  udp {
     port => 5001
     type => "ossec"
  }

}

filter {
  if "ossec" in [type] {

    grok {
      match => { "message" => "%{SYSLOGTIMESTAMP:syslog_timestamp} %{SYSLOGHOST:syslog_host} %{DATA:syslog_program}: Alert Level: %{NONNEGINT:Alert_Level}; Rule: %{NONNEGINT:Rule} - %{DATA:Description}; Location: %{DATA:Location}; (user: %{USER:User};%{SPACE})?(srcip: %{IP:Src_IP};%{SPACE})?(user: %{USER:User};%{SPACE})?(dstip: %{IP:Dst_IP};%{SPACE})?(src_port: %{NONNEGINT:Src_Port};%{SPACE})?(dst_port: %{NONNEGINT:Dst_Port};%{SPACE})?%{GREEDYDATA:Details}" }
    }

    mutate {
      remove_field => [ "message","syslog_timestamp", "syslog_program", "syslog_host", "syslog_message", "syslog_pid", "@version", "type", "host" ]
    }

  }
}

output {

  elasticsearch {

    hosts => ["localhost:9200"]

    ssl => true
    ssl_certificate_verification => false
    cacert => '/etc/elasticcerts/kibana/elasticsearch-ca.pem'

    user => "elastic"
    password => "${ES_PASSWORD}"

  }

  stdout { codec => rubydebug }

}
EOF

sudo systemctl restart logstash # Restarting logstash

sudo /var/ossec/bin/ossec-control enable client-syslog # Enabling OSSEC data transmit 

sudo /var/ossec/bin/ossec-control restart # Restartting OSSEC
```
***To add OSSEC in kibana web: Stack Management => Data views => Create data view - Index pattern: logs-generic-* (Name you'll use to find this data view)=> Save data view to Kibana. Then create own dashboard using Data view of OSSEC.**

# Logrotate
To prevend from getting out of space I'll create logrotate files, that will split file into different archives and older of them will be removed. By default lograte rotates many logs such as arkime log.

I'll create logrotate for syslog file and suricata's logs
```
sudo apt install logrotate -y

cat << EOF | sudo tee /etc/logrotate.d/syslog # Syslog rotate separately from rsyslog. Rotate if it reaches 10 GB or file is older that 1 hour and store 2 copy
su root syslog

/var/log/syslog
{
	hourly
	create
	rotate 2
	size 10G
	nocompress
	notifempty
	sharedscripts
        postrotate
                /usr/lib/rsyslog/rsyslog-rotate
        endscript
}
EOF

cat << EOF | sudo tee /etc/logrotate.d/suricata # Suricata rotate if file is older than one week and store 3 copies
/var/log/suricata/*.log /var/log/suricata/*.json
{
	weekly
	rotate 3
	missingok
	nocompress
	create
	sharedscripts
	postrotate
	/bin/kill -HUP `cat /var/run/suricata.pid 2>/dev/null` 2>/dev/null || true
	endscript
}
EOF


cat << EOF | sudo tee /etc/logrotate.d/rsyslog # Changing existing rotate file to remove /etc/syslog from it
su root syslog

/var/log/mail.info
/var/log/mail.warn
/var/log/mail.err
/var/log/mail.log
/var/log/daemon.log
/var/log/kern.log
/var/log/auth.log
/var/log/user.log
/var/log/lpr.log
/var/log/cron.log
/var/log/debug
/var/log/messages
{
        rotate 4
        weekly
        missingok
        notifempty
        compress
        delaycompress
        sharedscripts
        postrotate
                /usr/lib/rsyslog/rsyslog-rotate
        endscript
}
EOF    
```
Then check logrotate with running debug and run first rotate
```bash
sudo logrotate -d /etc/logrotate.d/*
sudo logrotate -v /etc/logrotate.d/*
```
After all add logrotate to the sudo cron for checking if rotate is needed every minute. Run:
```bash
sudo crontab -e
```
And add
```
* * * * * logrotate -v /etc/logrotate.d/*
```
# Additions
If you want to see and analyse net traffic from your linux agent you should use iptables -j TEE

Don't forget to enter your SOC server ip address
```bash
sudo iptables -t mangle -A INPUT -j TEE --gateway <your_SOC_server_ip>
```
