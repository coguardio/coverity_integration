
% Evaluation of cluster `demo_cluster_1`
% By CoGuard
% Tue Oct 24 2023 11:28:13 GMT+0000 (Coordinated Universal Time)
# Summary of Findings and Introduction
## Final Score
5.47/10

Scoring is between 1-10, where 1 is the least favorable, and 10 is the most favorable.

The full scope of the CoGuard Evaluation is based on the file manifest located inside the zip called `cluster_snapshot.zip`.
This documents the configuration files used to describe the devices, networks, applications and systems included in this evaluation.
The evaluation compares the configuration files and parameters as evidence of meeting the system requirements based on applicable trust services criteria.
There are limitations in the evaluation. The evaluation only looks at the configuration files and parameters provided.
There are inherent limitations in any system of internal control, including the possibility of human error and the circumvention of controls.

This report, including the description of tests of controls and results, is intended solely for the information and use of management of foobar.

# Findings


## `mongodb_authentication_sharded_cluster`
**Severity:** 5

It is best to distribute the load to different MongoDB instances. MongoDB accomplishes this by sharding the database. In a sharded cluster, one needs to ensure that authentication is enabled and connections are only done using SSL/TLS.

**Remediation:**
Set `net.ssl.mode` to `requireTLS` and set the `net.ssl.certificateKeyFile` to the path of the respective certificate. Furthermore, the key `net.ssl.clusterFile` or resp. ` net.tls.clusterCertificateSelector` should also contain the path the the key file for membership authentication.


*Sources*:

 - https://docs.mongodb.com/manual/reference/configuration-options/#net.ssl.mode
 - https://docs.mongodb.com/manual/reference/configuration-options/#net.tls.mode

## `apache_load_security_module`
**Severity:** 5

ModSecurity is a module that acts as a web application firewall for monitoring, logging, and access control. It should always be loaded and configured.

**Remediation:**
Load the module by adding `LoadModule security2_module modules/mod_security2.so`.


*Sources*:

 - https://www.modsecurity.org/download.html

## `apache_enable_ssl`
**Severity:** 5

We should never have any communication done using unencrypted channels. This check tests if the mod_ssl.so module is loaded and that SSLProtocol is set, together with a proper SSL certificate file and a key file.

**Remediation:**
Load the `mod_ssl.so` modules, and set the `SSLCertificateFile` and `SSLCertificateKeyFile` keys to the paths of the respective certificate and key file.


*Sources*:

 - https://httpd.apache.org/docs/current/mod/mod_ssl.html

## `apache_root_directory_options_none`
**Severity:** 5

With the options directive, one can allow scripts to be executed, follow symlinks, do content negotiation, etc. In the root directory, the Options directive should always be set to None.

**Remediation:**
Create a <Directory> Options None </Directory> directive.


*Sources*:

 - https://httpd.apache.org/docs/2.4/mod/core.html#directory

## `apache_deny_root_directory`
**Severity:** 5

Ensure that the root directory access is specifically denied. Otherwise, it is possible that an attacker can gain access to files through root directory mapping.

**Remediation:**
Create a <Directory> Require all denied </Directory> directive.


*Sources*:

 - https://httpd.apache.org/docs/2.4/mod/core.html#directory

## `kafka_no_plaintext_listening`
**Severity:** 5

There is a configuration for the Kafka brokers specifying a communication protocol for each one of them. One of the options is PLAINTEXT, which means that the broker is communicating without any encryption or authorization. A secure Kafka cluster should not be configured in this way.

**Remediation:**
For any `listeners` directive, the prefix should never be `PLAINTEXT`.


*Sources*:

 - https://kafka.apache.org/documentation/#brokerconfigs

## `hadoop_encrypt_block_data_transfer`
**Severity:** 5

By default, Hadoop does not encrypt the data transfer between nodes. This means that data is transferred unencrypted through the wires and a malicious player on the same network can extract potentially sensitive data.

**Remediation:**
Set `dfs.encrypt.data.transfer` to `true`.


*Sources*:

 - https://hadoop.apache.org/docs/stable/hadoop-project-dist/hadoop-common/SecureMode.html

## `mongodb_require_authorization`
**Severity:** 5

By default, there is no access control on databases in MongoDB.

**Remediation:**
There is a configuration parameter which needs to be set to the value 'enabled', which is under the security options, and is called 'authorization.


*Sources*:

 - https://docs.mongodb.com/manual/reference/configuration-options/#security-options

## `postgres_do_not_allow_trust_auth`
**Severity:** 5

The pg_hba file is defining the different connection and authentication processes for a specific Postgres instance. One should always need to authenticate, i.e. the method for authentication should never be `trust`.

**Remediation:**
For every line in `pg_hba.conf`, ensure that no line has `trust` as authentication method.


*Sources*:

 - https://www.postgresql.org/docs/current/auth-pg-hba-conf.html

## `postgres_allowed_connections_only_ssl`
**Severity:** 5

The pg_hba file is defining the different connection and authentication processes for a specific Postgres instance. It should never be possible to log in to Postgres without having SSL enabled.

**Remediation:**
Set the connection type in each line to either `local` or `hostssl`.


*Sources*:

 - https://www.postgresql.org/docs/current/auth-pg-hba-conf.html

## `postgres_enable_ssl_traffic`
**Severity:** 5

The communication to the database should always be encrypted.

**Remediation:**
Set the `ssl` directive to `on`.


*Sources*:

 - https://www.postgresql.org/docs/current/ssl-tcp.html

## `nginx_enforce_ssl`
**Severity:** 5

SSL should always be enabled, i.e. no cleartext communication. This can be checked in NGINX by adding ssl to the listen arguments.

**Remediation:**
Set `ssl` at the end of every listen directive (unless it is in a path that forwards to an SSL directive).


*Sources*:

 - https://nginx.org/en/docs/http/configuring_https_servers.html

## `mongodb_fips_mode_enabled`
**Severity:** 4

FIPSMode (Federal Information Processing Standard) is a standard used to certify software to encrypt and decrypt data securely. Setting FIPSMode to true ensures that MongoDB only runs with such a certified library for OpenSSL.

**Remediation:**
Set `net.ssl.FIPSMode` or `net.tls.FIPSMode` to `true` (default is `false`).


*Sources*:

 - https://docs.mongodb.com/manual/reference/configuration-options/#net.tls.FIPSMode

## `mongodb_ensure_activity_is_audited`
**Severity:** 4

Part of a good security practice is to perform audit logging. In MongoDB, one needs to set the destination of the audit log specifically. It is also recommended to set a system log destination specifically.

**Remediation:**
Specifically set the keys `auditLog.destination` and `systemLog.destination`.


*Sources*:

 - https://docs.mongodb.com/manual/reference/configuration-options/#auditLog.destination

## `mongodb_enable_encryption`
**Severity:** 4

MongoDB enterprise edition supports encryption for the WiredTiger storage engine, which should be set to true (default is false).

**Remediation:**
Set `security.enableEncryption` to `true`.


*Sources*:

 - https://docs.mongodb.com/manual/reference/configuration-options/#security.enableEncryption

## `mongodb_do_not_use_default_port`
**Severity:** 4

MongoDBs default ports are 27017, 27018 and 27019. When malicious actors are probing IP address pools for services, they look specifically for this port to identify MongoDB. One needs to set these ports to different numbers.

**Remediation:**
Set `net.port` to any other value but the aforementioned numbers.


*Sources*:

 - https://docs.mongodb.com/manual/reference/configuration-options/#net.port

## `mongodb_disable_server_side_scripting`
**Severity:** 4

MongoDB supports the execution of JavaScript. This should only be activated if specifically intended, as it opens the attack-vector to leverage insecure coding.

**Remediation:**
Set `security.javascriptEnabled` to `false`.


*Sources*:

 - https://docs.mongodb.com/manual/reference/configuration-options/#security.javascriptEnabled

## `mongodb_cluster_ip_sources_whitelist_exists`
**Severity:** 4

There should be a limited number of machines being able to access the specific MongoDB instance.

**Remediation:**
One can configure a specific whitelist containing IP addresses and CIDR-ranges, namely by setting `security.clusterIpSourceWhitelist` with appropriate CIDR ranges. It is best practice to set such a whitelist.


*Sources*:

 - https://docs.mongodb.com/manual/reference/configuration-options/#security.clusterIpSourceWhitelist

## `mongodb_cluster_auth_mode_x509`
**Severity:** 4

MongoDB cluster authentication is recommended to be performed via an x.509 certificate.

**Remediation:**
Set the key `security.clusterAuthMode` to `x509`.


*Sources*:

 - https://docs.mongodb.com/manual/reference/configuration-options/#security.clusterAuthMode

## `kafka_set_client_to_use_tls_when_zookeeper`
**Severity:** 4

When connecting to Zookeeper, it is recommended to enforce the use of TLS to ensure encryption in transit.

**Remediation:**
Ensure that the `zookeeper.ssl.client.enable` value is `true` (default is `false`).


*Sources*:

 - https://kafka.apache.org/documentation/#configuration

## `kafka_replication_factors_greater_than_one`
**Severity:** 4

The data replication among different Kafka brokers is crucial to its stability, as otherwise data losses can occur.

**Remediation:**
Ensure that the values for `offsets.topic.replication.factor`, `transaction.state.log.replication.factor`, `default.replication.factor`, `config.storage.replication.factor`, `offset.storage.replication.factor`, `status.storage.replication.factor` and `errors.deadletterqueue.topic.replication.factor` are all greater than one.


*Sources*:

 - https://kafka.apache.org/documentation/#configuration

## `kafka_inter_broker_protocol_not_plain`
**Severity:** 4

Kafka is a distributed system. There is a communication from consumers/producers, but there is also inter-broker communication. It needs to be ensured that this is also encrypted.

**Remediation:**
Ensure that the `security.inter.broker.protocol` value is anything but `PLAINTEXT` (default) or `SASL_PLAINTEXT`.


*Sources*:

 - https://kafka.apache.org/documentation/#configuration

## `apache_x_xss_protection_set`
**Severity:** 4

There is an HTTP response header that stops pages from loading in modern browsers when reflected cross site scripting attacks are detected.

**Remediation:**
Apache can automatically set this header for every response by setting `Header always append X-XSS-Protection "1; mode=block"`.


*Sources*:

 - https://wiki.owasp.org/index.php/OWASP_Secure_Headers_Project#xxxsp

## `apache_x_frame_options_same_origin`
**Severity:** 4

There is an HTTP response header that makes it harder to do clickjacking. It should be set.

**Remediation:**
Apache can automatically set this header for every response by setting `Header always append X-Frame-Options SAMEORIGIN`.


*Sources*:

 - https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options

## `apache_x_content_type_header_set`
**Severity:** 4

There is an HTTP response header that disables the functionality of the browser to detect a content type automatically, which poses an attack vector.

**Remediation:**
Apache can automatically set this header for every response by setting `Header always append X-Content-Type-Options "nosniff" `.


*Sources*:

 - https://wiki.owasp.org/index.php/OWASP_Secure_Headers_Project#xcto

## `apache_turn_trace_off`
**Severity:** 4

It is considered best practice to have tracing disabled for Apache HTTP servers.

**Remediation:**
Set `TraceEnable` to `off` in your configuration.


*Sources*:

 - https://owasp.org/www-community/attacks/Cross_Site_Tracing

## `apache_run_as_separate_user`
**Severity:** 4

Apache should not be run as root. In fact, it is best to configure the user it is run as.

**Remediation:**
Set the `User` and `Group` directives to any user but `root`.


*Sources*:

 - https://httpd.apache.org/docs/2.4/mod/mod_unixd.html

## `apache_hsts_header_set`
**Severity:** 4

There is an HTTP response header that instructs the browser to only communicate with the website using HTTPS, the so called HSTS header. This one should be enabled.

**Remediation:**
Apache can automatically set this header for every response by setting `Header always append  Strict-Transport-Security "max-age:<YOUR-VALUE>; includeSubdomains"`.


*Sources*:

 - https://wiki.owasp.org/index.php/OWASP_Secure_Headers_Project#hsts

## `apache_content_security_policy_set`
**Severity:** 4

One of the most effective techniques to prevent cross site scripting attacks is to control where the content is served from. This can be achieved by setting specific policies in the `Content-Security-Policy` header.

**Remediation:**
The value of that header is completely up to the specific web service. In order to pass this check, the `httpd.conf` needs to contain a line of the form `Header always append Content-Security-Policy <YOUR-CONTENT> `.


*Sources*:

 - https://wiki.owasp.org/index.php/OWASP_Secure_Headers_Project#csp

## `nginx_hsts_header_added`
**Severity:** 4

There is an HTTP response header that instructs the browser to only communicate with the website using HTTPS, the so called HSTS header. This one should be enabled.

**Remediation:**
In the `http` section of the `nginx.conf`, ensure that there is a directive of the form `add_header Strict-Transport-Security "max-age:<YOUR-VALUE>; includeSubdomains"`.


*Sources*:

 - https://wiki.owasp.org/index.php/OWASP_Secure_Headers_Project#hsts

## `nginx_content_security_policy_header_set`
**Severity:** 4

Modern browsers support a header called Content-Security-Policy, where multiple combinations of directives are possible to be set to ensure that the delivered content is not tampered with (e.g. by XSS attacks). This check flags if there is no such header added to an `http` directive of NGINX.

**Remediation:**
Ensure that every `http` block in your NGINX configuration has the `add_header Content-Security-Policy` value with some basic rules enabled.


*Sources*:

 - https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy

## `nginx_x_xss_protection_header`
**Severity:** 4

Although being largely replaced nowadays by the Content-Security-Policy header, it is still advisable to add the header X-XSS-Protection to every response to protect older web browsers from potential cross site scripting attacks.

**Remediation:**
Ensure that every `http` block in your NGINX configuration has `add_header X-XSS-Protection [VALUE]`, where value is not 0.


*Sources*:

 - https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection

## `nginx_ssl_protocols_tls_1_2_higher`
**Severity:** 4

By default, NGINX uses for `ssl_protocols` the value `TLSv1 TLSv1.1 TLSv1.2`.
 Since any protocol before TLSv1.2 is deprecated, it is recommended to change this default and only use TLSv1.2 or higher.

**Remediation:**
Set the `ssl_protocols` on the `http` block to any protocols greater or equal to TLS1.2.


*Sources*:

 - https://nginx.org/en/docs/http/ngx_http_ssl_module.html#ssl_protocols.

## `apache_restrict_access_ht_files`
**Severity:** 4

There are special reserved files called .htaccess, .htgroup and .htpasswd. While it is not recommended to use them, it is also important to ensure that, if they are being used, access to them is restricted.

**Remediation:**
Add the directive <FilesMatch "^\.ht">Require all denied</FilesMatch> on the parent level.


*Sources*:

 - https://httpd.apache.org/docs/2.4/mod/core.html#filesmatch

## `postgres_enable_archive_mode`
**Severity:** 4

In order to perform point in time recovery, the archive mode in Postgres needs to be set to be on.

**Remediation:**
Set the directive `archive_mode` to `on`.


*Sources*:

 - https://wiki.postgresql.org/wiki/Simple_Configuration_Recommendation

## `nginx_x_frame_options_header`
**Severity:** 4

There is an HTTP response header that makes it harder to do clickjacking.

**Remediation:**
NGINX can automatically set this header for every response by setting `add_header X-Frame-Options` to either `SAMEORIGIN` or `DENY` in nginx.conf.


*Sources*:

 - https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options

## `nginx_fast_cgi_pass_regular_expression`
**Severity:** 4

Passing any PHP file to the FastCGI backend can cause PHP to start guessing the right path. This is dangerous if uploads by users are allowed. This should not be done; furthermore, the cgi.fix_pathinfo in php.ini should be set to 0.

**Remediation:**
Whenever a directive like `location ~*` is being used, ensure that the regular expression is not too general.


*Sources*:

 - https://www.nginx.com/resources/wiki/start/topics/tutorials/config_pitfalls/

## `nginx_upstream_servers_https`
**Severity:** 4

NGINX is popular to be used as load balancer. The communication to the upstream servers should exclusively be done via HTTPS, because otherwise there is unencrypted communication going on.

**Remediation:**
Every server in the upstream directive should be starting with `https://`.


*Sources*:

 - https://nginx.org/en/docs/http/ngx_http_upstream_module.html

## `mongodb_no_localhost_auth_bypass`
**Severity:** 3

If no user is defined yet on MongoDB, anyone on localhost has full access to the MongoDB instance. It is best practice to have this behavior disabled.

**Remediation:**
Set `setParameter.enableLocalhostAuthBypass` to `false` (default is true).


*Sources*:

 - https://docs.mongodb.com/manual/reference/parameters/#param.enableLocalhostAuthBypass

## `kafka_do_not_enable_auto_create_topics`
**Severity:** 3

When a broker receives a message for a non-existent topic, the default configuration of Kafka states that the topic will be auto-generated. This has many downsides, as a bug in a producer/consumer code can cause pollution of topics, which can slow down the whole cluster. It is generally recommended to only create topics intentionally.

**Remediation:**
Ensure that the `auto.create.topics.enable` value is `false` (default is `true`).


*Sources*:

 - https://kafka.apache.org/documentation/#configuration

## `cloudformation_ec2_enable_enhanced_monitoring`
**Severity:** 3

When using EC2-instances, if real-time view on data is critical, it is advisable to enable enhanced monitoring. This also enables teams to get alarms more timely.

**Remediation:**
For every resource of type `AWS::EC2::Instance`, ensure that the `Monitoring` key is set to `true` (default is `false`).


*Sources*:

 - https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-instance.html
 - https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-cloudwatch-new.html

## `cloudformation_ec2_disable_termination`
**Severity:** 3

When using EC2-instances, it is advisable to enable termination protection, since it is otherwise possible to accidentally lose data or put the cluster in an undesired state.

**Remediation:**
For every resource of type `AWS::EC2::Instance`, ensure that the `DisableApiTermination` key is set to `true` (default is `false`).


*Sources*:

 - https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-instance.html

## `apache_server_tokens_off`
**Severity:** 3

Even when a user gets to an error page, there should never be more information than necessary displayed on the page. By not knowing the specific Apache HTTPd version, an attacker cannot match known issues to a certain attack.

**Remediation:**
Set `ServerTokens` to `Prod` or `ProductOnly` in your configuration.


*Sources*:

 - https://httpd.apache.org/docs/2.4/mod/core.html#servertokens

## `apache_restrict_ssl_protocol`
**Severity:** 3

SSL 2.0, 3.0, TLS 1, 1.1 have reportedly several crytographic flaws. Hence, only TLS 1.2 should be used.

**Remediation:**
Set `SSLProtocol` to `-ALL +TLSv1.2`.


*Sources*:

 - https://httpd.apache.org/docs/current/mod/mod_ssl.html

## `apache_do_not_allow_override`
**Severity:** 3

The use of .htaccess files introduces the risk of unintentional configuration overrides. In newer versions of Apache, this is disabled by default. It is best to set these specifically to ensure it is really off.

**Remediation:**
In every <Directory> directive, set AllowOverride to be none and ensure that AllowOverrideList is not set.


*Sources*:

 - https://httpd.apache.org/docs/2.4/mod/core.html#directory

## `apache_disable_autoindex`
**Severity:** 3

Apache's autoindex module automatically generates a list view of a folder on the server. This should be disabled, unless specifically desired.

**Remediation:**
Do not load mod_autoindex.


*Sources*:

 - https://httpd.apache.org/docs/2.4/mod/mod_autoindex.html

## `apache_deny_anything_older_than_http_1_1`
**Severity:** 3

Many malicious programs will try to send arbitrary requests to your Apache web server. It is important to only allow HTTP 1.1 requests, since support for older versions is obsolete.

**Remediation:**
Use the Rewrite engine module of Apache to filter out requests. Add the following lines:
RewriteEngine On
RewriteCond %{THE_REQUEST} !HTTP/1\.1$
RewriteRule .* - [F].


*Sources*:

 - http://httpd.apache.org/docs/current/mod/mod_rewrite.html

## `cloudformation_ec2_ensure_backup_plan`
**Severity:** 3

When using EC2-instances, it is recommended to ensure that the attached EBS volume is being backed up regularly.

**Remediation:**
When using a resource of type `AWS::EC2::Instance`, ensure that there is a resource of type `AWS::Backup::BackupPlan`, as well as a resource of type `AWS::Backup::BackupSelection`.


*Sources*:

 - https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-instance.html

## `nginx_limit_simultaneous_connections`
**Severity:** 3

In order to avoid having a single user over-loading the system with parallel connections, NGINX provides a module to limit the parallel connections possible to be opened by a so-called connection zone opened by a user.

**Remediation:**
Set the `limit_conn` key on the top level of the `http`-block to a value that would fit your specific use case.


*Sources*:

 - http://nginx.org/en/docs/http/ngx_http_limit_conn_module.html

## `apache_no_directory_listing`
**Severity:** 3

When a user puts in a URL to a directory, the contents should not be listed. This may reveal files which the hoster does not want the user to know about.

**Remediation:**
In each <Directory> directive, set Options to None or -Indexes.


*Sources*:

 - http://httpd.apache.org/docs/current/mod/core.html#directory

## `postgres_do_not_allow_domain_name_source`
**Severity:** 3

The pg_hba file is defining the different connection and authentication processes for a specific Postgres instance. One of the parameters for determining which authentication method to use is the origin where the request came from. This should always be an IP address or a network mask, but never defined via a domain name, as this makes it vulnerable in the case of DNS spoofing.

**Remediation:**
Ensure that there are no DNS references in the pg_hba.conf file.


*Sources*:

 - https://www.postgresql.org/docs/current/auth-pg-hba-conf.html

## `postgres_pg_hba_lines_mutually_exclusive`
**Severity:** 3

According to the documentation https://www.postgresql.org/docs/9.1/auth-pg-hba-conf.html, there is a first-match-only policy in Postgres for authentication. Hence, it is possible to create authentication lines which are never possible to be reached. If this check fails, you have such authentication lines in your pg_hba.conf file.

**Remediation:**
In your `pg_hba.conf` file, ensure that each lines address space or mask do not intersect.


*Sources*:

 - https://www.postgresql.org/docs/current/auth-pg-hba-conf.html

## `kerberos_default_tgs_enctypes`
**Severity:** 3

One should avoid the legacy TGS enctypes setting in the configuration.

**Remediation:**
`libdefaults` has a key called "default_tgs_enctypes". If this value is set, custom cryptographic mechanisms are set instead of default secure ones. The value should only be set for legacy systems.


*Sources*:

 - https://web.mit.edu/kerberos/krb5-1.12/doc/admin/conf_files/krb5_conf.html

## `postgres_log_timezone_utc`
**Severity:** 2

Working in different timezones is a great area of error. For logging, it is generally recommended to use UTC time, and convert in visual tools to local times as needed. By default, Postgres uses the operating system's timezone setting as its timezone for logging. It is best to set it to UTC to avoid confusion, or to your organization's standard time zone setting.

**Remediation:**
Set the parameter `log_timezone` to `UTC`.


*Sources*:

 - https://www.postgresql.org/docs/10/runtime-config-logging.html

## `postgres_log_statement_not_none`
**Severity:** 2

By default, log statements are not logged at all. It is useful for auditing purposes to at least set it to `ddl`, meaning that DROP, ALTER and CREATE statements are being logged.

**Remediation:**
Set the parameter `log_statement` to anything other but `none` (default value is `none`).


*Sources*:

 - https://www.postgresql.org/docs/10/runtime-config-logging.html

## `postgres_ensure_log_rotation_size_not_disabled`
**Severity:** 2

Log file rotation by by size is part of logging best practices. It is important to have a value set there that follows your companie's policies.

**Remediation:**
Set the parameter `log_rotation_size` to any value other than `0`.


*Sources*:

 - https://www.postgresql.org/docs/10/runtime-config-logging.html

## `postgres_ensure_log_directory_is_set`
**Severity:** 2

Postgres allows you to set your own log directory, which in turn ensures that the user as which Postgresql is run is allowed to write into that directory. It is recommended to set this directory specifically.

**Remediation:**
Set `log_directory` to a value of your choice.


*Sources*:

 - https://www.postgresql.org/docs/10/runtime-config-logging.html

## `postgres_do_not_use_standard_port`
**Severity:** 2

Using the standard port makes it easier for intruders to scan for the service from the outside.

**Remediation:**
Set the parameter `port` to any other value than 5432.


*Sources*:

 - https://www.postgresql.org/docs/current/runtime-config-connection.html

## `kafka_do_not_use_default_port`
**Severity:** 2

Using the standard port makes it easier for intruders to scan for the service from the outside.

**Remediation:**
Either set the deprecated 'port' directive to 9092, or ensure that the listener directive does not have 9092 anywhere defined as port.


*Sources*:

 - https://kafka.apache.org/documentation/#listener_configuration

## `cloudformation_ssh_not_default_port`
**Severity:** 2

When creating an EC2-instance in AWS, it is advisable to set the port to connect via SSH to anything else but the default port 22, as this is a port that is probed by potential attackers first.

**Remediation:**
For every resource of type `AWS::EC2::SecurityGroup`, ensure that there is no `Ingress` block inside `SecurityGroupIngress` where the `ToPort` is 22 and the `IpProtocol` is `TCP`.


*Sources*:

 - https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group.html

## `apache_set_directory_options_none`
**Severity:** 2

It is recommended to keep the Options for <Directory> directives as restrictive as possible, and only set Options not to None if really intended.

**Remediation:**
In every <Directory> directive, set `Options` to be `none`.


*Sources*:

 - https://httpd.apache.org/docs/2.4/mod/core.html#directory

## `hadoop_do_not_use_default_ports`
**Severity:** 2

Using the standard ports makes it easier for intruders to scan for the service from the outside.

**Remediation:**
Set
 - dfs.datanode.https.address to any port other than 9865
 - dfs.namenode.https-address to any port other than 9871
 - dfs.namenode.backup.address to any port other than 50100
 - dfs.namenode.backup.http-address to any port other than 50105
 - dfs.journalnode.rpc-address to any port other than 8485
 - dfs.journalnode.http-address to any port other than 8480
 - dfs.journalnode.https-address to any port other than 8481
 - dfs.namenode.secondary.http-address to any port other than 9868
 - dfs.namenode.secondary.https-address to any port other than 9869
 - dfs.datanode.address to any port other than 9866
 - dfs.datanode.http.address to any port other than 9864
 - dfs.datanode.ipc.address	to any port other than 9867
 - dfs.namenode.http-address to any port other than 9870.


*Sources*:

 - https://hadoop.apache.org/docs/stable/hadoop-project-dist/hadoop-common/ClusterSetup.html

## `postgres_enable_logging_disconnections`
**Severity:** 2

Postgresql offers a mechanism to log ends of sessions, including the duration of sessions. This is recommended to be turned on, as it enables the system administrator to analyze these logs and detect anomalies.

**Remediation:**
Set log_disconnections to `on`.


*Sources*:

 - https://www.postgresql.org/docs/9.1/runtime-config-logging.html

## `postgres_enable_logging_connections`
**Severity:** 2

Postgresql offers a mechanism to log connections to the database. This is recommended to be turned on, as it enables the system administrator to analyze these logs and detect anomalies.

**Remediation:**
Set the directive `log_connections` to `on`.


*Sources*:

 - https://wiki.postgresql.org/wiki/Simple_Configuration_Recommendation

## `nginx_disable_content_sniffing`
**Severity:** 2

There is an HTTP response header that makes it harder to perform content sniffing, which is considered a security vulnerability.

**Remediation:**
NGINX can automatically set this header for every response by setting `add_header X-Content-Type-Options` to `nosniff` in nginx.conf.


*Sources*:

 - https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options

## `nginx_server_tokens_off`
**Severity:** 2

Knowing what NGINX version you are running may make you vulnerable if there is a known vulnerability for a specific version. There is a parameter to turn the display of the version on the error pages off. Our checking mechanism looks into each http-directive and ensures it is disabled on the top level.

**Remediation:**
Set `server_tokens` to `off` on the http-level of the configuration.


*Sources*:

 - https://nginx.org/en/docs/http/ngx_http_core_module.html#server_tokens

## `nginx_proxy_pass_ending_with_slash`
**Severity:** 1

A very common mistake when using proxy_pass is not to place a `/` at the end. Even if you apply a rewrite rule, you may encounter issues, and it is best to place this path separator inside the location.

**Remediation:**
Ensure that every `proxy_pass` directive in your NGINX configuration has `proxy_pass` ending with a slash, unless it uses a variable.


*Sources*:

 - https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_pass

## `nginx_underscores_in_headers_allowed`
**Severity:** 1

The HTTP standard allows underscores in headers, but NGINX might silently dismiss them.

**Remediation:**
The setting `underscores_in_headers on` will turn them on for you.
 Remark: Since the underscores_in_headers_directive is allowed also in server-blocks, but only in very specific ones, we will only pass it if we find it in http-directives.


*Sources*:

 - https://www.nginx.com/resources/wiki/start/topics/tutorials/config_pitfalls/

## `nginx_avoid_if_directives`
**Severity:** 1

NGINX has an article called "If is Evil". Even though it is possible that there are uses where if makes sense, but in general, one should avoid using it.

**Remediation:**
Do not use the `if`-directive anywhere in your configuration file.


*Sources*:

 - https://www.nginx.com/resources/wiki/start/topics/tutorials/config_pitfalls/
 - https://www.nginx.com/resources/wiki/start/topics/depth/ifisevil/

## `nginx_one_root_outside_of_location_block`
**Severity:** 1

One can define a root directory inside of a location block. However, one also needs a root directory for all directives that do not match any given location.

**Remediation:**
Either have a top-level root directive, or ensure that there is one in every `location` directive.


*Sources*:

 - https://www.nginx.com/resources/wiki/start/topics/tutorials/config_pitfalls/

## `kerberos_dns_lookup_kdc`
**Severity:** 1

In order to avoid DoS attacks, it is recommended to not use the local DNS server to lookup KDCs.

**Remediation:**
`libdefaults` has a key called "dns_lookup_kdc". If this value is set to true, the local DNS server is used to look up KDCs and other servers in the realm. Setting this value to true opens up a type of denial of service attack.


*Sources*:

 - https://web.mit.edu/kerberos/krb5-1.12/doc/admin/conf_files/krb5_conf.html
