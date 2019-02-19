package gs.sy.m8.ldapswak;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.util.Arrays;

import javax.inject.Inject;
import javax.net.ssl.SSLContext;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryListenerConfig;
import com.unboundid.ldap.listener.LDAPListenerClientConnection;
import com.unboundid.ldap.listener.LDAPListenerExceptionHandler;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldif.LDIFException;

import picocli.CommandLine.Option;
import picocli.CommandLine.Help.Visibility;

public class BaseCommand {

	@Option(names = { "-h", "--help" }, usageHelp = true, description = "Display this help message.")
	boolean usageHelpRequested;

	@Option(names = { "-V", "--version" }, versionHelp = true, description = "print version information and exit")
	boolean versionRequested;

	@Option(names = { "-v", "--verbose" }, description = { "Specify multiple -v options to increase verbosity.",
			"For example, `-v -v -v` or `-vvv`" })
	boolean[] verbosity = new boolean[0];

	@Option(names = { "--request-log" }, description = "Log all requests")
	public boolean requestLog;

	@Option(names = { "-q", "--quiet" }, description = { "Only show warnings and errors" })
	boolean quiet;

	@Option(names = { "--bind" }, description = { "Network address to bind to" })
	InetAddress bind;

	@Option(names = { "-p", "--port" }, defaultValue = "-1", showDefaultValue = Visibility.NEVER, description = {
			"Port to bind to (defaults: 389 for normal, 636 for SSL)" })
	int port;

	@Option(names = { "--ssl" }, defaultValue = "false", description = { "Run a SSL/TLS listener" })
	boolean ssl;

	@Option(names = { "--nostarttls" }, defaultValue = "false", description = { "Disable StartTLS" })
	boolean nostarttls;

	@Option(names = { "--tls-proto" }, description = { "TLS versions to allow (${COMPLETION-CANDIDATES}}" })
	public TLSProtocol[] tlsProtocols;

	@Option(names = { "--tls-cipher" }, description = { "TLS ciphers to allow",
			"see https://docs.oracle.com/javase/9/docs/specs/security/standard-names.html" })
	public String[] tlsCiphers;

	@Option(names = { "--server-base-dn" }, defaultValue = "dc=fake", description = { "Base DNs to report" })
	String[] baseDN;

	@Option(names = { "--keystore" }, description = { "Keystore to load key/certificate from" })
	Path keystore;

	@Option(names = { "--keystore-type" }, defaultValue = "JKS", showDefaultValue = Visibility.ALWAYS, description = {
			"Keystore type" })
	KeyStoreType keystoreType;

	@Option(names = { "--key" }, description = "Private key file to use (PEM, in conjunction with --cert)")
	Path privateKey;

	@Option(names = { "--cert" }, description = "Certificate file to use (PEM, in conjunction with --key)")
	Path certificate;

	@Option(names = {
			"--keystore-pass" }, defaultValue = "changeit", showDefaultValue = Visibility.ALWAYS, description = {})
	String keystorePass;

	@Option(names = { "--fakecert-cn" }, defaultValue = "cn=fake", showDefaultValue = Visibility.ALWAYS, description = {
			"Subject DN to use when creating fake certificates" })
	String fakeCertCN;

	@Option(names = { "--fakecert-bits" }, defaultValue = "2048", showDefaultValue = Visibility.ALWAYS, description = {
			"RSA keySize when generating private key for fake certificates" })
	int fakeCertBitsize;

	@Option(names = {
			"--fakecert-sigalg" }, defaultValue = "SHA256withRSA", showDefaultValue = Visibility.ALWAYS, description = {
					"Signature algorithm to use when generating fake certificates" })
	SigAlg fakeCertSigalg;

	@Option(names = { "--fakecert-lifetime" }, defaultValue = "7", showDefaultValue = Visibility.ALWAYS, description = {
			"Lifetime of fake certificate in days" })
	int fakeCertLifetime;

	@Option(names = { "--fakecert-validfrom" }, description = { "Fake certificate validity start" })
	LocalDateTime fakeCertValidFrom;

	@Option(names = { "--fakecert-validto" }, description = { "Fake certificate validity end" })
	LocalDateTime fakeCertValidTo;

	@Option(names = { "--fakecert-san" }, description = { "Fake certificate subject alternative names" })
	String[] fakeCertSANs = new String[0];

	@Option(names = { "--schemaless" }, defaultValue = "false", description = { "Don't provide any schema" })
	boolean schemaless;

	@Option(names = { "--accept-user" }, defaultValue = "cn=user", description = { "Accept login using this user" })
	String acceptUser;

	@Option(names = { "--accept-pass" }, defaultValue = "pass", description = { "Accept login using this pass" })
	String acceptPass;

	@Option(names = { "--uid-attr" }, defaultValue = "uid", description = { "Attributes to extract username from DNs" })
	String[] uidAttrs;

	@Option(names = { "--write-creds" }, description = {
			"Write intercepted credentials to this file (format: user pass, one per line)" })
	Path writeCreds;

	@Option(names = { "--ntlm-relay" }, description = { "Relay intecepted NTLM exchange to SMB server for PSExec" })
	String relayServer;
	
	
	@Option(names = { "--relay-write-file" }, description = { "Using the relayed credentials, write this local file to the server" })
	Path writeFileSource;
	
	@Option(names = { "--relay-write-to" }, description = { "Using the relayed credentials, write file to this target share/path (SHARE/path/)" })
	String writeFileTarget;
	
	@Option(names = { "--psexec-service-name" }, description = { "Name of service used for PSExec" })
	String psexecServiceName = "psexec";

	@Option(names = { "--psexec-display-name" }, description = { "Display name of service used for PSExec" })
	String psexecDisplayName = "PSExec";

	@Option(names = { "--psexec-cmd" }, description = { "Using the relayed credentials, run system command using PSExec" })
	String psexecCMD;
	
	@Option(names = { "--psexec-cmd-log" }, description = { "Redirect CMD command output to file (filesystem path)" })
	String psexecCMDLog;

	@Option(names = { "--psexec-script-file" }, description = { "Using the relayed credentials, run Powershell code from script file using PSExec (size limits apply)" })
	Path psexecPSHScriptFile;

	@Option(names = { "--psexec-script" }, description = { "Using the relayed credentials, run Powershell code using PSExec (size limits apply)" })
	String psexecPSHScript;
	
	@Option(names = { "--psexec-psh-encode" }, description = { "Encode PSExec Powershell Payload" })
	boolean psexecPSHEncode;
	
	@Option(names = { "--psexec-cmd-script-loc" }, defaultValue = "/ADMIN$/Temp/", showDefaultValue = Visibility.ALWAYS, description = { "SHARE/Path for launcher script file used for output redirection" })
	String psexecCMDScriptLoc;
	
	@Option(names = { "--psexec-cmd-script-path" }, defaultValue = "C:\\Windows\\Temp\\", showDefaultValue = Visibility.ALWAYS, description = { "Local filesystem for launcher script file used for output redirection" })
	String psexecCMDScriptPath;

	@Option(names = { "--relay-read-from" }, description = { "Using the relayed credentials, read file from this target share/path (SHARE/path/)" })
	String readFileSource;
	
	@Option(names = { "--relay-read-to" }, description = {"Local file to store the read file data, leave empty for stdout"})
	Path readFileTarget;
	
	
	@Option(names = { "--relay-read-charset"}, defaultValue ="UTF-8",showDefaultValue = Visibility.ALWAYS, description = {"Charset for reading remote files, only relevant when outputting"})
	String readFileCharset;
	
	
	

	private static final Logger log = LoggerFactory.getLogger(BaseCommand.class);

	@Inject
	SSLContextProvider sslContextProv;

	

	


	public BaseCommand() {
		super();
	}

	protected InMemoryDirectoryServerConfig createConfig() throws LDAPException, Exception, IOException, LDIFException {
		if (log.isDebugEnabled()) {
			log.debug("Server base DNs: {}", Arrays.toString(baseDN));
		}

		InMemoryDirectoryServerConfig ldapcfg = new InMemoryDirectoryServerConfig(baseDN);

		ldapcfg.setListenerConfigs(createListenerConfig());
		ldapcfg.setListenerExceptionHandler(createExceptionListener());

		if (requestLog) {
			ldapcfg.setAccessLogHandler(new AccessLog());
		}

		// disable schema validation, we really don't care
		if (schemaless) {
			ldapcfg.setSchema(null);
		}

		ldapcfg.setEnforceSingleStructuralObjectClass(false);
		ldapcfg.setEnforceAttributeSyntaxCompliance(false);

		if (this.acceptUser != null && this.acceptPass != null) {
			ldapcfg.addAdditionalBindCredentials(this.acceptUser, this.acceptPass);
		}

		return ldapcfg;
	}

	private LDAPListenerExceptionHandler createExceptionListener() {
		return new LDAPListenerExceptionHandler() {

			public void connectionTerminated(LDAPListenerClientConnection connection, LDAPException cause) {
				if (cause != null) {
					if (cause.getCause() instanceof IOException
							&& ("Socket closed".equals(cause.getCause().getMessage())
									|| "Stream closed".equals(cause.getCause().getMessage()))) {
						return;
					}
					SocketAddress remote = connection.getSocket().getRemoteSocketAddress();
					log.warn("Connection closed with error " + remote, cause);
				}
			}

			public void connectionCreationFailure(Socket socket, Throwable cause) {
				SocketAddress remote = socket.getRemoteSocketAddress();
				if (cause != null) {
					log.warn("Connection was not established" + remote, cause);
				}
			}
		};
	}

	private InMemoryListenerConfig createListenerConfig() throws Exception, LDAPException {
		if (ssl) {
			SSLContext ctx = this.sslContextProv.createContext(this);
			this.port = this.port < 0 ? 636 : this.port;
			return InMemoryListenerConfig.createLDAPSConfig("ssl", bind, port,
					this.sslContextProv.configure(this, ctx.getServerSocketFactory()),
					this.sslContextProv.configure(this, ctx.getSocketFactory()));
		} else if (nostarttls) {
			this.port = this.port < 0 ? 389 : this.port;
			return InMemoryListenerConfig.createLDAPConfig("starttls", bind, port, null);
		} else {
			SSLContext ctx = this.sslContextProv.createContext(this);
			this.port = this.port < 0 ? 389 : this.port;
			return InMemoryListenerConfig.createLDAPConfig("starttls", bind, port,
					this.sslContextProv.configure(this, ctx.getSocketFactory()));
		}
	}

}