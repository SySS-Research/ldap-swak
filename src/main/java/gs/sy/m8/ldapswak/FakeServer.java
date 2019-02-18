package gs.sy.m8.ldapswak;

import java.io.Closeable;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.sdk.schema.Schema;
import com.unboundid.ldif.LDIFReader;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

@Command(name = "fake", description = "Launch fake LDAP server")
public class FakeServer extends BaseCommand implements CommandRunnable, Closeable {
	
	private static final Logger log = LoggerFactory.getLogger(FakeServer.class);

	@Option(names = { "--schema" }, description = { "LDIF schema to apply" })
	Path schema;

	@Option(names = { "--load" }, description = { "LDIF file to load" })
	Path[] load = new Path[0];

	private InMemoryDirectoryServer service;

	CredentialsOperationInterceptor creds;

	@Override
	public void run() throws Exception {

		InMemoryDirectoryServerConfig ldapcfg = createConfig();
		if (this.schema != null) {
			try (InputStream is = Files.newInputStream(this.schema, StandardOpenOption.READ)) {
				ldapcfg.setSchema(Schema.getSchema(is));
			}
		}

		creds = new CredentialsOperationInterceptor(this);
		ldapcfg.addInMemoryOperationInterceptor(creds);
		
		if ( this.relayServer != null ) {
			ldapcfg.addSASLBindHandler(new PassTheHashNTLMSASLBindHandler(this));
		}

		InMemoryDirectoryServer ds = new InMemoryDirectoryServer(ldapcfg);

		for (Path load : this.load) {
			try (InputStream is = Files.newInputStream(load, StandardOpenOption.READ)) {
				ds.importFromLDIF(false, new LDIFReader(is));
			}
		}

		
		log.info("Starting {} listener on {}:{}", ssl ? "SSL" : (nostarttls ? "plain" : "StartTLS"),
				bind != null ? bind.getHostAddress() : "*", port);

		this.service = ds;
		ds.startListening();
	}

	@Override
	public void close()  {
		if ( this.service != null ) {
			this.service.shutDown(true);
		}
	}
}
