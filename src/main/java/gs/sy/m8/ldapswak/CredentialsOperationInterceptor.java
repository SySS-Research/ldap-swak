package gs.sy.m8.ldapswak;

import java.util.Base64;
import java.util.LinkedList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSASLBindRequest;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSimpleBindRequest;
import com.unboundid.ldap.listener.interceptor.InMemoryOperationInterceptor;
import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.GenericSASLBindRequest;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.RDN;

class CredentialsOperationInterceptor extends InMemoryOperationInterceptor {

	
	private static Logger log = LoggerFactory.getLogger(CredentialsOperationInterceptor.class);
	
	
	private final BaseCommand config;
	
	final List<String[]> collected = new LinkedList<>();
	
	public CredentialsOperationInterceptor(BaseCommand config) {
		this.config = config;
	}

	
	@Override
	public void processSASLBindRequest(InMemoryInterceptedSASLBindRequest request) throws LDAPException {
		GenericSASLBindRequest r = request.getRequest();
		if ("PLAIN".equalsIgnoreCase(r.getSASLMechanismName())) {
			String creds = r.getCredentials().stringValue();
			String authId, authzId, pw;

			int sep = creds.indexOf('\0');
			if (sep < 0) {
				log.warn("Unexpected SASL plain credential format");
				super.processSASLBindRequest(request);
				return;
			}

			int sep2 = creds.indexOf('\0', sep + 1);
			if (sep2 < 0) {
				authId = creds.substring(0, sep);
				pw = creds.substring(sep + 1);
			} else {
				authzId = creds.substring(0, sep);
				log.debug("SASL authzId {}", authzId);
				authId = creds.substring(sep + 1, sep2);
				pw = creds.substring(sep2 + 1);
			}

			log.debug("SASL PLAIN {}:{}", authId, pw);
			handleCreds(authId, pw);
		} else {
			log.debug("SASL " + r.getBindType() + " bind " + r.getBindDN() + " "
					+ Base64.getEncoder().encodeToString(r.getCredentials().getValue()));
		}

		super.processSASLBindRequest(request);
	}

	@Override
	public void processSimpleBindRequest(InMemoryInterceptedSimpleBindRequest request) throws LDAPException {
		String bindDn = request.getRequest().getBindDN();
		String pw = request.getRequest().getPassword().stringValue();
		if (bindDn.isEmpty() && pw.isEmpty()) {
			log.debug("Anonymous bind");
		} else {
			log.debug("Simple bind {} pw '{}'", bindDn, pw);
			handleCreds(extractUid(this.config, bindDn), pw);
			super.processSimpleBindRequest(request);
		}
	}

	private String extractUid(BaseCommand config, String bindDN) {
		try {
			DN dn = new DN(bindDN);
			for (RDN rdn : dn.getRDNs()) {
				for (String uidAttr : config.uidAttrs) {
					if (rdn.hasAttribute(uidAttr)) {
						return fetchAttribute(uidAttr, rdn);
					}
				}
			}
		} catch (Exception e) {
			log.debug("Failed to process Bind DN " + bindDN, e);
		}

		return bindDN;
	}

	private String fetchAttribute(String string, RDN rdn) {
		for (Attribute attr : rdn.getAttributes()) {
			if (string.equals(attr.getBaseName())) {
				return attr.getValue();
			}
		}
		return null;
	}

	private void handleCreds(String user, String pw) {
		log.info("Intercepted credentials {}:{}", user, pw);
		
		this.collected.add( new String[] { user, pw });
	}

}
