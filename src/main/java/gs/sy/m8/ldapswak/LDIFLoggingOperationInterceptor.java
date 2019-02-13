package gs.sy.m8.ldapswak;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedAddRequest;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedModifyRequest;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSearchEntry;
import com.unboundid.ldap.listener.interceptor.InMemoryOperationInterceptor;
import com.unboundid.ldap.sdk.LDAPException;

final class LDIFLoggingOperationInterceptor extends InMemoryOperationInterceptor {
	
	private static final Logger log = LoggerFactory.getLogger("access");
	
	@Override
	public void processSearchEntry(InMemoryInterceptedSearchEntry entry) {
		super.processSearchEntry(entry);
		log.info("Search result: {}", entry.getSearchEntry().toLDIFString());
	}

	@Override
	public void processAddRequest(InMemoryInterceptedAddRequest request) throws LDAPException {
		log.info("Add: {}",request.getRequest().toLDIFString());
		super.processAddRequest(request);
	}

	@Override
	public void processModifyRequest(InMemoryInterceptedModifyRequest request) throws LDAPException {
		log.info("Modify: {}",request.getRequest().toLDIFString());
		super.processModifyRequest(request);
	}
}