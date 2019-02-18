package gs.sy.m8.ldapswak;


import jcifs.CIFSContext;
import jcifs.smb.NtlmPasswordAuthenticator;
import jcifs.smb.SSPContext;
import jcifs.smb.SmbException;

final class PassTheHashNtlmCredentials extends NtlmPasswordAuthenticator {
	private static final long serialVersionUID = 1L;
	
	private final byte[] initialToken;

	private final PassTheHashNtlmContext context;
	
	public PassTheHashNtlmCredentials(byte[] d) {
		this.initialToken = d;
		this.context = new PassTheHashNtlmContext(this.initialToken);
	}
	
	private PassTheHashNtlmCredentials(byte[] d, PassTheHashNtlmContext ctx) {
		this.initialToken = d;
		this.context = ctx;
	}
	
	public PassTheHashNtlmContext getContext() {
		return context;
	}
	
	@Override
	public boolean isAnonymous() {
		return false;
	}
	
	@Override
	public boolean isGuest() {
		return false;
	}

	@Override
	public String getUsername() {
		return context.getUsername();
	}
	
	@Override
	public NtlmPasswordAuthenticator clone() {
		return new PassTheHashNtlmCredentials(initialToken, context);
	}

	@Override
	public SSPContext createContext(CIFSContext tc, String targetDomain, String host,
			byte[] initialToken, boolean doSigning) throws SmbException {
		return this.context;
	}
}