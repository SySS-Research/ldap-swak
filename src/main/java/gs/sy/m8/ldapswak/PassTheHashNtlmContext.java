package gs.sy.m8.ldapswak;

import java.io.IOException;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jcifs.CIFSException;
import jcifs.ntlmssp.Type2Message;
import jcifs.ntlmssp.Type3Message;
import jcifs.smb.NtlmContext;
import jcifs.smb.SSPContext;
import jcifs.spnego.NegTokenInit;
import jcifs.spnego.NegTokenTarg;
import jcifs.spnego.SpnegoException;
import jcifs.spnego.SpnegoToken;

public class PassTheHashNtlmContext implements SSPContext {

	private static final Logger log = LoggerFactory.getLogger(PassTheHashNtlmContext.class);

	private boolean finished;
	private final byte[] initialToken;

	private volatile Type2Message type2Message;
	private volatile Type3Message type3Message;

	private volatile boolean failed;

	public PassTheHashNtlmContext(byte[] initialToken) {
		this.initialToken = initialToken;
	}

	@Override
	public boolean isEstablished() {
		return this.finished;
	}

	public Type2Message waitForType2(long timeout) throws InterruptedException {
		long to = System.currentTimeMillis() + timeout;
		
		while (this.type2Message == null && System.currentTimeMillis() < to && !this.failed) {
			synchronized (this) {
				wait(timeout);
			}
		}
		return this.type2Message;
	}
	
	
	public void fail() {
		this.failed = true;
		synchronized (this) {
			notifyAll();
		}
	}

	public void setType3(Type3Message t) {
		this.type3Message = t;
		synchronized (this) {
			notifyAll();
		}
	}

	@Override
	public byte[] initSecContext(byte[] token, int off, int len) throws CIFSException {
		try {
			Object o = getToken(token);

			if (o instanceof NegTokenInit) {
				NegTokenInit tok = (NegTokenInit) o;

				int foundAt = -1;
				int i = 0;

				for (ASN1ObjectIdentifier oid : tok.getMechanisms()) {
					if (NtlmContext.NTLMSSP_OID.equals(oid)) {
						foundAt = i;
						break;
					}
					i++;
				}

				if (foundAt < 0) {
					// server does not support NTLM
					log.warn("Server does not support NTLM");
					this.finished = true;
					return new byte[0];
				} else if (foundAt == 0 && tok.getMechanismToken() != null) {
					// NTLM is the initial mech, send token now
					return handleType2(new Type2Message(tok.getMechanismToken()));
				}

				return new NegTokenInit(new ASN1ObjectIdentifier[] { NtlmContext.NTLMSSP_OID }, 0, initialToken, null)
						.toByteArray();
			} else if (o instanceof NegTokenTarg) {
				NegTokenTarg tok = (NegTokenTarg) o;
				if (!NtlmContext.NTLMSSP_OID.equals(tok.getMechanism())) {
					log.warn("Server chose something else");
					this.finished = true;
					return new byte[0];
				}
				return handleType2(new Type2Message(tok.getMechanismToken()));
			} else {
				log.warn("Unexpected message");
			}
		} catch (Exception e) {
			log.warn("Failed to parse server challenge as SPNEGO", e);
		}
		this.finished = true;
		return new byte[0];
	}

	private byte[] handleType2(Type2Message t2) throws InterruptedException, IOException {
		this.type2Message = t2;
		synchronized (this) {
			notifyAll();
		}

		while (this.type3Message == null) {
			synchronized (this) {
				this.wait();
			}
		}

		this.finished = true;
		return new NegTokenTarg(NegTokenTarg.UNSPECIFIED_RESULT, null, this.type3Message.toByteArray(),
				null).toByteArray();
	}

	private static SpnegoToken getToken(byte[] token) throws SpnegoException {
		SpnegoToken spnegoToken = null;
		try {
			switch (token[0]) {
			case (byte) 0x60:
				spnegoToken = new NegTokenInit(token);
				break;
			case (byte) 0xa1:
				spnegoToken = new NegTokenTarg(token);
				break;
			default:
				throw new SpnegoException("Invalid token type");
			}
			return spnegoToken;
		} catch (IOException e) {
			throw new SpnegoException("Invalid token");
		}
	}

	@Override
	public String getNetbiosName() {
		return null;
	}

	@Override
	public void dispose() throws CIFSException {
	}

	@Override
	public boolean isSupported(ASN1ObjectIdentifier mechanism) {
		return true;
	}

	@Override
	public boolean isPreferredMech(ASN1ObjectIdentifier selectedMech) {
		return true;
	}

	@Override
	public int getFlags() {
		return 0;
	}

	@Override
	public byte[] getSigningKey() throws CIFSException {
		return null;
	}

	@Override
	public ASN1ObjectIdentifier[] getSupportedMechs() {
		return new ASN1ObjectIdentifier[0];
	}

	@Override
	public boolean supportsIntegrity() {
		return false;
	}

	@Override
	public byte[] calculateMIC(byte[] data) throws CIFSException {
		return null;
	}

	@Override
	public void verifyMIC(byte[] data, byte[] mic) throws CIFSException {
	}

	@Override
	public boolean isMICAvailable() {
		return false;
	}

	public String getUsername() {
		if ( this.type3Message != null ) {
			return this.type3Message.getUser();
		}
		return null;
	}

}
