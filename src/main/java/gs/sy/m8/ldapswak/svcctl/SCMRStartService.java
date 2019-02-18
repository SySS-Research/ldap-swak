package gs.sy.m8.ldapswak.svcctl;

import jcifs.dcerpc.DcerpcMessage;
import jcifs.dcerpc.ndr.NdrBuffer;
import jcifs.dcerpc.ndr.NdrException;
import jcifs.util.Strings;

public class SCMRStartService extends DcerpcMessage {

	private byte[] handle;
	private String[] args;
	public int retval;

	public SCMRStartService(byte[] handle, String[] args) {
		this.handle = handle;
		this.ptype = 0;
		this.flags = DCERPC_FIRST_FRAG | DCERPC_LAST_FRAG;
		this.args = args != null ? args.clone() : null;
	}

	@Override
	public int getOpnum() {
		return 19;
	}

	@Override
	public void encode_in(NdrBuffer buf) throws NdrException {
		buf.writeOctetArray(this.handle, 0, this.handle.length);
		buf.enc_ndr_long(this.args != null ? this.args.length : 0);
		buf.enc_ndr_referent(null, 1);
		if (this.args != null) {
			for (String arg : this.args) {
				byte[] abytes = Strings.getUNIBytes(arg);
				buf.writeOctetArray(abytes, 0, abytes.length);
				buf.advance(1);
			}
		}
	}

	@Override
	public void decode_out(NdrBuffer buf) throws NdrException {
		this.retval = buf.dec_ndr_long();
	}

}
