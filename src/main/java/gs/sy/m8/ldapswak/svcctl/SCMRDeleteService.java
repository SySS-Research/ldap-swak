package gs.sy.m8.ldapswak.svcctl;

import jcifs.dcerpc.DcerpcMessage;
import jcifs.dcerpc.ndr.NdrBuffer;
import jcifs.dcerpc.ndr.NdrException;

public class SCMRDeleteService extends DcerpcMessage {

	private byte[] handle;
	public int retval;

	public SCMRDeleteService(byte[] handle) {
		this.handle = handle;
		this.ptype = 0;
		this.flags = DCERPC_FIRST_FRAG | DCERPC_LAST_FRAG;
	}

	@Override
	public int getOpnum() {
		return 2;
	}

	@Override
	public void encode_in(NdrBuffer buf) throws NdrException {
		buf.writeOctetArray(this.handle, 0, this.handle.length);
	}

	@Override
	public void decode_out(NdrBuffer buf) throws NdrException {
		this.retval = buf.dec_ndr_long();
	}

}
