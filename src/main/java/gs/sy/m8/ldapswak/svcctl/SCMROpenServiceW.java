package gs.sy.m8.ldapswak.svcctl;

import jcifs.dcerpc.DcerpcMessage;
import jcifs.dcerpc.ndr.NdrBuffer;
import jcifs.dcerpc.ndr.NdrException;

public class SCMROpenServiceW extends DcerpcMessage {

	private byte[] handle;
	private String serviceName;
	private int desiredAccess;
	
	public int retval;
	public byte[] serviceHandle = new byte[20];

	public SCMROpenServiceW(byte[] handle, String serviceName, int desiredAccess ) {
		this.handle = handle;
		this.serviceName = serviceName;
		this.desiredAccess = desiredAccess;
		this.ptype = 0;
		this.flags = DCERPC_FIRST_FRAG | DCERPC_LAST_FRAG;
	}

	@Override
	public int getOpnum() {
		return 16;
	}

	@Override
	public void encode_in(NdrBuffer buf) throws NdrException {
		buf.writeOctetArray(this.handle, 0, this.handle.length);
		buf.enc_ndr_string(this.serviceName != null ? this.serviceName : "");
		buf.enc_ndr_long(this.desiredAccess);	
	}

	@Override
	public void decode_out(NdrBuffer buf) throws NdrException {
		buf.readOctetArray(this.serviceHandle, 0, 20); 
		this.retval = buf.dec_ndr_long();
	}

}
