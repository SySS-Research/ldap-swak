package gs.sy.m8.ldapswak.svcctl;

import jcifs.dcerpc.DcerpcMessage;
import jcifs.dcerpc.ndr.NdrBuffer;
import jcifs.dcerpc.ndr.NdrException;
import jcifs.util.Strings;

public class SCMRCreateServiceW extends DcerpcMessage {

	private byte[] handle;

	public String serviceName;
	public String displayName;
	public int desiredAccess;
	public int serviceType;
	public int startType;
	public int errorControl;

	public String binaryPathName;
	public String loadOrderGroup;

	public int tagId;

	public String[] dependencies;
	public String serviceStartName; // user to run the service as
	public String password;

	public int retval;
	public byte[] serviceHandle = new byte[20];

	public SCMRCreateServiceW(byte[] handle) {
		this.handle = handle;
		this.ptype = 0;
		this.flags = DCERPC_FIRST_FRAG | DCERPC_LAST_FRAG;
	}

	@Override
	public int getOpnum() {
		return 12;
	}

	@Override
	public void encode_in(NdrBuffer buf) throws NdrException {

		buf.writeOctetArray(this.handle, 0, this.handle.length);

		buf.enc_ndr_string(this.serviceName != null ? this.serviceName : "");

		buf.enc_ndr_referent(this.displayName, 1);
		if (this.displayName != null) {
			buf.enc_ndr_string(this.displayName);
		}

		buf.enc_ndr_long(this.desiredAccess);
		buf.enc_ndr_long(this.serviceType);
		buf.enc_ndr_long(this.startType);
		buf.enc_ndr_long(this.errorControl);

		buf.enc_ndr_string(this.binaryPathName != null ? this.binaryPathName : "");

		buf.enc_ndr_referent(this.loadOrderGroup, 1);
		if (this.loadOrderGroup != null) {
			buf.enc_ndr_string(this.loadOrderGroup);
		}

		buf.enc_ndr_long(this.tagId);

		buf.enc_ndr_referent(this.dependencies, 1);
		int depLen = 0;
		if (this.dependencies != null) {
			for (String dep : this.dependencies) {
				byte[] dbytes = Strings.getUNIBytes(dep);
				buf.writeOctetArray(dbytes, 0, dbytes.length);
				buf.advance(1);
				depLen += dbytes.length + 1;
			}
			depLen += 1;
		}
		buf.enc_ndr_long(depLen);

		buf.enc_ndr_referent(this.serviceStartName, 1);
		if (this.serviceStartName != null) {
			buf.enc_ndr_string(this.serviceStartName);
		}

		buf.enc_ndr_referent(this.password, 1);
		int pwLen = 0;
		if (this.password != null) {
			byte[] pwbytes = Strings.getUNIBytes(this.password);
			buf.writeOctetArray(pwbytes, 0, pwbytes.length);
			buf.advance(1);
			pwLen += pwbytes.length + 1;
		}
		buf.enc_ndr_long(pwLen);

	}

	@Override
	public void decode_out(NdrBuffer buf) throws NdrException {
		this.tagId = buf.dec_ndr_long();
		buf.readOctetArray(this.serviceHandle, 0, 20); 
		this.retval = buf.dec_ndr_long();
	}

}
