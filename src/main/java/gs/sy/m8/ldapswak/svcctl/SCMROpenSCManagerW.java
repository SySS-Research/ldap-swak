package gs.sy.m8.ldapswak.svcctl;

import jcifs.dcerpc.DcerpcMessage;
import jcifs.dcerpc.ndr.NdrBuffer;
import jcifs.dcerpc.ndr.NdrException;

public class SCMROpenSCManagerW extends DcerpcMessage {

	private String server;
	private String dbName;
	private int desiredAccess;
	
	
	public int retval;
	public byte[] handle = new byte[20];
	


	public SCMROpenSCManagerW(String server, String dbName, int desiredAccess) {
		this.server = server;
		this.dbName = dbName;
		this.desiredAccess = desiredAccess;
	    this.ptype = 0;
        this.flags = DCERPC_FIRST_FRAG | DCERPC_LAST_FRAG;
	}

	@Override
	public int getOpnum() {
		return 15;
	}

	@Override
	public void encode_in(NdrBuffer buf) throws NdrException {
		 buf.enc_ndr_referent(this.server, 1); 
		 if ( this.server!= null ) {
             buf.enc_ndr_string(this.server);

         }
         buf.enc_ndr_referent(this.dbName, 1);
         if ( this.dbName!= null ) {
             buf.enc_ndr_string(this.dbName);

         }
         buf.enc_ndr_long(this.desiredAccess);
	}

	@Override
	public void decode_out(NdrBuffer buf) throws NdrException {
		buf.readOctetArray(this.handle, 0, 20); 
		this.retval = buf.dec_ndr_long();
	}

}
