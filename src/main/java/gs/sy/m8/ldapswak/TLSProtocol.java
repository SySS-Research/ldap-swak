package gs.sy.m8.ldapswak;

public enum TLSProtocol {
	TLS12("TLSv1.2"),
	TLS11("TLSv1.1"),
	TLS10("TLSv1"),
	SSLv3("SSLv3"),
	SSLv2("SSLv2");
	
	private String protoId;

	private TLSProtocol(String name) {
		protoId = name;
	}
	
	public String getProtoId() {
		return protoId;
	}
}
