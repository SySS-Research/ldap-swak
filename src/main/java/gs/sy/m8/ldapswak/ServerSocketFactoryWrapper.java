package gs.sy.m8.ldapswak;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.util.LinkedList;
import java.util.List;

import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;

public class ServerSocketFactoryWrapper extends SSLServerSocketFactory {
	
	
	private final SSLServerSocketFactory delegate;
	private final String[] cipherSuites;
	private final String[] protocols;

	public ServerSocketFactoryWrapper(SSLServerSocketFactory delegate, String[] cipherSuites, String[] protocols) {
		this.delegate = delegate;
		this.protocols = protocols != null ? protocols.clone() : new String[] { "TLSv1.2", "TLSv1.1", "TLSv1", "SSLv3" };
		
		
		if ( cipherSuites != null ) {
			this.cipherSuites = cipherSuites.clone();
		} else {
			List<String> use = new LinkedList<>();
			for ( String sup : delegate.getSupportedCipherSuites()) {
				if ( sup.contains("_anon_") || sup.contains("_NULL_") || sup.contains("_DES_")) {
					continue;
				}
				use.add(sup);
			}
			use.add("TLS_EMPTY_RENEGOTIATION_INFO_SCSV");
			this.cipherSuites = use.toArray(new String[use.size()]);
		}
	}
	
	@Override
	public String[] getDefaultCipherSuites() {
		return delegate.getDefaultCipherSuites();
	}

	@Override
	public String[] getSupportedCipherSuites() {
		return delegate.getSupportedCipherSuites();
	}

	@Override
	public ServerSocket createServerSocket(int port) throws IOException {
		return configure(delegate.createServerSocket(port));
	}

	@Override
	public ServerSocket createServerSocket(int port, int backlog) throws IOException {
		return configure(delegate.createServerSocket(port, backlog));
	}

	@Override
	public ServerSocket createServerSocket(int port, int backlog, InetAddress ifAddress) throws IOException {
		return configure(delegate.createServerSocket(port, backlog, ifAddress));
	}

	private ServerSocket configure(ServerSocket s) {
		SSLServerSocket ss = (SSLServerSocket) s;
		SSLParameters params = new SSLParameters(cipherSuites, protocols);
		params.setUseCipherSuitesOrder(true);
		ss.setSSLParameters(params);
		return ss;
	}

}
