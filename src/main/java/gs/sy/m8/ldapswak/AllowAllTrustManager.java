package gs.sy.m8.ldapswak;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedTrustManager;

import java.net.Socket;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

class AllowAllTrustManager extends X509ExtendedTrustManager {

	public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {

	}

	public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {

	}

	public X509Certificate[] getAcceptedIssuers() {
		return new X509Certificate[0];
	}

	@Override
	public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket)
			throws CertificateException {

	}

	@Override
	public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket)
			throws CertificateException {

	}

	@Override
	public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
			throws CertificateException {

	}

	@Override
	public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
			throws CertificateException {

	}

}