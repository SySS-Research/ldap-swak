package gs.sy.m8.ldapswak;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Random;

public class BaseServerTest {
	private static final Random RANDOM = new Random();
	static final InetAddress LOCALHOST;

	static {
		InetAddress lc;
		try {
			lc = InetAddress.getLocalHost();
		} catch (Exception e) {
			try {
				lc = InetAddress.getByAddress(new byte[] { 127, 0, 0, 1 });
			} catch (UnknownHostException e1) {
				lc = null;
			}
		}

		LOCALHOST = lc;
	}

	
	FakeServer createServerBase() {
		FakeServer fs = new FakeServer();
		basicSetup(fs);
		return fs;
	}

	ProxyServer createProxyBase() {
		ProxyServer ps = new ProxyServer();
		basicSetup(ps);
		return ps;
	}

	void basicSetup(BaseCommand c) {
		c.sslContextProv = new SSLContextProvider();
		c.baseDN = new String[] { "cn=test" };
		c.port = RANDOM.nextInt(2 * Short.MAX_VALUE - 1023) + 1024;
		c.bind = LOCALHOST;
		c.fakeCertBitsize = 2048;
		c.fakeCertSigalg = SigAlg.SHA256withRSA;
		c.fakeCertCN = "cn=testCert";
		c.keystorePass = "changeit";
	}
}
