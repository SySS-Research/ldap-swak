package gs.sy.m8.ldapswak;

import static org.junit.jupiter.api.Assertions.*;
import static org.hamcrest.CoreMatchers.*;
import static org.hamcrest.MatcherAssert.assertThat;

import java.math.BigInteger;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.List;


import org.hamcrest.collection.IsCollectionWithSize;
import org.hamcrest.core.IsIterableContaining;
import org.junit.jupiter.api.Test;

class SSLContextProviderTest {

	@Test
	void testKeystoreGenernate() throws Exception {
		BaseCommand c = basicConfig();
		X509Certificate x509 = getCertificate(c);
		assertThat(x509.getPublicKey(), instanceOf(RSAPublicKey.class));
		RSAPublicKey rsa = (RSAPublicKey) x509.getPublicKey();

		assertThat(rsa.getModulus().bitLength(), is(equalTo(2048)));
		assertEquals("CN=testCert", x509.getSubjectX500Principal().getName());
		assertEquals(c.fakeCertSigalg.name(), x509.getSigAlgName());

		x509.checkValidity();
	}

	private X509Certificate getCertificate(BaseCommand c) throws Exception, KeyStoreException {
		KeyStore ks = new SSLContextProvider().getKeystore(c);
		String first = ks.aliases().nextElement();
		Certificate cert = ks.getCertificate(first);
		assertThat(cert, instanceOf(X509Certificate.class));
		return (X509Certificate) cert;
	}

	@Test
	void testKeystoreGenernateSAN() throws Exception {
		BaseCommand c = basicConfig();
		c.fakeCertSANs = new String[] { "dns1", "dns:dns2", "ip:127.0.0.1" };
		X509Certificate x509 = getCertificate(c);

		byte[] ext = x509.getExtensionValue("2.5.29.17");
		assertNotNull(ext);

		Collection<List<?>> sans = x509.getSubjectAlternativeNames();
		assertThat(sans, IsCollectionWithSize.hasSize(c.fakeCertSANs.length));
		assertThat(sans, IsIterableContaining.hasItem(equalTo(Arrays.asList(2, "dns1"))));
		assertThat(sans, IsIterableContaining.hasItem(equalTo(Arrays.asList(2, "dns2"))));
		assertThat(sans, IsIterableContaining.hasItem(equalTo(Arrays.asList(7, "127.0.0.1"))));
	}
	
	
	@Test
	void testKeystoreGenerateSigalg() throws Exception {
		BaseCommand c = basicConfig();
		c.fakeCertSigalg = SigAlg.MD5withRSA;
		X509Certificate x509 = getCertificate(c);
		assertEquals(c.fakeCertSigalg.name(), x509.getSigAlgName());
	}
	
	
	@Test
	void testKeystoreGenerateValidity() throws Exception {
		BaseCommand c = basicConfig();
		
		c.fakeCertValidFrom = LocalDateTime.of(2018, 11, 1, 12, 0);
		c.fakeCertValidTo = LocalDateTime.of(2018, 11, 15, 12, 0);
		
		X509Certificate x509 = getCertificate(c);
		
		Date notBefore = x509.getNotBefore();
		Date notAfter = x509.getNotAfter();
		
		assertEquals(Date.from(c.fakeCertValidFrom.toInstant(ZoneOffset.UTC)), notBefore);
		assertEquals(Date.from(c.fakeCertValidTo.toInstant(ZoneOffset.UTC)), notAfter);
	}
	
	@Test
	void testLoadJKS() throws Exception {
		BaseCommand c = basicConfig();
		c.keystorePass = "changeit";
		c.keystoreType = KeyStoreType.JKS;		
		
		String r = getClass().getResource("/test.jks").getFile();
		assertNotNull(r);
		c.keystore = Paths.get(r);
		X509Certificate cert = getCertificate(c);
		assertEquals(new BigInteger("135e84e0", 16), cert.getSerialNumber());
		assertEquals("CN=Tester,OU=Test,O=Test,L=Test,ST=Test,C=DE",
				cert.getSubjectX500Principal().getName());
	}
	
	@Test
	void testLoadP12() throws Exception {
		BaseCommand c = basicConfig();
		c.keystorePass = "testing";
		c.keystoreType = KeyStoreType.PKCS12;		
		
		String r = getClass().getResource("/test.p12").getFile();
		assertNotNull(r);
		c.keystore = Paths.get(r);
		X509Certificate cert = getCertificate(c);
		assertEquals(new BigInteger("3e8e4f87", 16), cert.getSerialNumber());
		assertEquals("CN=P12Test,OU=Unknown,O=Unknown,L=Unknown,ST=Unknown,C=Unknown",
				cert.getSubjectX500Principal().getName());
	}
	
	@Test
	void testLoadPEM() throws Exception {
		String pk = getClass().getResource("/test.key").getFile();
		assertNotNull(pk);
		
		String cr = getClass().getResource("/test.crt").getFile();
		assertNotNull(cr);
		
		BaseCommand c = basicConfig();
		c.privateKey = Paths.get(pk);
		c.certificate = Paths.get(cr);
		
		
		X509Certificate cert = getCertificate(c);
		assertEquals(new BigInteger("e527e64e1b665694", 16), cert.getSerialNumber());
		assertEquals("CN=test",
				cert.getSubjectX500Principal().getName());
	}

	
	@Test
	void testLoadPEMCombined() throws Exception {
		String pk = getClass().getResource("/test-combined.pem").getFile();
		assertNotNull(pk);
		
		BaseCommand c = basicConfig();
		c.privateKey = Paths.get(pk);
		
		X509Certificate cert = getCertificate(c);
		assertEquals(new BigInteger("e527e64e1b665694", 16), cert.getSerialNumber());
		assertEquals("CN=test",
				cert.getSubjectX500Principal().getName());
	}


	private BaseCommand basicConfig() {
		BaseCommand c = new MainCommand();
		c.fakeCertBitsize = 2048;
		c.fakeCertSigalg = SigAlg.SHA256withRSA;
		c.fakeCertCN = "cn=testCert";
		c.fakeCertLifetime = 5;
		c.keystorePass = "changeit";

		return c;
	}

}
