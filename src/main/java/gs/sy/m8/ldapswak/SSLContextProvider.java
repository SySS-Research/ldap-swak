package gs.sy.m8.ldapswak;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.NoSuchElementException;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;



public class SSLContextProvider {

	static {
		System.setProperty("jdk.tls.ephemeralDHKeySize", "2048");
	}

	private static final Logger log = LoggerFactory.getLogger(SSLContextProvider.class);


	public SSLContext createContext(BaseCommand config) throws Exception {
		SecureRandom sr = new SecureRandom();
		KeyManagerFactory kmf = KeyManagerFactory.getInstance("PKIX");

		kmf.init(getKeystore(config), config.keystorePass.toCharArray());

		SSLContext ctx = SSLContext.getInstance("TLSv1.2");
		ctx.init(kmf.getKeyManagers(), new TrustManager[] { new AllowAllTrustManager() }, sr);

		return ctx;
	}

	private KeyStore getKeystore(BaseCommand config) throws Exception {
		if (config.keystore != null) {
			try (InputStream is = Files.newInputStream(config.keystore, StandardOpenOption.READ)) {
				KeyStore ks = KeyStore.getInstance(config.keystoreType.name());
				ks.load(is, config.keystorePass.toCharArray());
				return ks;
			}
		} else if (config.privateKey != null) {
			Path certFile = config.certificate;
			if (certFile == null) {
				certFile = config.privateKey;
			}

			Certificate[] chain = new Certificate[0];
			try (InputStream is = Files.newInputStream(certFile, StandardOpenOption.READ)) {
				chain = CertificateFactory.getInstance("X.509").generateCertificates(is).toArray(chain);
			}

			KeyStore ks = KeyStore.getInstance("JKS");
			ks.setKeyEntry("private", loadPrivateKey(config.privateKey), null, chain);
			return ks;
		}
		return createFakeKeystore(config);
	}

	public static PrivateKey loadPrivateKey(Path path) throws Exception {

		try (BufferedReader br = Files.newBufferedReader(path, StandardCharsets.US_ASCII);
				PEMParser pr = new PEMParser(br)) {
			Object o = pr.readObject();

			if (o instanceof PrivateKey) {
				return (PrivateKey) o;
			}
		}

		throw new NoSuchElementException("No privat key found");
	}

	private KeyStore createFakeKeystore(BaseCommand config) throws Exception {

		log.debug("Generating self-signed certificate for {}", config.fakeCertCN);

		KeyPairGenerator inst = KeyPairGenerator.getInstance("RSA");
		SecureRandom random = new SecureRandom();
		inst.initialize(config.fakeCertBitsize, random);
		KeyPair key = inst.generateKeyPair();

		ContentSigner contentSigner = new JcaContentSignerBuilder(config.fakeCertSigalg.name())
				.build(key.getPrivate());

		BigInteger serial = BigInteger.valueOf(random.nextLong());
		Date startDate = Date
				.from((config.fakeCertValidFrom != null ? config.fakeCertValidFrom : LocalDateTime.now())
						.atOffset(ZoneOffset.UTC).toInstant());
		Date endDate = Date.from((config.fakeCertValidTo != null ? config.fakeCertValidTo
				: LocalDateTime.now().plusDays(config.fakeCertLifetime)).atOffset(ZoneOffset.UTC).toInstant());
		X500Name dn = new X500Name(config.fakeCertCN);
		JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(dn, serial, startDate, endDate, dn,
				key.getPublic());

		certBuilder.addExtension(Extension.extendedKeyUsage, false,
				new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth));
		certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
		addSANs(config, certBuilder);
		X509CertificateHolder cert = certBuilder.build(contentSigner);

		KeyStore ks = KeyStore.getInstance("JKS");
		ks.load(null, config.keystorePass.toCharArray());

		Certificate certificate = CertificateFactory.getInstance("X.509")
				.generateCertificate(new ByteArrayInputStream(cert.getEncoded()));

		if (log.isDebugEnabled()) {
			log.debug("Generated certificate " + certificate);
		}

		ks.setCertificateEntry("cert", certificate);
		ks.setKeyEntry("private", key.getPrivate(), config.keystorePass.toCharArray(),
				new Certificate[] { certificate });
		return ks;
	}

	private void addSANs(BaseCommand config, JcaX509v3CertificateBuilder certBuilder) throws CertIOException {
		GeneralName[] names = new GeneralName[config.fakeCertSANs.length];

		for (int i = 0; i < names.length; i++) {
			String name = config.fakeCertSANs[i];
			int sep = name.indexOf(':');
			int tag = GeneralName.dNSName;
			if (sep >= 0) {
				String type = name.substring(0, sep);

				switch (type) {
				case "dns":
					break;
				case "ip":
					tag = GeneralName.iPAddress;
					break;
				default:
					throw new IllegalArgumentException("unsupported name type " + type);
				}

				name = name.substring(sep + 1, name.length());
			}

			names[i] = new GeneralName(tag, name);
		}

		if (names != null && names.length > 0) {
			certBuilder.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(names));
		}
	}

	public SSLServerSocketFactory configure(BaseCommand config, SSLServerSocketFactory serverSocketFactory) {
		return new ServerSocketFactoryWrapper(serverSocketFactory, mapProtocols(config.tlsProtocols),
				config.tlsCiphers);
	}

	private static String[] mapProtocols(TLSProtocol[] tlsProtocols) {
		if (tlsProtocols == null) {
			return null;
		}
		String[] proto = new String[tlsProtocols.length];
		for (int i = 0; i < tlsProtocols.length; i++) {
			proto[i] = tlsProtocols[i].getProtoId();
		}
		return proto;
	}

	public SSLSocketFactory configure(BaseCommand config, SSLSocketFactory socketFactory) {
		return socketFactory;
	}
}
