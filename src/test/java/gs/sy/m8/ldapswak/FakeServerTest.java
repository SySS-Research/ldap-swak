package gs.sy.m8.ldapswak;

import static org.junit.jupiter.api.Assertions.*;
import static org.hamcrest.CoreMatchers.*;
import static org.hamcrest.MatcherAssert.assertThat;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.List;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;

import org.hamcrest.collection.IsCollectionWithSize;
import org.hamcrest.core.IsIterableContaining;
import org.junit.jupiter.api.Test;

import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPConnectionOptions;
import com.unboundid.ldap.sdk.LDAPConnectionPool;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.ldap.sdk.StartTLSPostConnectProcessor;

class FakeServerTest extends BaseServerTest {

	@Test
	void testConnection() throws Exception {
		ServerThread<FakeServer> st = new ServerThread<>(createServerBase());
		try {
			st.waitStart();
			try (LDAPConnection lc = new LDAPConnection(LOCALHOST.getHostAddress(), st.command.port)) {
				lc.getRootDSE();

			}
		} finally {
			st.shutdown();
		}
	}

	@Test
	void testConnectionSSL() throws Exception {
		FakeServer c = createServerBase();
		c.ssl = true;

		SSLContext ctx = SSLContext.getInstance("TLSv1.2");
		ctx.init(new KeyManager[] {}, new TrustManager[] { new AllowAllTrustManager() }, new SecureRandom());

		SSLSocketFactory sf = ctx.getSocketFactory();
		ServerThread<FakeServer> st = new ServerThread<>(c);
		try {
			st.waitStart();
			try (LDAPConnection lc = new LDAPConnection(sf, LOCALHOST.getHostAddress(), st.command.port)) {
				lc.getRootDSE();
			}

		} finally {
			st.shutdown();
		}
	}

	@Test
	void testConnectionStartTLS() throws Exception {
		SSLContext ctx = SSLContext.getInstance("TLSv1.2");
		ctx.init(new KeyManager[] {}, new TrustManager[] { new AllowAllTrustManager() }, new SecureRandom());
		ServerThread<FakeServer> st = new ServerThread<>(createServerBase());
		try {
			st.waitStart();

			LDAPConnectionOptions opt = new LDAPConnectionOptions();

			StartTLSPostConnectProcessor starttls = new StartTLSPostConnectProcessor(ctx);

			try (LDAPConnection lc = new LDAPConnection(opt, LOCALHOST.getHostAddress(), st.command.port);
					LDAPConnectionPool p = new LDAPConnectionPool(lc, 1, 2, starttls)) {

				p.getRootDSE();
			}

		} finally {
			st.shutdown();
		}
	}

	@Test
	void testBindDisallowed() throws Exception {
		ServerThread<FakeServer> st = new ServerThread<>(createServerBase());
		try {
			st.waitStart();
			try (LDAPConnection lc = new LDAPConnection(LOCALHOST.getHostAddress(), st.command.port)) {
				lc.bind("cn=test", "test");

			} catch (LDAPException e) {
				if (e.getResultCode() != ResultCode.INVALID_CREDENTIALS) {
					throw e;
				}
			}
			assertThat(st.command.creds.collected,
					IsIterableContaining.hasItem(equalTo(new String[] { "cn=test", "test" })));
		} finally {
			st.shutdown();
		}
	}

	@Test
	void testBindAllowed() throws Exception {
		FakeServer c = createServerBase();
		c.acceptUser = "cn=test";
		c.acceptPass = "test";
		ServerThread<FakeServer> st = new ServerThread<>(c);
		try {
			st.waitStart();
			try (LDAPConnection lc = new LDAPConnection(LOCALHOST.getHostAddress(), st.command.port)) {
				lc.bind("cn=test", "test");
			}
			assertThat(st.command.creds.collected,
					IsIterableContaining.hasItem(equalTo(new String[] { "cn=test", "test" })));
		} finally {
			st.shutdown();
		}
	}

	@Test
	void testExtractUser() throws Exception {
		FakeServer c = createServerBase();
		String dn = "uid=foobar";
		c.uidAttrs = new String[] { "uid" };
		c.acceptUser = dn;
		c.acceptPass = "test";
		ServerThread<FakeServer> st = new ServerThread<>(c);
		try {
			st.waitStart();
			try (LDAPConnection lc = new LDAPConnection(LOCALHOST.getHostAddress(), st.command.port)) {
				lc.bind(dn, "test");
			}
			assertThat(st.command.creds.collected,
					IsIterableContaining.hasItem(equalTo(new String[] { "foobar", "test" })));
		} finally {
			st.shutdown();
		}
	}

	@Test
	void testLoadData() throws Exception {
		String data = getClass().getResource("/test-add.ldif").getFile();
		assertNotNull(data);
		FakeServer c = createServerBase();
		c.baseDN = new String[] { "dc=test" };
		c.load = new Path[] { Paths.get(data) };
		ServerThread<FakeServer> st = new ServerThread<>(c);
		try {
			st.waitStart();
			try (LDAPConnection lc = new LDAPConnection(LOCALHOST.getHostAddress(), st.command.port)) {
				SearchResultEntry sre = lc.getEntry("cn=foo,dc=test");
				Attribute a = sre.getAttribute("sn");
				assertNotNull(a);
				assertEquals("Test", a.getValue());
			}
		} finally {
			st.shutdown();
		}
	}

	@Test
	void testWriteCreds() throws Exception {
		Path t = Files.createTempFile("pw", ".list");
		try {
			FakeServer c = createServerBase();
			String dn = "uid=foobar";
			c.uidAttrs = new String[] { "uid" };
			c.acceptUser = dn;
			c.acceptPass = "test";
			c.writeCreds = t;
			ServerThread<FakeServer> st = new ServerThread<>(c);
			try {
				st.waitStart();
				try (LDAPConnection lc = new LDAPConnection(LOCALHOST.getHostAddress(), st.command.port)) {
					lc.bind(dn, "test");
				}
			} finally {
				st.shutdown();
			}

			List<String> lines = Files.readAllLines(t, StandardCharsets.UTF_8);

			assertThat(lines, IsCollectionWithSize.hasSize(1));
			assertThat(lines, IsIterableContaining.hasItem("foobar test"));
		} finally {
			Files.deleteIfExists(t);
		}
	}

}
