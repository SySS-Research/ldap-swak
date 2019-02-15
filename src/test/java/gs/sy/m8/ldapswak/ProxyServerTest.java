package gs.sy.m8.ldapswak;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.nio.file.Path;
import java.nio.file.Paths;

import org.junit.jupiter.api.Test;

import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.SearchResultEntry;

public class ProxyServerTest extends BaseServerTest {

	@Test
	void testProxy() throws Exception {
		FakeServer c = createServerBase();
		String data = getClass().getResource("/test-add.ldif").getFile();
		assertNotNull(data);
		c.baseDN = new String[] { "dc=test" };
		c.load = new Path[] { Paths.get(data) };
		ProxyServer p = createProxyBase();

		p.proxyServers = new String[] { String.format("%s:%d", c.bind.getHostAddress(), c.port) };

		ServerThread<FakeServer> st = new ServerThread<>(c);
		try {
			st.waitStart();
			ServerThread<ProxyServer> pt = new ServerThread<>(p);
			try {
				pt.waitStart();
				
				assertNotEquals(st.command.port, pt.command.port);

				try (LDAPConnection lc = new LDAPConnection(LOCALHOST.getHostAddress(), pt.command.port)) {

					SearchResultEntry sre = lc.getEntry("cn=foo,dc=test");
					Attribute a = sre.getAttribute("sn");
					assertNotNull(a);
					assertEquals("Test", a.getValue());
				}
			} finally {
				pt.shutdown();
			}
		} finally {
			st.shutdown();
		}
	}

	@Test
	void testProxySSL() throws Exception {
		FakeServer c = createServerBase();
		String data = getClass().getResource("/test-add.ldif").getFile();
		assertNotNull(data);
		c.baseDN = new String[] { "dc=test" };
		c.load = new Path[] { Paths.get(data) };
		c.ssl = true;
		ProxyServer p = createProxyBase();

		p.proxyServers = new String[] { String.format("%s:%d", c.bind.getHostAddress(), c.port) };
		p.proxySSL = true;
		
		ServerThread<FakeServer> st = new ServerThread<>(c);
		try {
			st.waitStart();
			ServerThread<ProxyServer> pt = new ServerThread<>(p);
			try {
				pt.waitStart();
				
				assertNotEquals(st.command.port, pt.command.port);

				try (LDAPConnection lc = new LDAPConnection(LOCALHOST.getHostAddress(), pt.command.port)) {

					SearchResultEntry sre = lc.getEntry("cn=foo,dc=test");
					Attribute a = sre.getAttribute("sn");
					assertNotNull(a);
					assertEquals("Test", a.getValue());
				}
			} finally {
				pt.shutdown();
			}
		} finally {
			st.shutdown();
		}
	}

}
