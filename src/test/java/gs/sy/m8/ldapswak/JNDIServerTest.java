package gs.sy.m8.ldapswak;

import static org.junit.jupiter.api.Assertions.*;
import static org.hamcrest.MatcherAssert.assertThat;

import java.io.File;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Hashtable;
import java.util.Random;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.Reference;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.ldap.LdapReferralException;

import org.hamcrest.collection.ArrayMatching;
import org.hamcrest.core.IsInstanceOf;
import org.junit.jupiter.api.Test;

import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchResult;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.ldap.sdk.SearchResultReference;

public class JNDIServerTest extends BaseServerTest {

	@Test
	public void testReferral() throws Exception {
		JNDIServer c = createJNDIBase();
		c.referral = "ldap://test";
		ServerThread<JNDIServer> st = new ServerThread<>(c);
		try {
			st.waitStart();

			try (LDAPConnection lc = new LDAPConnection(LOCALHOST.getHostAddress(), st.command.port)) {
				try {
					lc.getEntry(c.baseDN[0]);
				} catch (LDAPException e) {
					if (e.getResultCode() != ResultCode.REFERRAL) {
						throw e;
					}

					if (e.getReferralURLs().length > 0) {
						assertEquals(c.referral, e.getReferralURLs()[0]);
					} else {

						SearchResult r = (SearchResult) e.toLDAPResult();
						assertEquals(1, r.getReferenceCount());
						SearchResultReference ref = r.getSearchReferences().get(0);
						assertThat(ref.getReferralURLs(), ArrayMatching.hasItemInArray(c.referral));
					}
				}
			}
		} finally {
			st.shutdown();
		}
	}

	@Test
	public void testJNDIReferral() throws Exception {
		JNDIServer c = createJNDIBase();
		c.referral = "rmi://test/bar";
		ServerThread<JNDIServer> st = new ServerThread<>(c);
		try {
			st.waitStart();

			Hashtable<String, Object> env = new Hashtable<>();
			env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
			env.put(Context.PROVIDER_URL, String.format("ldap://%s:%d", c.bind.getHostAddress(), c.port));
			env.put(Context.REFERRAL, "throw");

			InitialDirContext ctx = new InitialDirContext(env);
			try {
				try {
					ctx.lookup("cn=test");
				} catch (LdapReferralException e) {
					assertEquals(c.referral, e.getReferralInfo());
				}
			} finally {
				ctx.close();
			}

		} finally {
			st.shutdown();
		}
	}
	
	
	@Test
	public void testReference() throws Exception {
		JNDIServer c = createJNDIBase();
		c.refCodebase = new URL("http://localhost:12345/test/");
		c.refClass = "MyExploit";
		ServerThread<JNDIServer> st = new ServerThread<>(c);
		try {
			st.waitStart();

			try (LDAPConnection lc = new LDAPConnection(LOCALHOST.getHostAddress(), st.command.port)) {
				SearchResultEntry sre = lc.getEntry(c.baseDN[0]);

				assertThat(sre.getObjectClassValues(), ArrayMatching.hasItemInArray("javaNamingReference"));

				assertEquals(c.refCodebase, new URL(sre.getAttributeValue("javaCodeBase")));
				assertEquals(c.refClass, sre.getAttributeValue("javaFactory"));
			}
		} finally {
			st.shutdown();
		}
	}

	@Test
	public void testJNDIReference() throws Exception {
		JNDIServer c = createJNDIBase();
		c.refCodebase = new URL("http://localhost:12345/test/");
		c.refClass = "MyExploit";
		ServerThread<JNDIServer> st = new ServerThread<>(c);
		try {
			st.waitStart();

			DirContext ctx = InitialContext.doLookup(String.format("ldap://%s:%d", c.bind.getHostAddress(), c.port));

			try {
				Object o = ctx.lookup("cn=test");
				assertThat(o, IsInstanceOf.instanceOf(Reference.class));

				Reference r = (Reference) o;
				assertEquals(c.refClass, r.getFactoryClassName());
				assertEquals(c.refCodebase, new URL(r.getFactoryClassLocation()));
			} finally {
				ctx.close();
			}

		} finally {
			st.shutdown();
		}
	}

	@Test
	public void testSerialized() throws Exception {

		byte[] testData = new byte[1024];
		new Random().nextBytes(testData);
		Path t = Files.createTempFile("test", ".data");

		Files.write(t, testData, StandardOpenOption.TRUNCATE_EXISTING);
		try {

			JNDIServer c = createJNDIBase();
			c.serialized = t;
			ServerThread<JNDIServer> st = new ServerThread<>(c);
			try {
				st.waitStart();

				try (LDAPConnection lc = new LDAPConnection(LOCALHOST.getHostAddress(), st.command.port)) {
					SearchResultEntry sre = lc.getEntry(c.baseDN[0]);

					assertThat(sre.getObjectClassValues(), ArrayMatching.hasItemInArray("javaSerializedData"));

					byte[] returned = sre.getAttributeValueBytes("javaSerializedData");
					assertArrayEquals(testData, returned);
				}
			} finally {
				st.shutdown();
			}
		} finally {
			Files.deleteIfExists(t);
		}
	}

	@Test
	public void testJNDISerialized() throws Exception {

		Path t = Files.createTempFile("test", ".data");

		try (OutputStream os = Files.newOutputStream(t, StandardOpenOption.TRUNCATE_EXISTING);
				ObjectOutputStream oos = new ObjectOutputStream(os)) {
			oos.writeObject(new File("/tmp/test"));
		}
		try {

			JNDIServer c = createJNDIBase();
			c.serialized = t;
			ServerThread<JNDIServer> st = new ServerThread<>(c);
			try {
				st.waitStart();

				DirContext ctx = InitialContext
						.doLookup(String.format("ldap://%s:%d", c.bind.getHostAddress(), c.port));

				try {
					Object o = ctx.lookup("cn=test");
					assertThat(o, IsInstanceOf.instanceOf(File.class));
				} finally {
					ctx.close();
				}

			} finally {
				st.shutdown();
			}
		} finally {
			Files.deleteIfExists(t);
		}
	}

	JNDIServer createJNDIBase() {
		JNDIServer ps = new JNDIServer();
		basicSetup(ps);
		return ps;
	}
}
