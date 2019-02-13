package gs.sy.m8.ldapswk;

import java.io.IOException;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.jar.Manifest;

import picocli.CommandLine.IVersionProvider;

public class Version implements IVersionProvider {

	@Override
	public String[] getVersion() throws Exception {

		URLClassLoader cl = (URLClassLoader) getClass().getClassLoader();
		try {
			URL url = cl.findResource("META-INF/MANIFEST.MF");
			if (url != null) {
				Manifest manifest = new Manifest(url.openStream());
				String ver = manifest.getMainAttributes().getValue("Version");
				if ( ver != null ) {
					return new String[] { ver,
							com.unboundid.ldap.sdk.Version.FULL_VERSION_STRING };
				}
			}
		} catch (IOException E) {
		}
		return new String[] { "dev", com.unboundid.ldap.sdk.Version.FULL_VERSION_STRING };
	}
}
