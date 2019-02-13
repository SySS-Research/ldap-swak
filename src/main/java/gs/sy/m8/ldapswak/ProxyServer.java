package gs.sy.m8.ldapswak;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.net.SocketFactory;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.unboundid.ldap.listener.AccessLogRequestHandler;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryListenerConfig;
import com.unboundid.ldap.listener.LDAPListener;
import com.unboundid.ldap.listener.LDAPListenerConfig;
import com.unboundid.ldap.listener.LDAPListenerRequestHandler;
import com.unboundid.ldap.listener.ProxyRequestHandler;
import com.unboundid.ldap.listener.ReadOnlyInMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.StartTLSRequestHandler;
import com.unboundid.ldap.listener.interceptor.InMemoryOperationInterceptorRequestHandler;
import com.unboundid.ldap.sdk.BindRequest;
import com.unboundid.ldap.sdk.DNSSRVRecordServerSet;
import com.unboundid.ldap.sdk.FailoverServerSet;
import com.unboundid.ldap.sdk.LDAPConnectionOptions;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.PostConnectProcessor;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.ServerSet;
import com.unboundid.util.StaticUtils;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

@Command(name = "proxy", description = "Launch proxy LDAP server")
public class ProxyServer extends BaseCommand implements CommandRunnable {

	private static final Logger log = LoggerFactory.getLogger(ProxyServer.class);

	@Option(names = { "--srv" }, description = { "Connect to backend servers resolved using a DNS SRV record" })
	String proxySRV;

	@Option(names = { "--server" })
	String[] proxyServers;

	boolean proxySSL;

	@Override
	public void run() throws Exception {

		InMemoryDirectoryServerConfig ldapcfg = createConfig();
		ldapcfg.addInMemoryOperationInterceptor(new ProxyInterceptor(this));
		ldapcfg.addInMemoryOperationInterceptor(new CredentialsOperationInterceptor(this));

		if (requestLog) {
			ldapcfg.addInMemoryOperationInterceptor(new LDIFLoggingOperationInterceptor());
		}

		ServerSet serverSet = createServerSet();

		log.info("Starting {} proxy on {}:{}", ssl ? "SSL" : (nostarttls ? "plain" : "StartTLS"),
				bind != null ? bind.getHostAddress() : "*", port);

		startProxyServer(ldapcfg, serverSet);

	}

	private ServerSet createServerSet() {
		SocketFactory socketFactory = null;
		LDAPConnectionOptions connectionOptions = null;
		BindRequest bindRequest = null;
		PostConnectProcessor postConnectProcessor = null;

		if (proxySRV != null) {
			return new DNSSRVRecordServerSet(proxySRV, null, null, -1, socketFactory, connectionOptions, bindRequest,
					postConnectProcessor);
		}

		if (proxyServers == null) {
			throw new IllegalArgumentException("Backend server specification required");
		}

		String hosts[] = new String[proxyServers.length];
		int ports[] = new int[proxyServers.length];

		int defPort = proxySSL ? 636 : 389;

		for (int i = 0; i < proxyServers.length; i++) {
			String spec = proxyServers[i];
			String host = null;
			int sep = spec.indexOf(':');
			if (sep < 0) {
				host = spec;
				port = defPort;
			} else {
				host = spec.substring(0, sep);
				port = Integer.parseInt(spec.substring(sep + 1));
			}
			hosts[i] = host;
			ports[i] = port;
		}

		return new FailoverServerSet(hosts, ports, socketFactory, connectionOptions, bindRequest, postConnectProcessor);
	}

	private void startProxyServer(InMemoryDirectoryServerConfig ldapcfg, ServerSet serverSet) throws LDAPException {
		ReadOnlyInMemoryDirectoryServerConfig config = new ReadOnlyInMemoryDirectoryServerConfig(ldapcfg);

		ProxyRequestHandler proxyHandler = new ProxyRequestHandler(serverSet);

		LDAPListenerRequestHandler requestHandler = proxyHandler;

		if (config.getAccessLogHandler() != null) {
			requestHandler = new AccessLogRequestHandler(config.getAccessLogHandler(), requestHandler);
		}

		if (!config.getOperationInterceptors().isEmpty()) {
			requestHandler = new InMemoryOperationInterceptorRequestHandler(config.getOperationInterceptors(),
					requestHandler);
		}

		final List<InMemoryListenerConfig> listenerConfigs = config.getListenerConfigs();

		LinkedHashMap<String, LDAPListener> listeners = new LinkedHashMap<String, LDAPListener>(listenerConfigs.size());
		LinkedHashMap<String, LDAPListenerConfig> ldapListenerConfigs = new LinkedHashMap<String, LDAPListenerConfig>(
				listenerConfigs.size());
		LinkedHashMap<String, SocketFactory> clientSocketFactories = new LinkedHashMap<String, SocketFactory>(
				listenerConfigs.size());

		for (final InMemoryListenerConfig c : listenerConfigs) {
			final String name = StaticUtils.toLowerCase(c.getListenerName());

			final LDAPListenerRequestHandler listenerRequestHandler;
			if (c.getStartTLSSocketFactory() == null) {
				listenerRequestHandler = requestHandler;
			} else {
				listenerRequestHandler = new StartTLSRequestHandler(c.getStartTLSSocketFactory(), requestHandler);
			}

			final LDAPListenerConfig listenerCfg = new LDAPListenerConfig(c.getListenPort(), listenerRequestHandler);
			listenerCfg.setMaxConnections(config.getMaxConnections());
			listenerCfg.setExceptionHandler(config.getListenerExceptionHandler());
			listenerCfg.setListenAddress(c.getListenAddress());
			listenerCfg.setServerSocketFactory(c.getServerSocketFactory());

			ldapListenerConfigs.put(name, listenerCfg);

			if (c.getClientSocketFactory() != null) {
				clientSocketFactories.put(name, c.getClientSocketFactory());
			}
		}
		startListening(listeners, ldapListenerConfigs);
	}

	private void startListening(LinkedHashMap<String, LDAPListener> listeners,
			LinkedHashMap<String, LDAPListenerConfig> ldapListenerConfigs) throws LDAPException {
		final ArrayList<String> messages = new ArrayList<String>(listeners.size());

		for (final Map.Entry<String, LDAPListenerConfig> cfgEntry : ldapListenerConfigs.entrySet()) {
			final String name = cfgEntry.getKey();

			if (listeners.containsKey(name)) {
				// This listener is already running.
				continue;
			}

			final LDAPListenerConfig listenerConfig = cfgEntry.getValue();
			final LDAPListener listener = new LDAPListener(listenerConfig);

			try {
				listener.startListening();
				listenerConfig.setListenPort(listener.getListenPort());
				listeners.put(name, listener);
			} catch (final Exception e) {
				log.error("Failed to start listener", e);
				messages.add(e.toString());
			}
		}

		if (!messages.isEmpty()) {
			throw new LDAPException(ResultCode.LOCAL_ERROR, StaticUtils.concatenateStrings(messages));
		}
	}
}
