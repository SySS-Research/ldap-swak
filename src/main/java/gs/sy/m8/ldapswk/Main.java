package gs.sy.m8.ldapswk;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import picocli.CommandLine;

public class Main {
	private static final Logger log = LoggerFactory.getLogger(Main.class);

	public static void main(String[] args) {
		Config cfg = new Config();
		CommandLine cli = new CommandLine(cfg);
		cli.parse(args);
		
		if ( cfg.usageHelpRequested ) {
			cli.usage(System.out);
			return;
		} else if ( cfg.versionRequested ) {
			cli.printVersionHelp(System.out);
			return;
		}

		setupLogger(cfg);
	
		
		log.info("Starting...");
		
	}
	
	
	private static void setupLogger(Config cfg) {
		Logger root = LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);
		try {
			Class<?> logCl = Class.forName("ch.qos.logback.classic.Logger");
			if ( logCl.isInstance(root)) {
				ch.qos.logback.classic.Level l =ch.qos.logback.classic.Level.INFO;
				
				if ( cfg.quiet ) {
					l = ch.qos.logback.classic.Level.WARN;
				} else if ( cfg.verbosity.length >= 2 ) {
					l = ch.qos.logback.classic.Level.TRACE;
				} else if ( cfg.verbosity.length >= 1 ) {
					l = ch.qos.logback.classic.Level.DEBUG;
				}
				
				((ch.qos.logback.classic.Logger)root).setLevel(l);
			}
		} catch ( ClassNotFoundException e ) {
		}
	}
}
