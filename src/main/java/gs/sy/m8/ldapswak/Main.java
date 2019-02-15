package gs.sy.m8.ldapswak;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.inject.Guice;
import com.google.inject.Injector;

import picocli.CommandLine;

public class Main {
	private static final Logger log = LoggerFactory.getLogger(Main.class);

	public static void main(String[] args) {
		Injector injector = Guice.createInjector(new LDAPModule());
		MainCommand mainCommand = new MainCommand();
		CommandLine cli = new CommandLine(mainCommand, new GuiceFactory(injector));
		List<CommandLine> parsed = cli.parse(args);
		
		if ( parsed.size() == 1 ) {
			parsed.get(0).usage(System.out);
			return;
		}
		
		for (CommandLine p : parsed) {
		    if (p.isUsageHelpRequested()) {
		        p.usage(System.out);
		        return;
		    } else if (p.isVersionHelpRequested()) {
		        p.printVersionHelp(System.out);
		        return;
		    }
		}

		CommandLine last = parsed.get(parsed.size() - 1);
		BaseCommand cmd = last.getCommand();

		setupLogger(cmd);

		log.debug("Starting initialization...");
		try {
			log.debug("Command is {}", last.getCommandName());
			if ( cmd instanceof CommandRunnable ) {
				((CommandRunnable)cmd).run();
			}
		} catch (Exception e) {
			log.error("Exception occured initializing server", e);
		}
	}

	private static void setupLogger(BaseCommand cfg) {
		Logger root = LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);
		try {
			Class<?> logCl = Class.forName("ch.qos.logback.classic.Logger");
			if (logCl.isInstance(root)) {
				ch.qos.logback.classic.Level l = ch.qos.logback.classic.Level.INFO;

				if (cfg.quiet) {
					l = ch.qos.logback.classic.Level.WARN;
				} else if (cfg.verbosity.length >= 2) {
					l = ch.qos.logback.classic.Level.TRACE;
				} else if (cfg.verbosity.length >= 1) {
					l = ch.qos.logback.classic.Level.DEBUG;
				}

				((ch.qos.logback.classic.Logger) root).setLevel(l);
			}
		} catch (ClassNotFoundException e) {
		}
	}
}
