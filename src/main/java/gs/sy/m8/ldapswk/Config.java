package gs.sy.m8.ldapswk;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

@Command(description = "LDAP Swiss Army Knife", name = "ldapswk", versionProvider = Version.class)
public class Config {

	@Option(names = { "-h", "--help" }, usageHelp = true, description = "Display this help message.")
	boolean usageHelpRequested;

	@Option(names = { "-V", "--version" }, versionHelp = true, description = "print version information and exit")
	boolean versionRequested;

	@Option(names = { "-v", "--verbose" }, description = { "Specify multiple -v options to increase verbosity.",
			"For example, `-v -v -v` or `-vvv`" })
	boolean[] verbosity = new boolean[0];

	@Option(names = { "-q", "--quiet" }, description = { "Only show warnings and errors" })
	boolean quiet;

	int port;

	@Option(names = { "--ssl" }, defaultValue = "false", description = { "Run a SSL/TLS listener" })
	boolean ssl;

	@Option(names = { "--nostarttls" }, defaultValue = "false", description = { "Disable support for StartTLS" })
	boolean nostarttls;

}
