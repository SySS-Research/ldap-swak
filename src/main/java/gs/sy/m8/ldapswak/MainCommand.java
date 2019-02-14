package gs.sy.m8.ldapswak;

import picocli.CommandLine.Command;

@Command(description = "LDAP Swiss Army Knife",  
versionProvider = Version.class,
subcommands = { FakeServer.class, ProxyServer.class, JNDIServer.class } )
public class MainCommand extends BaseCommand {

}
