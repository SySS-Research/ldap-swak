package gs.sy.m8.ldapswak;

import java.io.Closeable;
import java.io.IOException;

public class ServerThread<T extends CommandRunnable & Closeable> extends Thread {

	
	final T command;
	private volatile boolean started;
	private volatile boolean stopped;
	
	public ServerThread(T r) {
		command = r;
	}
	
	@Override
	public void run() {
	
		try {
			command.run();
			this.started = true;
			synchronized (this) {
				notifyAll();
			}
			
			while ( true ) {
				Thread.sleep(1000);
			}
		} catch ( InterruptedException e ) {
			return;
		} catch ( Exception e ) {
			e.printStackTrace();
		} finally {
			try {
				command.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		this.stopped = true;
		synchronized (this) {
			notifyAll();
		}
	}
	
	
	public void waitStart() {
		start();
		while ( !started && !stopped ) {
			synchronized (this) {
				try {
					wait(1000);
				} catch (InterruptedException e) {
				}
			}
			
		}
	}
	
	public void shutdown() {
		try {
			interrupt();
			join(1000);
		} catch ( Exception e ) {}
	}
	
}
