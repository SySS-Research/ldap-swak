package gs.sy.m8.ldapswak;

import java.util.logging.Handler;
import java.util.logging.LogRecord;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class AccessLog extends Handler {
	
	private static final Logger log = LoggerFactory.getLogger("access");

	@Override
	public void publish(LogRecord record) {	
		log.info(record.getMessage(),record.getThrown());
	}

	@Override
	public void flush() {
	}

	@Override
	public void close() throws SecurityException {
	}

}
