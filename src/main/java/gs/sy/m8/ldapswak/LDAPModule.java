package gs.sy.m8.ldapswak;

import com.google.inject.Binder;
import com.google.inject.Module;

public class LDAPModule implements Module {


	
	@Override
	public void configure(Binder bind) {
		//bind.bind(Config.class).toInstance(this.config);
		bind.bind(CommandRunnable.class).to(FakeServer.class);
	}

}
