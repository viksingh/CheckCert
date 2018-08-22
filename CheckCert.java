package com.saki.demo;

import java.io.FileInputStream;
import java.net.URL;
import java.nio.charset.Charset;
import java.security.Key;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;
import javax.ejb.Local;
import javax.ejb.LocalHome;
import javax.ejb.Remote;
import javax.ejb.RemoteHome;
import javax.ejb.Stateless;

import com.sap.aii.af.lib.mp.module.Module;
import com.sap.aii.af.lib.mp.module.ModuleContext;
import com.sap.aii.af.lib.mp.module.ModuleData;
import com.sap.aii.af.lib.mp.module.ModuleException;
import com.sap.aii.af.lib.mp.module.ModuleHome;
import com.sap.aii.af.lib.mp.module.ModuleLocal;
import com.sap.aii.af.lib.mp.module.ModuleLocalHome;
import com.sap.aii.af.lib.mp.module.ModuleRemote;
import com.sap.engine.interfaces.messaging.api.Message;
import com.sap.engine.interfaces.messaging.api.MessageDirection;
import com.sap.engine.interfaces.messaging.api.MessageKey;
import com.sap.engine.interfaces.messaging.api.PublicAPIAccessFactory;
import com.sap.engine.interfaces.messaging.api.auditlog.AuditAccess;
import com.sap.engine.interfaces.messaging.api.auditlog.AuditLogStatus;
import com.sap.engine.interfaces.messaging.api.exception.MessagingException;

/**
 * Session Bean implementation class CheckCert
 */

@Stateless
@Local(value={ModuleLocal.class})
@Remote(value={ModuleRemote.class})
@LocalHome(value=ModuleLocalHome.class)
@RemoteHome(value=ModuleHome.class)

public class CheckCert implements Module{

    
	public static String whereFrom(Object o) {
		  if ( o == null ) {
		    return null;
		  }
		  Class<?> c = o.getClass();
		  ClassLoader loader = c.getClassLoader();
		  if ( loader == null ) {
		    // Try the bootstrap classloader - obtained from the ultimate parent of the System Class Loader.
		    loader = ClassLoader.getSystemClassLoader();
		    while ( loader != null && loader.getParent() != null ) {
		      loader = loader.getParent();
		    }
		  }
		  if (loader != null) {
		    String name = c.getCanonicalName();
		    URL resource = loader.getResource(name.replace(".", "/") + ".class");
		    if ( resource != null ) {
		      return resource.toString();
		    }
		  }
		  return "Unknown";
		}		
	
	private AuditAccess audit;
	
	public CheckCert() {
        // TODO Auto-generated constructor stub
    }

    
    @PreDestroy
    public void ReleaseResources(){
    	
    }
    
    
    @PostConstruct
    public void InitResources(){
    	
    	try {
			audit = PublicAPIAccessFactory.getPublicAPIAccess().getAuditAccess();
		} catch (MessagingException e) {
		}    	
    }

    
	@Override
	public ModuleData process(ModuleContext moduleContext, ModuleData inputModuleData)
			throws ModuleException {
		
		Object obj = null;
		Message msg = null;
		String outputData = "";
		Boolean checkMetadata;
		MessageKey key = null;
		
		
	    String path = (String) moduleContext.getContextData("path");
	    String fileName = (String) moduleContext.getContextData("fileName");
	    String pwdCert = (String) moduleContext.getContextData("pwdCert");
	    
	    String fullPath = path + "/" + fileName;

		obj = inputModuleData.getPrincipalData();
		msg = (Message) obj;			

		if (msg.getMessageDirection().equals(MessageDirection.OUTBOUND)) {
			key = new MessageKey(msg.getMessageId(),
					MessageDirection.OUTBOUND);
		} else {
			key = new MessageKey(msg.getMessageId(),
					MessageDirection.INBOUND);
		}		
		
		audit.addAuditLogEntry(key, AuditLogStatus.SUCCESS,
		" CheckCert: Module called");
		
		   try {
			   
				audit.addAuditLogEntry(key, AuditLogStatus.SUCCESS,
				" CheckCert: Getting keystore instance PKCS12");
			   
			KeyStore ks = KeyStore.getInstance("PKCS12");
			
			audit.addAuditLogEntry(key, AuditLogStatus.SUCCESS,
			" Encoding is " + Charset.defaultCharset() );
			
			audit.addAuditLogEntry(key, AuditLogStatus.SUCCESS,
			"Full path is " + fullPath );
			
			audit.addAuditLogEntry(key, AuditLogStatus.SUCCESS,
			" Password of cert is " + pwdCert);

			
			
			ks.load(new FileInputStream(fullPath), pwdCert.toCharArray());
//			ks.load(new FileInputStream(fullPath), pwdCert.toCharArray());

			audit.addAuditLogEntry(key, AuditLogStatus.SUCCESS,
			" CheckCert: Cert loaded");
			
			
			audit.addAuditLogEntry(key, AuditLogStatus.SUCCESS,"Keystore location "+whereFrom(ks));
			audit.addAuditLogEntry(key, AuditLogStatus.SUCCESS,"JVM version " + Runtime.class.getPackage().getImplementationVersion());

			
			audit.addAuditLogEntry(key, AuditLogStatus.SUCCESS,

					"Keystore size is " + ks.size());
			
			audit.addAuditLogEntry(key, AuditLogStatus.SUCCESS,

					"Keystore provider is " + ks.getProvider());

			audit.addAuditLogEntry(key, AuditLogStatus.SUCCESS,
					"KS type is " + ks.getType() );

			
		    Enumeration<String> en = ks.aliases();
		    
		    for (; en.hasMoreElements();) {
		    	
		    	 String alias = (String)en.nextElement();
				   
					audit.addAuditLogEntry(key, AuditLogStatus.SUCCESS,
					"Alias is " + alias );
				    
					audit.addAuditLogEntry(key, AuditLogStatus.SUCCESS,
							"Alias length is " + alias.length() );

					
					audit.addAuditLogEntry(key, AuditLogStatus.SUCCESS,
							" Contains alias: " + alias + " " + ks.containsAlias(alias));

					
					audit.addAuditLogEntry(key, AuditLogStatus.SUCCESS,"Keystore : Is Cert ? : "+ks.isCertificateEntry(alias));
					audit.addAuditLogEntry(key, AuditLogStatus.SUCCESS,"Keystore : Is Key ? : "+ks.isKeyEntry(alias));
					
					
					 if (ks.isKeyEntry(alias)){
						    Key key1 = ks.getKey(alias, pwdCert.toCharArray());
						    audit.addAuditLogEntry(key, AuditLogStatus.SUCCESS, "Key is " +key1.toString());
						    }					
					
					// Why is this null - works on local PC and standalone tests in Java SE environments
					
				    X509Certificate x509cert = ((X509Certificate)ks.getCertificate(alias));
				    
				    audit.addAuditLogEntry(key, AuditLogStatus.SUCCESS, "Cert type is " + x509cert.getType());

					audit.addAuditLogEntry(key, AuditLogStatus.SUCCESS, " Valid till : " + x509cert.getNotAfter());		    	

		    }
		    
		   
		    
		    
//		     PrivateKey privatekey = ((PrivateKey)ks.getKey(alias, "Th3N3s7.1819".toCharArray()));

		     			
			
		   } catch (Exception e) {

				audit.addAuditLogEntry(key, AuditLogStatus.SUCCESS,e.getMessage());
		}		
		
		return inputModuleData;
	}

}
