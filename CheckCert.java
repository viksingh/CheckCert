package com.saki.demo;

import java.io.FileInputStream;
import java.security.KeyStore;
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
			" CheckCert: Loading Certificate");

			
			ks.load(new FileInputStream("/tmp/UYcert.pfx"), "Th3N3s7.1819".toCharArray());			

			audit.addAuditLogEntry(key, AuditLogStatus.SUCCESS,
			" CheckCert: Cert loaded");

			
		    Enumeration en = ks.aliases();
		    String alias = (String)en.nextElement();

			audit.addAuditLogEntry(key, AuditLogStatus.SUCCESS,
			"Alias is " + alias);
		    
			
// Why is this null - works on local PC and standalone tests in Java SE environments			
			Certificate cert = ks.getCertificate(alias);
			audit.addAuditLogEntry(key, AuditLogStatus.SUCCESS,
					" CheckCert: Normal cert " + cert.getType() );

			
		    X509Certificate x509cert = ((X509Certificate)ks.getCertificate(alias));

			audit.addAuditLogEntry(key, AuditLogStatus.SUCCESS,
			" CheckCert: Cert loaded" + x509cert.getSubjectDN().getName() +" Valid till : " + x509cert.getNotAfter());
		    
		    
//		     PrivateKey privatekey = ((PrivateKey)ks.getKey(alias, "Th3N3s7.1819".toCharArray()));

		     			
			
		   } catch (Exception e) {

				audit.addAuditLogEntry(key, AuditLogStatus.SUCCESS,e.getMessage());
		}		
		
		return null;
	}

}
