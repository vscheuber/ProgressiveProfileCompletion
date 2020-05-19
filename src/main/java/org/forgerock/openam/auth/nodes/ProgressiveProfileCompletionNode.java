/*
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2017-2018 ForgeRock AS.
 */


package org.forgerock.openam.auth.nodes;

import static org.forgerock.openam.auth.node.api.SharedStateConstants.USERNAME;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.ResourceBundle;

import javax.inject.Inject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.ConfirmationCallback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.TextOutputCallback;

import org.forgerock.json.JsonPointer;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.sm.annotations.adapters.Password;
import org.forgerock.util.i18n.PreferredLocales;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.collect.ImmutableList;
import com.google.inject.assistedinject.Assisted;
import com.sun.identity.authentication.callbacks.ScriptTextOutputCallback;
import com.sun.identity.sm.RequiredValueValidator;

@Node.Metadata(outcomeProvider = ProgressiveProfileCompletionNode.ProgressiveProfileCompletionNodeOutcomeProvider.class,
        configClass = ProgressiveProfileCompletionNode.Config.class)
public class ProgressiveProfileCompletionNode implements Node {

    private static final String BUNDLE = ProgressiveProfileCompletionNode.class.getName().replace(".", "/");
    private final Logger logger = LoggerFactory.getLogger("amAuth");
    private final static String PPC_LOG_ID = "ProgressiveProfileCompletionNode";
    private final static String PPC_TRIGGERED_KEY = "ProgressiveProfileCompletionNode_PPC_Triggered";
    private final static String PPC_MAP_KEY = "ProgressiveProfileCompletionNode_PPC_Map";
    private final Config config;

    /**
     * Configuration for the node.
     * It can have as many attributes as needed, or none.
     */
    public interface Config {

        @Attribute(order = 100, validators = {RequiredValueValidator.class})
        String idmBaseUrl();

        @Attribute(order = 200, validators = {RequiredValueValidator.class})
        default String idmAdminUser() { return "openidm-admin"; }

        @Attribute(order = 300, validators = {RequiredValueValidator.class})
        @Password
        char[] idmAdminPassword();
        
    }


    /*
     * Constructs a new GetSessionPropertiesNode instance.
     * We can have Assisted:
     * * Config config
     * * UUID nodeId
     *
     * We may want to Inject:
     * CoreWrapper
     */
    @Inject
    public ProgressiveProfileCompletionNode(@Assisted Config config) {
    	this.config = config;
    }

    @Override
    public Action process(TreeContext context) throws NodeProcessException {
        JsonValue sharedState = context.sharedState;
        JsonValue transientState = context.transientState;
        logger.debug("{}: Start", PPC_LOG_ID);

        if (context.getCallback(ConfirmationCallback.class).isPresent()) {
            ConfirmationCallback confirmationCallback = context.getCallback(ConfirmationCallback.class).get();
            if (confirmationCallback.getSelectedIndex() == 0) {
            	logger.debug("{}: Saving...", PPC_LOG_ID);
            	
            	submitPPCResponse(sharedState.get(USERNAME).asString(), createPPCResponse(context));
            	sharedState.remove(PPC_MAP_KEY);
            	logger.debug("{}: Completed.", PPC_LOG_ID);
            	
                return Action.goTo(PPCOutcome.COMPLETED.name()).replaceSharedState(sharedState).replaceTransientState(transientState).build();
            }
            logger.debug("{}: Canceled.", PPC_LOG_ID);
            return Action.goTo(PPCOutcome.CANCELED.name()).replaceSharedState(sharedState).replaceTransientState(transientState).build();
        }

        if (wasPPCTriggered(sharedState)) {
        	logger.debug("{}: Progressive profile completion initiated", PPC_LOG_ID);
        	return Action.send(createPPCCallbacks(context)).replaceSharedState(sharedState).replaceTransientState(transientState).build();
        }
        
        logger.debug("{}: Nothing to do.", PPC_LOG_ID);
        return Action.goTo(PPCOutcome.CONTINUE.name()).replaceSharedState(sharedState).replaceTransientState(transientState).build();

    }

    public static String createClientSideScriptExecutorFunction(String script) {
        return String.format(
                "(function(output) {\n" +
                "    var autoSubmitDelay = 0,\n" +
                "        submitted = false;\n" +
                "    function submit() {\n" +
                "        if (submitted) {\n" +
                "            return;\n" +
                "        }" +
                "        document.forms[0].submit();\n" +
                "        submitted = true;\n" +
                "    }\n" +
                "    %s\n" + // script
                "    setTimeout(submit, autoSubmitDelay);\n" +
                "}) (document.forms[0].elements['nada']);\n",
                script);
    }

    /**
     * The possible outcomes for the LdapDecisionNode.
     */
    public enum PPCOutcome {
        /**
         * Nothing to do.
         */
        CONTINUE,
        /**
         * Completed all progressive profile completion prompts.
         */
        COMPLETED,
        /**
         * Partially completed progressive profile completion prompts.
         */
        PARTIAL,
        /**
         * Canceled.
         */
        CANCELED
    }


    /**
     * Defines the possible outcomes from this Login node.
     */
    public static class ProgressiveProfileCompletionNodeOutcomeProvider implements org.forgerock.openam.auth.node.api.OutcomeProvider {
        @Override
        public List<Outcome> getOutcomes(PreferredLocales locales, JsonValue nodeAttributes) {
            ResourceBundle bundle = locales.getBundleInPreferredLocale(ProgressiveProfileCompletionNode.BUNDLE,
                                                                       ProgressiveProfileCompletionNodeOutcomeProvider.class.getClassLoader());
            return ImmutableList.of(
                    new Outcome(PPCOutcome.CONTINUE.name(), bundle.getString("okOutcome")),
                    new Outcome(PPCOutcome.COMPLETED.name(), bundle.getString("acceptOutcome")),
                    new Outcome(PPCOutcome.CANCELED.name(), bundle.getString("cancelOutcome")));
        }
    }
    
    /* Authentication, which DID trigger PPC
		{
		    "_id": "login",
		    "authorization": {
		        "authLogin": true,
		        "roles": [
		            "managed/role/0dcff7c4-9fb3-4ff9-b388-d545ddcd8569"
		        ],
		        "ipAddress": "192.168.7.100",
		        "authenticationId": "openidm-admin",
		        "queryId": "credential-internaluser-query",
		        "userRolesProperty": "authzRoles",
		        "processesRequired": true,
		        "component": "managed/user",
		        "adminUser": "openidm-admin",
		        "authenticationIdProperty": "username",
		        "requiredProfileProcesses": [
		            "selfservice/profile"
		        ],
		        "id": "vscheuber",
		        "moduleId": "INTERNAL_USER"
		    },
		    "authenticationId": "vscheuber"
		}
		
		DID NOT trigger PPC
		{
		    "_id": "login",
		    "authorization": {
		        "userRolesProperty": "authzRoles",
		        "component": "managed/user",
		        "authLogin": true,
		        "adminUser": "openidm-admin",
		        "authenticationIdProperty": "username",
		        "roles": [
		            "internal/role/openidm-authorized",
		            "managed/role/0dcff7c4-9fb3-4ff9-b388-d545ddcd8569"
		        ],
		        "ipAddress": "192.168.7.100",
		        "authenticationId": "openidm-admin",
		        "id": "vscheuber",
		        "moduleId": "INTERNAL_USER",
		        "queryId": "credential-internaluser-query"
		    },
		    "authenticationId": "vscheuber"
		}
     */
    
    private boolean wasPPCTriggered(JsonValue sharedState) {
    	if (sharedState.get(new JsonPointer(PPC_TRIGGERED_KEY)) == null) {
    		JSONObject response = authenticateAs(sharedState.get(USERNAME).asString());
        	try {
    			if (null != response &&
    				response.has("authorization") && 
    				response.getJSONObject("authorization").has("requiredProfileProcesses")) {
    				sharedState.put(PPC_TRIGGERED_KEY, true);
    				return true;
    			}
    		} catch (JSONException e) {
    			logger.debug(PPC_LOG_ID + ": wasPPCTriggered: Error parsing auth response: " + e.getMessage(), e);
    		}
    	}
    	else {
    		return sharedState.get(PPC_TRIGGERED_KEY).asBoolean();
    	}
		sharedState.put(PPC_TRIGGERED_KEY, false);
    	return false;
    }
    
    private JSONObject authenticateAs(String username) {
    	String idmBaseUrl = config.idmBaseUrl();
    	String idmAdminUser = config.idmAdminUser();
    	String idmAdminPassword = new String(config.idmAdminPassword());
    	String idmTermsAndConditionsUrl = String.format("%s/authentication?_action=login&_prettyPrint=true", idmBaseUrl);
        try {
            URL url = new URL(idmTermsAndConditionsUrl);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Accept", "*/*");
            conn.setRequestProperty("content-type", "application/json");
            conn.setRequestProperty("X-OpenIDM-Username", idmAdminUser);
            conn.setRequestProperty("X-OpenIDM-Password", idmAdminPassword);
            conn.setRequestProperty("X-OpenIDM-NoSession", "false");
            conn.setRequestProperty("X-OpenIDM-RunAs", username);
            conn.setRequestProperty("User-Agent", "ForgeRock ProgressiveProfileCompletion Authentication Node");

            // handle response
            String response = "";
            BufferedReader br = new BufferedReader(new InputStreamReader((conn.getInputStream())));
            String output;
            while ((output = br.readLine()) != null) {
                response = response + output;
            }
            br.close();
            // end handle response
            
    		int responseCode = conn.getResponseCode();
            if ( responseCode == 200 ) {
            	logger.debug("{}: authenticateAs: HTTP Success: response code - {}, response: {}", PPC_LOG_ID, responseCode, response);
                
                conn.disconnect();
                
                JSONObject jsonResponse = new JSONObject(response);
                String authId = jsonResponse.getString("authenticationId");
                if ( username.equalsIgnoreCase(authId) ) {
                	return jsonResponse;
                }
                
                logger.error("{}: authenticateAs: runAs failed! Tried to authenticate as {} but got session for {}. Check your IDM runAs configuration in authentication.json.", PPC_LOG_ID, username, authId);
                return null;
            }
            else {
            	String responseMessage = conn.getResponseMessage();
            	logger.error("authenticateAs: HTTP failed, response code: {} - {}, response: {}", PPC_LOG_ID, responseCode, responseMessage, response);
                
                conn.disconnect();
                return null;
            }
        } catch (Throwable t) {
        	logger.error(PPC_LOG_ID + ": authenticateAs: ", t);
        }
        return null;
    }
    
    /* selfservice/profile HAS NO Requirements
		{
		    "_id": "1",
		    "_rev": "1153428953",
		    "type": "conditionaluser",
		    "tag": "initial",
		    "requirements": {}
		}
     */
    
    /* selfservice/profile HAS Requirements
		{
		    "_id": "1",
		    "_rev": "1725275522",
		    "type": "conditionaluser",
		    "tag": "initial",
		    "requirements": {
		        "$schema": "http://json-schema.org/draft-04/schema#",
		        "description": "Attribute Details",
		        "type": "object",
		        "properties": {},
		        "attributes": [
		            {
		                "name": "postalAddress",
		                "isRequired": false,
		                "schema": {
		                    "type": "string",
		                    "title": "Address 1",
		                    "description": "Address 1",
		                    "viewable": true,
		                    "userEditable": true,
		                    "usageDescription": null,
		                    "isPersonal": true
		                },
		                "value": "512 Blue Agave Ln"
		            },
		            {
		                "name": "city",
		                "isRequired": false,
		                "schema": {
		                    "type": "string",
		                    "title": "City",
		                    "description": "City",
		                    "viewable": true,
		                    "userEditable": true,
		                    "usageDescription": null,
		                    "isPersonal": false
		                },
		                "value": "Georgetown"
		            },
		            {
		                "name": "postalCode",
		                "isRequired": false,
		                "schema": {
		                    "type": "string",
		                    "title": "Postal Code",
		                    "description": "Postal Code",
		                    "viewable": true,
		                    "userEditable": true,
		                    "usageDescription": null,
		                    "isPersonal": false
		                },
		                "value": "78626"
		            }
		        ],
		        "uiConfig": {
		            "displayName": "Complete your profile",
		            "purpose": "Help us get to know you better",
		            "buttonText": "Save"
		        }
		    }
		}
	*/
    
    private List<Callback> createPPCCallbacks(TreeContext context) {
    	ArrayList<Callback> callbacks = new ArrayList<Callback>();
    	try {
	    	JSONObject response = readPPCRequirements(context.sharedState.get(USERNAME).asString());
	    	if (null!=response && 
				response.has("requirements") &&
				response.getJSONObject("requirements").has("attributes")) 
	    	{
	    		logger.debug("{}: createPPCCallbacks: Progressive profile completion initiated: {}", PPC_LOG_ID, response);
	        	
        		JSONObject uiConfig = response.getJSONObject("requirements").getJSONObject("uiConfig");
	        	String title = uiConfig.getString("displayName");
	        	String message = uiConfig.getString("purpose");
	        	String confirm = uiConfig.getString("buttonText");

	    		callbacks.add(new TextOutputCallback(TextOutputCallback.INFORMATION, title));
				callbacks.add(new TextOutputCallback(TextOutputCallback.INFORMATION, message));

				Map<String, String> map = new HashMap<String, String>();
	    		JSONArray attributes = response.getJSONObject("requirements").getJSONArray("attributes");
	    		for (int i = 0; i < attributes.length(); i++) {
					JSONObject attribute = attributes.getJSONObject(i);
					String prompt = attribute.getJSONObject("schema").getString("title");
					String defaultName = attribute.getString("value");
					logger.debug("createPPCCallbacks: Adding NameCallback with prompt=" + prompt + " and defaultName=" + defaultName);
					map.put(prompt, attribute.getString("name"));
		    		if (null==defaultName || defaultName.length()==0)
		    			callbacks.add(new NameCallback(prompt));
		    		else
		    			callbacks.add(new NameCallback(prompt, defaultName));
				}
	    		context.sharedState.put(PPC_MAP_KEY, map);
				callbacks.add(new ConfirmationCallback(ConfirmationCallback.INFORMATION, new String[]{confirm, "Cancel"}, 0));

	    		String clientSideScriptExecutorFunction = createClientSideScriptExecutorFunction(createScript(attributes));
	            ScriptTextOutputCallback scriptAndSelfSubmitCallback = new ScriptTextOutputCallback(clientSideScriptExecutorFunction);
	            // insert at beginning of list
	    		callbacks.add(0, scriptAndSelfSubmitCallback);
	        }
		} catch (JSONException e) {
			logger.error(PPC_LOG_ID + ": createPPCCallbacks: ", e);
		}
    	return callbacks;
    }
    
    private String createScript(JSONArray attributes) {
    	StringBuffer script = new StringBuffer()
	    	.append("var callbackScript = document.createElement(\"script\");\n")
	    	.append("callbackScript.type = \"text/javascript\";\n")
	    	.append("callbackScript.text = \"function completed() { document.querySelector(\\\"input[type=submit]\\\").click(); }\";\n")
			.append("document.body.appendChild(callbackScript);\n")
			.append("\n")
			.append("submitted = true;\n")
	    	.append("\n")
	    	.append("var decodeHTML = function (html) {\n")
	    	.append("	var txt = document.createElement('textarea');\n")
	    	.append("	txt.innerHTML = html;\n")
	    	.append("	return txt.value;\n")
	    	.append("};")
	    	.append("\n")
	    	.append("function callback() {\n")
	    	.append("\n")
	    	.append("    var title = document.getElementById('callback_1');\n")
	    	.append("    title.className = \"0 h1\";\n")
	    	.append("    title.align = \"center\";\n")
	    	.append("\n")
	    	.append("    var message = document.getElementById('callback_2');\n")
	    	.append("    message.className = \"0 h3\";\n")
	    	.append("    message.align = \"center\";\n");
    	
    	// generate code for callback fields
    	// callback_0: script
    	// callback_1: title
    	// callback_2: message
    	// callback_3: first PPC field
		for (int i = 0; i < attributes.length(); i++) {
			try {
				JSONObject attribute = attributes.getJSONObject(i);
				// only set non-null values
				if ( "null" != attribute.getString("value"))
					script
				    	.append("\n")
				    	.append("    var ppc_field_").append(i+3).append(" = document.getElementsByName('callback_").append(i+3).append("')[0];\n")
				    	.append("    ppc_field_").append(i+3).append(".value = \"").append(attribute.get("value")).append("\";\n");
			} catch (JSONException e) {
				logger.error(PPC_LOG_ID + ": createScript: ", e);
			}
		}
    	
    	script
	    	.append("}\n")
			.append("\n")
			.append("if (document.readyState !== 'loading') {\n")
			.append("  callback();\n")
			.append("} else {\n")
			.append("  document.addEventListener(\"DOMContentLoaded\", callback);\n")
			.append("}");
    	return script.toString();
    }
    
    private JSONObject readPPCRequirements(String username) {
    	String idmBaseUrl = config.idmBaseUrl();
    	String idmAdminUser = config.idmAdminUser();
    	String idmAdminPassword = new String(config.idmAdminPassword());
    	String idmTermsAndConditionsUrl = String.format("%s/selfservice/profile?_prettyPrint=true", idmBaseUrl);
        try {
            URL url = new URL(idmTermsAndConditionsUrl);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setRequestProperty("Accept", "*/*");
            conn.setRequestProperty("content-type", "application/json");
            conn.setRequestProperty("X-OpenIDM-Username", idmAdminUser);
            conn.setRequestProperty("X-OpenIDM-Password", idmAdminPassword);
            conn.setRequestProperty("X-OpenIDM-RunAs", username);
            conn.setRequestProperty("User-Agent", "ForgeRock ProgressiveProfileCompletion Authentication Node");

            // handle response
            String response = "";
            BufferedReader br = new BufferedReader(new InputStreamReader((conn.getInputStream())));
            String output;
            while ((output = br.readLine()) != null) {
                response = response + output;
            }
            br.close();
            // end handle response
            
            int responseCode = conn.getResponseCode();
            if ( responseCode == 200 ) {
            	logger.debug("{}: readPPCRequirements: HTTP Success: response code - {}, response: {}", PPC_LOG_ID, responseCode, response);
                
                conn.disconnect();
                return new JSONObject(response);
            }
            else {
            	String responseMessage = conn.getResponseMessage();
            	logger.debug("{}: readPPCRequirements: HTTP failed, response code: {} - {}, response: {}", PPC_LOG_ID, responseCode, responseMessage, response);
                
                conn.disconnect();
                return null;
            }
        } catch (Throwable t) {
        	logger.debug(PPC_LOG_ID + ": readPPCRequirements: ", t);
        }
        return null;
    }
    
    /* selfservice/profile submitRequirements COMPLETED
		{
		    "type": "conditionaluser",
		    "tag": "end",
		    "status": {
		        "success": true
		    },
		    "additions": {}
		}
		
		NOT COMPLETED must include token in next call
		
		{
		    "type": "conditionaluser",
		    "tag": "initial",
		    "requirements": {
		        "$schema": "http://json-schema.org/draft-04/schema#",
		        "description": "Attribute Details",
		        "type": "object",
		        "properties": {},
		        "attributes": [
		            {
		                "name": "description",
		                "isRequired": false,
		                "schema": {
		                    "title": "Description",
		                    "description": "Description",
		                    "viewable": true,
		                    "type": "string",
		                    "searchable": true,
		                    "userEditable": true,
		                    "usageDescription": null,
		                    "isPersonal": false
		                },
		                "value": null
		            }
		        ],
		        "uiConfig": {
		            "displayName": "Tell us about yourself",
		            "purpose": "Help us get to know you better",
		            "buttonText": "Save"
		        }
		    },
		    "token": "eyJ0eXAiOiJKV1QiLCJjdHkiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.ZXlKMGVYQWlPaUpLVjFRaUxDSmxibU1pT2lKQk1USTRRMEpETFVoVE1qVTJJaXdpWVd4bklqb2lVbE5CTVY4MUluMC5ZcXhBQ3puV2NfejVLS3FfazNBN1pVVDJrM1NrVFp3WEpaaGpoNFNLbEFoeTU4YXVyQktRajE5VVUxRm9peW0zS3NtSnM1YUtBajZGX29Jc1dtTWM3V1N3T2xFR01VSnJ4cjNLTm9FN1h1TUNSZ0xBRVdKUTB6Rk8tcUNoNEFmMmZFSk1qLVdENG5JQzdWX01NaUdGY083cUdpMGNYZFljaEZwa1JOajhHTG1LWC1zUGIybnV5ajcwUC1ONFlLbUlyMXNtR2RORVpaak5STEtjYVJ3YkRvVlR5VmhqTTdFa3RwVGJTZGpQcWFQUHBxdU5JclBqdWNQNlVQaWJrdS1oaVJjX3Rsai15cWFqemROYTNCUm1xSkExbEllNkxfbEtEQlhkaVJ0d0ZDQnpuRUlfOVJndFozU1pJWXY3Y0puc1lVdG1odm94ZnFGUUpVOUZ1YmVXR2cuZlM2OWlNUjllT090dlFPMkhWNWxyZy5EU1RNbWVJSlR1VE1KUzlQczdzWXV6SnBENzdNMVJBcjNHMDF1TnhBSDM2YWdpWk96eUJ1NWU5WURWenJQcGlha1UtMXEzS21YX2RBUHQ5X2FJWnBIME5XRjhrbUx1V0M4REY0WGhuTDEyMUwwc1hsRjRlWUpDd21ydFRUSEpia3p3UU9rQWZqbEdLOUF2ZHV4MElrdFVSQ1prZmxnc2lPdDRQcVNDeHVqWmcuVXpHVXFzOEo0ZHpJVlJDeTJvVVo0dw.8el0cvHS_Mm5PcsghbK14uyprFL6S-nS-DeFPgCznVQ"
		}
     */
    
    private String createPPCResponse(TreeContext context) {
    	@SuppressWarnings("unchecked")
		Map<String, String> map = (Map<String, String>) context.sharedState.get(PPC_MAP_KEY).getObject();
    	StringBuffer requirements = new StringBuffer()
    	.append("{\n");
//    	if (false) {
//            requirements
//        	.append("	\"token\":\"ssssss\"\n");
//    	}
    	requirements
    	.append("	\"input\":{\n")
    	.append("		\"attributes\":{\n");
    	Iterator<? extends Callback> iterator = context.getCallbacks(NameCallback.class).iterator();
        while (iterator.hasNext()) {
            NameCallback callback = (NameCallback) iterator.next();
            requirements.append("			\"").append(map.get(callback.getPrompt())).append("\":\"").append(callback.getName()).append("\"").append(iterator.hasNext() ? "," : "").append("\n");
        }
        requirements
    	.append("		}\n")
    	.append("	}\n")
    	.append("}");

        logger.debug("{}: createPPCResponse: {}",PPC_LOG_ID, requirements.toString());
        
    	return requirements.toString();
    }
    
    private boolean submitPPCResponse(String username, String jsonPayload) {
    	String idmBaseUrl = config.idmBaseUrl();
    	String idmAdminUser = config.idmAdminUser();
    	String idmAdminPassword = new String(config.idmAdminPassword());
    	String idmTermsAndConditionsUrl = String.format("%s/selfservice/profile?_action=submitRequirements&_prettyPrint=true", idmBaseUrl);
        try {
            URL url = new URL(idmTermsAndConditionsUrl);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Accept", "*/*");
            conn.setRequestProperty("content-type", "application/json");
            conn.setRequestProperty("X-OpenIDM-Username", idmAdminUser);
            conn.setRequestProperty("X-OpenIDM-Password", idmAdminPassword);
            conn.setRequestProperty("X-OpenIDM-RunAs", username);
            conn.setRequestProperty("User-Agent", "ForgeRock ProgressiveProfileCompletion Authentication Node");
            
            // handle payload
            conn.setDoOutput(true);
            OutputStream os = conn.getOutputStream();
            byte[] payload = jsonPayload.getBytes("utf-8");
            os.write(payload, 0, payload.length);
    		os.flush();
    		os.close();
    		// end handle payload

            // handle response
            String response = "";
            BufferedReader br = new BufferedReader(new InputStreamReader((conn.getInputStream())));
            String output;
            while ((output = br.readLine()) != null) {
                response = response + output;
            }
            br.close();
            // end handle response
            
    		int responseCode = conn.getResponseCode();
            if ( responseCode == 200 ) {
            	logger.debug("{}: submitPPCResponse: HTTP Success: response code - {}, response: {}", PPC_LOG_ID, responseCode, response);
                
                conn.disconnect();
                return true;
            }
            else {
            	String responseMessage = conn.getResponseMessage();
            	logger.error("{}: submitPPCResponse: HTTP failed, response code: {} - {}, response: {}", PPC_LOG_ID, responseCode, responseMessage, response);
                
                conn.disconnect();
                return false;
            }
        } catch (Throwable t) {
        	logger.error(PPC_LOG_ID + ": submitPPCResponse: ", t);
        }
        return false;
    }

}
